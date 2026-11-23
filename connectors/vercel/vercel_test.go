package vercel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

var now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

const testToken = "test-token-not-real"

func msAgo(days int) int64 { return now.AddDate(0, 0, -days).UnixMilli() }

func raw(s string) httpxtest.Route { return httpxtest.Static(json.RawMessage(s)) }

func newServer(t *testing.T, routes map[string]httpxtest.Route) *httpxtest.Server {
	return httpxtest.NewServer(t, http.Header{"Authorization": {"Bearer " + testToken}}, routes)
}

func run(t *testing.T, srv *httpxtest.Server, tok string) *httpxtest.Recorder {
	t.Helper()
	rec := &httpxtest.Recorder{}
	c := &Connector{BaseURL: srv.URL, Now: func() time.Time { return now }}
	if err := c.Inventory(context.Background(), connector.Request{Secrets: map[string]string{secretName: tok}}, rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestInventory(t *testing.T) {
	srv := newServer(t, map[string]httpxtest.Route{
		"/v2/user": raw(`{"user":{"username":"example-user","email":"user@example.com"}}`),
		"/v6/user/tokens": func(q url.Values) (int, any) {
			if q.Get("status") != "active" {
				t.Errorf("tokens query %v", q)
			}
			return http.StatusOK, json.RawMessage(fmt.Sprintf(`{"pagination":{"count":3,"next":null,"prev":null},"tokens":[
				{"id":"t1","name":"ci","kind":"access-token","type":"oauth2-token","activeAt":%d,"createdAt":%d,"expiresAt":%d},
				{"id":"t2","name":"old","kind":"access-token","type":"oauth2-token","activeAt":%d,"createdAt":%d},
				{"id":"t3","name":"oops","kind":"access-token","type":"oauth2-token","activeAt":%d,"createdAt":%d,"leakedAt":%d,"leakedUrl":"https://example.com/paste"}]}`,
				msAgo(1), msAgo(10), now.AddDate(0, 1, 0).UnixMilli(),
				msAgo(200), msAgo(400),
				msAgo(1), msAgo(5), msAgo(2)))
		},
		"/v2/teams": raw(`{"pagination":{"count":2},"teams":[
			{"id":"team_a","slug":"a","name":"A","billing":{"plan":"pro"},"membership":{"role":"OWNER"}},
			{"id":"team_b","slug":"b","name":"B","billing":{"plan":"hobby"}}]}`),
	})
	rec := run(t, srv, testToken)
	want := map[string]finding.Severity{
		"vercel_token/t1":                finding.SevInfo,
		"vercel_token/t2":                finding.SevHigh,
		"vercel_token/t3":                finding.SevCritical,
		"vercel_team/team_a":             finding.SevInfo,
		"vercel_team/team_b":             finding.SevInfo,
		"vercel_spend_management/team_a": finding.SevLow,
	}
	got := map[string]finding.Severity{}
	for _, f := range rec.Findings {
		got[f.Resource.Type+"/"+f.Resource.ID] = f.Severity
		if f.Account != "example-user" {
			t.Errorf("account: %q", f.Account)
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	if leak := rec.ByResource(t, "vercel_token", "t3"); leak.Evidence["leaked_url"] != "https://example.com/paste" {
		t.Fatalf("leak evidence: %+v", leak.Evidence)
	}
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateOK || len(srv.Misses) != 0 {
		t.Fatalf("statuses %+v misses %v", rec.Statuses, srv.Misses)
	}
	rec.AssertNoSecret(t, testToken)
}

func TestFailingEndpointIsReportedNotFatal(t *testing.T) {
	srv := newServer(t, map[string]httpxtest.Route{
		"/v2/user":        raw(`{"user":{"username":"example-user"}}`),
		"/v6/user/tokens": httpxtest.Fail(http.StatusForbidden, "missing scope"),
		"/v2/teams":       raw(`{"teams":[]}`),
	})
	rec := run(t, srv, testToken)
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateError || !strings.Contains(rec.Statuses[0].Detail, "tokens:") {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
}

func TestMissingTokenExplainsSetup(t *testing.T) {
	rec := &httpxtest.Recorder{}
	if err := (&Connector{}).Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	if st := rec.Statuses[0]; st.State != finding.StateMissingCredentials || !strings.Contains(st.Detail, "keychain:securizame-vercel") {
		t.Fatalf("status: %+v", st)
	}
}

func TestRejectedTokenIsReauth(t *testing.T) {
	rec := run(t, newServer(t, nil), "wrong")
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateReauth {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
}

func TestTokenFinding(t *testing.T) {
	p := func(v int64) *int64 { return &v }
	cases := []struct {
		name string
		tok  token
		want finding.Severity
	}{
		{"healthy", token{ActiveAt: p(msAgo(1)), ExpiresAt: p(now.AddDate(0, 0, 30).UnixMilli())}, finding.SevInfo},
		{"no expiry", token{ActiveAt: p(msAgo(1))}, finding.SevMedium},
		{"idle", token{ActiveAt: p(msAgo(91)), ExpiresAt: p(now.AddDate(1, 0, 0).UnixMilli())}, finding.SevHigh},
		{"leaked beats idle", token{ActiveAt: p(msAgo(300)), LeakedAt: p(msAgo(3))}, finding.SevCritical},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if f := tokenFinding(tc.tok, now); f.Severity != tc.want {
				t.Fatalf("got %s %q", f.Severity, f.Title)
			}
		})
	}
}
