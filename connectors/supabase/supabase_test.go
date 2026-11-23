package supabase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const (
	testToken = "sbp_test_not_real"
	fakeKey   = "REDACTED-FIXTURE-VALUE"
)

func raw(s string) httpxtest.Route { return httpxtest.Static(json.RawMessage(s)) }

func routes(t *testing.T) map[string]httpxtest.Route {
	return map[string]httpxtest.Route{
		"/v1/organizations":          raw(`[{"slug":"org-free","name":"Hobby"},{"slug":"org-pro","name":"Company"}]`),
		"/v1/organizations/org-free": raw(`{"id":"org-free","name":"Hobby","plan":"free"}`),
		"/v1/organizations/org-pro":  raw(`{"id":"org-pro","name":"Company","plan":"pro"}`),
		"/v1/projects": raw(`[
			{"ref":"abcdefghijklmnopqrst","name":"app","organization_slug":"org-pro","region":"eu-west-1","status":"ACTIVE_HEALTHY"},
			{"ref":"zzzzzzzzzzzzzzzzzzzz","name":"broken","organization_slug":"org-free","status":"ACTIVE_HEALTHY"},
			{"ref":"yyyyyyyyyyyyyyyyyyyy","name":"gone","organization_slug":"org-free","status":"REMOVED"}]`),
		"/v1/projects/abcdefghijklmnopqrst/api-keys": func(q url.Values) (int, any) {
			if q.Get("reveal") != "false" {
				t.Errorf("api keys must be listed with reveal=false, got %v", q)
			}
			return http.StatusOK, json.RawMessage(`[
				{"name":"anon","type":"legacy","api_key":"` + fakeKey + `"},
				{"name":"service_role","type":"legacy","api_key":"` + fakeKey + `"},
				{"id":"k3","name":"default","type":"secret","api_key":"` + fakeKey + `","inserted_at":"2026-01-01T00:00:00Z"}]`)
		},
	}
}

func run(t *testing.T, srv *httpxtest.Server, tok string) *httpxtest.Recorder {
	t.Helper()
	rec := &httpxtest.Recorder{}
	c := &Connector{BaseURL: srv.URL}
	if err := c.Inventory(context.Background(), connector.Request{Secrets: map[string]string{secretName: tok}}, rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func newServer(t *testing.T) *httpxtest.Server {
	return httpxtest.NewServer(t, http.Header{"Authorization": {"Bearer " + testToken}}, routes(t))
}

func TestInventory(t *testing.T) {
	srv := newServer(t)
	rec := run(t, srv, testToken)
	got := map[string]finding.Severity{}
	for _, f := range rec.Findings {
		got[f.Account+" "+f.Resource.Type+" "+f.Resource.ID] = f.Severity
	}
	want := map[string]finding.Severity{
		"org-free supabase_organization org-free":                           finding.SevInfo,
		"org-pro supabase_organization org-pro":                             finding.SevInfo,
		"org-pro supabase_spend_cap org-pro":                                finding.SevLow,
		"org-pro supabase_api_key abcdefghijklmnopqrst/legacy:anon":         finding.SevInfo,
		"org-pro supabase_api_key abcdefghijklmnopqrst/legacy:service_role": finding.SevMedium,
		"org-pro supabase_api_key abcdefghijklmnopqrst/k3":                  finding.SevInfo,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	if k := rec.ByResource(t, "supabase_api_key", "abcdefghijklmnopqrst/k3"); k.CreatedAt == nil {
		t.Fatal("inserted_at should become created_at")
	}
	rec.AssertNoSecret(t, fakeKey)
	rec.AssertNoSecret(t, testToken)
	// org-free: the "broken" project's keys 404 and the removed project is skipped; org-pro: ok.
	if len(rec.Statuses) != 2 || rec.Statuses[0].Account != "org-free" || rec.Statuses[0].State != finding.StateError || rec.Statuses[1].State != finding.StateOK {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
	for _, m := range srv.Misses {
		if strings.Contains(m, "yyyyyyyyyyyyyyyyyyyy") {
			t.Fatal("removed project should not be queried")
		}
	}
}

func TestMissingTokenExplainsSetup(t *testing.T) {
	rec := &httpxtest.Recorder{}
	if err := (&Connector{}).Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	if st := rec.Statuses[0]; st.State != finding.StateMissingCredentials || !strings.Contains(st.Detail, "keychain:securizame-supabase") {
		t.Fatalf("status: %+v", st)
	}
}

func TestRejectedTokenIsReauth(t *testing.T) {
	rec := run(t, newServer(t), "wrong")
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateReauth {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
}

func TestOrgFindingsOnlyAskForSpendCapWhenBilledByUsage(t *testing.T) {
	for plan, want := range map[string]int{"free": 1, "pro": 2, "team": 2, "": 1} {
		if got := len(orgFindings(organization{Slug: "o", Plan: plan})); got != want {
			t.Errorf("plan %q: %d findings, want %d", plan, got, want)
		}
	}
}
