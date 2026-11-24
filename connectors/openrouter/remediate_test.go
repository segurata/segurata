package openrouter

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const testWriteKey = "sk-or-v1-WRITE-not-a-real-management-key-1111"

func quietIO() connector.IO {
	return connector.IO{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
}

func keysServer(t *testing.T) *httpxtest.Server {
	self := orKey("self", 5.0, nil, 0, nil)
	self["label"] = "sk-or-v1-TES...0000" // the inventory's own management key
	srv := httpxtest.NewServer(t, http.Header{"Authorization": {"Bearer " + testKey}}, map[string]httpxtest.Route{
		"/keys": func(q url.Values) (int, any) {
			if q.Get("workspace_id") != "ws-main" {
				t.Errorf("keys listed outside the finding's workspace: %v", q)
			}
			disabled := orKey("off", nil, nil, 0, nil)
			disabled["disabled"] = true
			return 200, map[string]any{"data": []any{
				orKey("never", 5.0, nil, 0, nil),
				orKey("legacy", 5.0, nil, 12, nil),
				orKey("busy", 5.0, daysAgo(1), 3, nil),
				disabled, self,
			}}
		},
	})
	srv.DeleteAuth = http.Header{"Authorization": {"Bearer " + testWriteKey}}
	return srv
}

func creds(write bool) connector.Credentials {
	cs := connector.Credentials{Request: connector.Request{Secrets: map[string]string{secretName: testKey}},
		Resolve: func(context.Context, string) (string, error) { return testWriteKey, nil }}
	if write {
		cs.WriteRefs = map[string]string{writeSecret: "keychain:segurata-openrouter-admin-write"}
	}
	return cs
}

func orFinding(hash string) finding.Finding {
	return finding.Finding{ID: hash, Connector: name, Account: "main", Resource: finding.Resource{Type: "api_key", ID: hash},
		Evidence: map[string]any{"workspace_id": "ws-main"}, Remediation: finding.Remediation{Action: ActionDeleteUnusedKey}}
}

func TestInventoryOffersDeletionForUnusedEnabledKeys(t *testing.T) {
	cases := map[string]string{
		"never": ActionDeleteUnusedKey, "legacy": ActionDeleteUnusedKey, "stale": ActionDeleteUnusedKey,
		"busy": "", "expired": "", "disabled": "",
	}
	keys := map[string]apiKey{
		"never":    {Hash: "never"},
		"legacy":   {Hash: "legacy", Usage: 12},
		"stale":    {Hash: "stale", LastUsedAt: ptr(daysAgo(120))},
		"busy":     {Hash: "busy", LastUsedAt: ptr(daysAgo(1))},
		"expired":  {Hash: "expired", ExpiresAt: ptr(daysAgo(5))},
		"disabled": {Hash: "disabled", Disabled: true},
	}
	for n, want := range cases {
		if got := keyFinding("main", keys[n], now).Remediation.Action; got != want {
			t.Errorf("%s: action %q, want %q", n, got, want)
		}
	}
}

func ptr(s string) *string { return &s }

func TestDeletePlanIsExactAndBlockedWithoutAWriteKey(t *testing.T) {
	srv := keysServer(t)
	r := (&Connector{BaseURL: srv.URL, Now: func() time.Time { return now }}).WithCredentials(creds(false))
	p, err := r.Plan(context.Background(), orFinding("legacy"))
	if err != nil {
		t.Fatal(err)
	}
	want := []connector.Call{{Method: "DELETE", URL: srv.URL + "/keys/legacy", Secret: writeSecret}}
	if !reflect.DeepEqual(p.Calls, want) || len(p.Undo) != 0 {
		t.Fatalf("plan %+v", p)
	}
	if !strings.Contains(p.Summary, `"legacy"`) || !strings.Contains(p.Summary, "no recorded use since the end of 2025") {
		t.Errorf("summary %q", p.Summary)
	}
	if !strings.Contains(p.Blocked, "remediation_secrets") || !strings.Contains(p.Blocked, "read/write") {
		t.Errorf("blocked %q", p.Blocked)
	}
	if err := r.Apply(context.Background(), orFinding("legacy"), p, quietIO()); err == nil || len(srv.Deleted) != 0 {
		t.Fatalf("apply without a write key: %v %v", err, srv.Deleted)
	}
}

func TestDeleteAppliesWithTheWriteKeyAndRefusesTheRest(t *testing.T) {
	srv := keysServer(t)
	r := (&Connector{BaseURL: srv.URL, Now: func() time.Time { return now }}).WithCredentials(creds(true))
	f := orFinding("never")
	p, err := r.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Apply(context.Background(), f, p, quietIO()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(srv.Deleted, []string{"/keys/never"}) {
		t.Fatalf("deleted %v", srv.Deleted)
	}
	for _, hash := range []string{"busy", "off", "self", "gone"} {
		if _, err := r.Plan(context.Background(), orFinding(hash)); err == nil {
			t.Errorf("%s: planned", hash)
		}
	}
	srv.DeleteAuth = http.Header{"Authorization": {"Bearer another"}}
	if err := r.Apply(context.Background(), f, p, quietIO()); err == nil || !strings.Contains(err.Error(), writeSecret+" was refused") {
		t.Fatalf("read-only write key: %v", err)
	}
}
