package openrouter

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// Synthetic, obviously fake credential: it must never show up in output.
const testKey = "sk-or-v1-TEST-not-a-real-management-key-0000"

var now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func daysAgo(d int) string { return now.Add(-time.Duration(d) * 24 * time.Hour).Format(time.RFC3339) }

func orKey(hash string, limit any, lastUsed any, usage float64, expires any) map[string]any {
	return map[string]any{
		"hash": hash, "name": hash, "label": "sk-or-v1-abc...123", "disabled": false,
		"limit": limit, "limit_remaining": limit, "limit_reset": "monthly", "include_byok_in_limit": false,
		"usage": usage, "usage_daily": 0, "usage_weekly": 0, "usage_monthly": usage / 10,
		"byok_usage": 0, "byok_usage_daily": 0, "byok_usage_weekly": 0, "byok_usage_monthly": 0,
		"created_at": daysAgo(300), "updated_at": nil, "expires_at": expires, "last_used_at": lastUsed,
		"external_user": nil, "creator_user_id": "user_x", "workspace_id": "ws-main",
	}
}

func TestInventoryFindsUncappedAndIdleKeysAcrossWorkspacesAndPages(t *testing.T) {
	var bulk []any
	for i := range pageSize {
		bulk = append(bulk, orKey(fmt.Sprintf("bulk%03d", i), 5.0, daysAgo(1), 1, nil))
	}
	srv := httpxtest.NewServer(t, http.Header{"Authorization": {"Bearer " + testKey}}, map[string]httpxtest.Route{
		"/workspaces": httpxtest.Static(map[string]any{"total_count": 2, "data": []any{
			map[string]any{"id": "ws-main", "name": "main", "slug": "main"},
			map[string]any{"id": "ws-side", "name": "side", "slug": "side"},
		}}),
		"/keys": func(q url.Values) (int, any) {
			switch {
			case q.Get("workspace_id") == "ws-side":
				return 200, map[string]any{"data": []any{orKey("side_ok", 10.0, daysAgo(2), 3, nil)}}
			case q.Get("workspace_id") != "ws-main":
				t.Errorf("keys requested without a workspace: %v", q)
				return 400, nil
			case q.Get("offset") == "0":
				return 200, map[string]any{"data": bulk}
			case q.Get("offset") == "100":
				return 200, map[string]any{"data": []any{
					orKey("open_busy", nil, daysAgo(1), 50, nil),
					orKey("open_idle", nil, daysAgo(200), 50, nil),
					orKey("capped_never", 5.0, nil, 0, nil),
					orKey("capped_legacy", 5.0, nil, 12, nil),
					orKey("capped_stale", 5.0, daysAgo(120), 3, nil),
					orKey("expired", nil, nil, 0, daysAgo(5)),
				}}
			}
			t.Errorf("unexpected offset %q", q.Get("offset"))
			return 400, nil
		},
		"/credits": httpxtest.Static(map[string]any{"data": map[string]any{"total_credits": 100.5, "total_usage": 25.75}}),
	})

	rec := &httpxtest.Recorder{}
	c := &Connector{BaseURL: srv.URL, Now: func() time.Time { return now }}
	if err := c.Inventory(context.Background(), connector.Request{Secrets: map[string]string{secretName: testKey}}, rec); err != nil {
		t.Fatal(err)
	}
	if len(srv.Misses) > 0 {
		t.Fatalf("unexpected paths requested: %v", srv.Misses)
	}
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateOK {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
	rec.AssertNoSecret(t, testKey)

	// 100 bulk + 6 special + 1 side keys, 2 workspace spend findings, 1 credits finding.
	if len(rec.Findings) != pageSize+6+1+2+1 {
		t.Fatalf("got %d findings", len(rec.Findings))
	}
	cases := []struct {
		id  string
		sev finding.Severity
	}{
		{"bulk042", finding.SevInfo},
		{"side_ok", finding.SevInfo},
		{"open_busy", finding.SevHigh},
		{"open_idle", finding.SevHigh},
		{"capped_never", finding.SevMedium},
		{"capped_legacy", finding.SevMedium},
		{"capped_stale", finding.SevMedium},
		{"expired", finding.SevInfo},
	}
	for _, tc := range cases {
		if f := rec.ByResource(t, "api_key", tc.id); f.Severity != tc.sev {
			t.Errorf("%s: severity %s, want %s (%s)", tc.id, f.Severity, tc.sev, f.Title)
		}
	}
	legacy := rec.ByResource(t, "api_key", "capped_legacy")
	if legacy.LastUsedAt != nil || legacy.Evidence["issues"].([]string)[0] != "no recorded use since the end of 2025" {
		t.Errorf("a key with usage but no last_used_at is idle, not never used: %v", legacy.Evidence["issues"])
	}
	stale := rec.ByResource(t, "api_key", "capped_stale")
	if stale.LastUsedAt == nil || stale.CreatedAt == nil || stale.Account != "main" || stale.Evidence["redacted"] != "sk-or-v1-abc...123" {
		t.Errorf("finding fields: %+v", stale)
	}

	main := rec.ByResource(t, "workspace", "ws-main")
	if main.Kind != finding.KindSpend || main.Evidence["keys_without_limit"] != 3 || main.Evidence["keys"] != pageSize+6 {
		t.Errorf("workspace evidence: %v", main.Evidence)
	}
	credits := rec.ByResource(t, "credits", account)
	if credits.Evidence["balance_usd"] != 74.75 {
		t.Errorf("credits evidence: %v", credits.Evidence)
	}
}

func TestWorkspaceScopedKeyFallsBackToItsOwnWorkspace(t *testing.T) {
	srv := httpxtest.NewServer(t, http.Header{"Authorization": {"Bearer " + testKey}}, map[string]httpxtest.Route{
		"/workspaces": httpxtest.Fail(http.StatusForbidden, "organization-scoped key required"),
		"/credits":    httpxtest.Fail(http.StatusForbidden, "organization-scoped key required"),
		"/keys": func(q url.Values) (int, any) {
			if q.Has("workspace_id") {
				t.Errorf("fallback should not name a workspace: %v", q)
			}
			return 200, map[string]any{"data": []any{orKey("only", nil, daysAgo(1), 1, nil)}}
		},
	})
	rec := &httpxtest.Recorder{}
	c := &Connector{BaseURL: srv.URL, Now: func() time.Time { return now }}
	if err := c.Inventory(context.Background(), connector.Request{Secrets: map[string]string{secretName: testKey}}, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateOK || len(rec.Logs) != 2 {
		t.Fatalf("statuses=%+v logs=%v", rec.Statuses, rec.Logs)
	}
	if f := rec.ByResource(t, "api_key", "only"); f.Severity != finding.SevHigh || f.Account != "default workspace" {
		t.Fatalf("finding: %+v", f)
	}
}

func TestMissingSecretReportsHowToConfigure(t *testing.T) {
	rec := &httpxtest.Recorder{}
	c := &Connector{BaseURL: "http://127.0.0.1:1"}
	if err := c.Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Findings) != 0 || len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateMissingCredentials || rec.Statuses[0].Detail != setupHint {
		t.Fatalf("findings=%v statuses=%+v", rec.Findings, rec.Statuses)
	}
}

func TestBadKeyStopsWithAnErrorStatus(t *testing.T) {
	srv := httpxtest.NewServer(t, http.Header{"Authorization": {"Bearer right"}}, nil)
	rec := &httpxtest.Recorder{}
	c := &Connector{BaseURL: srv.URL}
	if err := c.Inventory(context.Background(), connector.Request{Secrets: map[string]string{secretName: "wrong"}}, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateError || len(rec.Findings) != 0 {
		t.Fatalf("statuses=%+v findings=%d", rec.Statuses, len(rec.Findings))
	}
}
