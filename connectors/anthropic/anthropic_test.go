package anthropic

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// Synthetic, obviously fake credential: it must never show up in output.
const testKey = "sk-ant-admin01-TEST-not-a-real-key-000000"

var now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func daysAgo(d int) string { return now.Add(-time.Duration(d) * 24 * time.Hour).Format(time.RFC3339) }

func ptr[T any](v T) *T { return &v }

func apiKeyJSON(id, status string, createdDays int, creator string, principal any) map[string]any {
	k := map[string]any{
		"type": "api_key", "id": id, "name": id, "status": status, "created_at": daysAgo(createdDays),
		"expires_at": nil, "partial_key_hint": "sk-ant-api03-R2D...igAA", "principal": principal,
		"scope": map[string]any{"type": "workspace", "workspace_id": "wrkspc_prod"},
	}
	if creator != "" {
		k["created_by"] = map[string]any{"type": "user", "id": creator}
	}
	return k
}

func usageRow(key any, output int) map[string]any {
	return map[string]any{
		"api_key_id": key, "uncached_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": output,
		"cache_creation":  map[string]any{"ephemeral_1h_input_tokens": 0, "ephemeral_5m_input_tokens": 0},
		"server_tool_use": map[string]any{"web_search_requests": 0},
	}
}

func TestInventoryFindsOrphanAndUnusedKeysAndCost(t *testing.T) {
	personal := map[string]any{"type": "user_actor", "user_id": "user_gone"}
	srv := httpxtest.NewServer(t, http.Header{"X-Api-Key": {testKey}, "Anthropic-Version": {apiVersion}}, map[string]httpxtest.Route{
		"/v1/organizations/me": httpxtest.Static(map[string]any{"id": "org_1", "type": "organization", "name": "Acme Test"}),
		"/v1/organizations/workspaces": func(q url.Values) (int, any) {
			if q.Get("include_archived") != "true" {
				t.Errorf("workspaces must include archived ones (their keys would show a bare id): %v", q)
			}
			if q.Get("after_id") == "" {
				return 200, map[string]any{"data": []any{map[string]any{"id": "wrkspc_prod", "name": "prod"}}, "has_more": true, "last_id": "wrkspc_prod"}
			}
			return 200, map[string]any{"data": []any{map[string]any{"id": "wrkspc_lab", "name": "lab"}}, "has_more": false, "last_id": "wrkspc_lab"}
		},
		"/v1/organizations/users": httpxtest.Static(map[string]any{"data": []any{map[string]any{"id": "user_ana", "type": "user"}}, "has_more": false}),
		"/v1/organizations/api_keys": httpxtest.Static(map[string]any{"has_more": false, "data": []any{
			apiKeyJSON("k_busy", "active", 400, "user_ana", nil),
			apiKeyJSON("k_orphan", "active", 400, "user_gone", nil),
			apiKeyJSON("k_idle", "active", 400, "user_ana", nil),
			apiKeyJSON("k_new", "active", 10, "user_ana", nil),
			apiKeyJSON("k_zero", "active", 400, "user_ana", nil),
			apiKeyJSON("k_personal", "active", 400, "user_gone", personal),
			apiKeyJSON("k_inactive", "inactive", 400, "user_gone", nil),
			apiKeyJSON("k_archived", "archived", 400, "user_ana", nil),
		}}),
		"/v1/organizations/usage_report/messages": func(q url.Values) (int, any) {
			if q.Get("group_by[]") != "api_key_id" || q.Get("bucket_width") != "1d" {
				t.Errorf("usage query: %v", q)
			}
			if q.Get("page") == "" {
				return 200, map[string]any{"data": []any{
					map[string]any{"starting_at": daysAgo(40), "results": []any{usageRow("k_busy", 5), usageRow(nil, 99), usageRow("k_zero", 0)}},
				}, "has_more": true, "next_page": "page_2"}
			}
			return 200, map[string]any{"data": []any{
				map[string]any{"starting_at": daysAgo(1), "results": []any{usageRow("k_busy", 1), usageRow("k_orphan", 7), usageRow("k_personal", 3)}},
			}, "has_more": false, "next_page": nil}
		},
		"/v1/organizations/cost_report": func(q url.Values) (int, any) {
			if q.Get("group_by[]") != "workspace_id" {
				t.Errorf("cost query: %v", q)
			}
			return 200, map[string]any{"data": []any{
				map[string]any{"starting_at": daysAgo(3), "results": []any{
					map[string]any{"amount": "1200", "currency": "USD", "workspace_id": "wrkspc_prod"},
					map[string]any{"amount": "100", "currency": "USD", "workspace_id": nil},
				}},
				map[string]any{"starting_at": daysAgo(2), "results": []any{
					map[string]any{"amount": "50", "currency": "USD", "workspace_id": "wrkspc_prod"},
				}},
			}, "has_more": false, "next_page": nil}
		},
	})

	rec := &httpxtest.Recorder{}
	c := &Connector{BaseURL: srv.URL, Now: func() time.Time { return now }}
	if err := c.Inventory(context.Background(), connector.Request{Secrets: map[string]string{secretName: testKey}}, rec); err != nil {
		t.Fatal(err)
	}
	if len(srv.Misses) > 0 {
		t.Fatalf("unexpected paths requested: %v", srv.Misses)
	}
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateOK || rec.Statuses[0].Account != "Acme Test" {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
	rec.AssertNoSecret(t, testKey)

	cases := []struct {
		typ, id string
		sev     finding.Severity
	}{
		{"api_key", "k_busy", finding.SevInfo},
		{"api_key", "k_orphan", finding.SevHigh},   // workspace key whose creator left
		{"api_key", "k_idle", finding.SevMedium},   // no usage in the window, created long ago
		{"api_key", "k_new", finding.SevMedium},    // never used since creation
		{"api_key", "k_zero", finding.SevMedium},   // a zero-token row is not use
		{"api_key", "k_personal", finding.SevInfo}, // acts as its user, so it is not orphaned
		{"api_key", "k_inactive", finding.SevInfo}, // cannot authenticate while inactive
		{"organization", "organization", finding.SevLow},
		{"workspace", "wrkspc_prod", finding.SevLow},
		{"workspace", "default", finding.SevLow},
		{"workspace", "wrkspc_lab", finding.SevInfo}, // no cost
	}
	if len(rec.Findings) != len(cases) {
		t.Fatalf("got %d findings, want %d (archived keys are skipped)", len(rec.Findings), len(cases))
	}
	for _, tc := range cases {
		if f := rec.ByResource(t, tc.typ, tc.id); f.Severity != tc.sev {
			t.Errorf("%s %s: severity %s, want %s (%s)", tc.typ, tc.id, f.Severity, tc.sev, f.Title)
		}
	}

	busy := rec.ByResource(t, "api_key", "k_busy")
	if busy.Evidence["last_usage_day"] != now.Add(-24*time.Hour).Format("2006-01-02") {
		t.Errorf("latest usage day should win across pages: %v", busy.Evidence)
	}
	if busy.LastUsedAt != nil {
		t.Error("LastUsedAt must stay nil: the API has no last-used timestamp")
	}
	if busy.CreatedAt == nil || busy.Evidence["workspace"] != "prod" || busy.Evidence["redacted"] != "sk-ant-api03-R2D…igAA(?)" {
		t.Errorf("finding: created=%v evidence=%v", busy.CreatedAt, busy.Evidence)
	}
	if got := rec.ByResource(t, "workspace", "wrkspc_prod").Evidence["cost_30d_usd"]; got != 12.5 {
		t.Errorf("prod cost = %v, want 12.5", got)
	}
	if got := rec.ByResource(t, "organization", "organization").Evidence["cost_30d_usd"]; got != 13.5 {
		t.Errorf("org cost = %v, want 13.5", got)
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

func TestUnreadableUsersOrUsageNeverInventsRisk(t *testing.T) {
	k := apiKey{ID: "k", Status: "active", CreatedBy: &struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}{"user", "user_gone"}}
	created := ptr(now.Add(-400 * 24 * time.Hour))
	if a := keyAssessment(k, created, nil, nil, now); a.Severity != finding.SevInfo {
		t.Fatalf("unknown members and usage gave %s %v", a.Severity, a.Reasons)
	}
	if a := keyAssessment(k, created, map[string]bool{}, nil, now); a.Severity != finding.SevHigh {
		t.Fatalf("creator missing from a known member list gave %s", a.Severity)
	}
	old := map[string]time.Time{"k": now.Add(-91 * 24 * time.Hour)}
	if a := keyAssessment(k, created, nil, old, now); a.Severity != finding.SevMedium {
		t.Fatalf("last use 91 days ago gave %s", a.Severity)
	}
}
