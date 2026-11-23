package openai

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
const testKey = "sk-admin-TEST-not-a-real-key-0000000000"

var now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func ago(days int) int64 { return now.Add(-time.Duration(days) * 24 * time.Hour).Unix() }

func key(id, name string, lastUsed any, access string) map[string]any {
	return map[string]any{
		"object": "organization.project.api_key", "id": id, "name": name,
		"redacted_value": "sk-proj-****" + id, "created_at": ago(400), "last_used_at": lastUsed,
		"owner_project_access": access,
		"owner":                map[string]any{"type": "user", "user": map[string]any{"id": "user_" + id, "email": id + "@example.test"}},
	}
}

func listOf(data ...any) map[string]any {
	return map[string]any{"object": "list", "data": data, "has_more": false}
}

func TestInventoryFindsUncappedIdleAndOrphanKeysAndBudgets(t *testing.T) {
	srv := httpxtest.NewServer(t, http.Header{"Authorization": {"Bearer " + testKey}}, map[string]httpxtest.Route{
		"/organization/projects": httpxtest.Static(listOf(
			map[string]any{"id": "proj_prod", "name": "prod"},
			map[string]any{"id": "proj_lab", "name": "lab"},
		)),
		"/organization/spend_limit":                     httpxtest.Fail(http.StatusNotFound, "no spend limit"),
		"/organization/spend_alerts":                    httpxtest.Static(listOf()),
		"/organization/projects/proj_prod/spend_limit":  httpxtest.Fail(http.StatusNotFound, "no spend limit"),
		"/organization/projects/proj_prod/spend_alerts": httpxtest.Static(listOf()),
		"/organization/projects/proj_lab/spend_limit": httpxtest.Static(map[string]any{
			"object": "project.spend_limit", "threshold_amount": 5000, "currency": "USD", "interval": "month",
			"enforcement": map[string]any{"status": "inactive"},
		}),
		"/organization/projects/proj_lab/spend_alerts": httpxtest.Static(listOf(map[string]any{"id": "alert_1", "threshold_amount": 4000})),
		// Two pages, to prove the after=last_id cursor is followed.
		"/organization/projects/proj_prod/api_keys": func(q url.Values) (int, any) {
			if q.Get("owner_project_access") != "any" {
				t.Errorf("owner_project_access=%q, want any (orphaned keys would be hidden)", q.Get("owner_project_access"))
			}
			if q.Get("after") == "" {
				return 200, map[string]any{"object": "list", "data": []any{key("key_busy", "busy", ago(1), "active")}, "has_more": true, "last_id": "key_busy"}
			}
			return 200, listOf(key("key_orphan", "orphan", ago(2), "inactive"))
		},
		"/organization/projects/proj_lab/api_keys": httpxtest.Static(listOf(
			key("key_capped", "capped", ago(1), "active"),
			key("key_stale", "stale", ago(200), "active"),
			key("key_never", "never", nil, "active"),
		)),
		"/organization/admin_api_keys": httpxtest.Static(listOf(
			map[string]any{"id": "adm_used", "name": "ci", "redacted_value": "sk-admin-****used", "created_at": ago(50), "last_used_at": ago(3), "owner": map[string]any{"name": "Ana"}},
			map[string]any{"id": "adm_never", "name": "old", "redacted_value": "sk-admin-****nevr", "created_at": ago(300), "last_used_at": nil, "owner": map[string]any{"name": "Ana"}},
		)),
		"/organization/costs": func(q url.Values) (int, any) {
			if q.Get("group_by[]") != "project_id" || q.Get("start_time") == "" {
				t.Errorf("costs query: %v", q)
			}
			bucket := func(results ...any) map[string]any { return map[string]any{"object": "bucket", "results": results} }
			cost := func(project any, v float64) map[string]any {
				return map[string]any{"object": "organization.costs.result", "amount": map[string]any{"value": v, "currency": "usd"}, "project_id": project}
			}
			if q.Get("page") == "" {
				return 200, map[string]any{"data": []any{bucket(cost("proj_prod", 10.5), cost("proj_lab", 1.25))}, "has_more": true, "next_page": "p2"}
			}
			return 200, map[string]any{"data": []any{bucket(cost("proj_prod", 2), cost(nil, 0.25))}, "has_more": false, "next_page": nil}
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
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateOK {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
	rec.AssertNoSecret(t, testKey)

	cases := []struct {
		typ, id string
		kind    finding.Kind
		sev     finding.Severity
	}{
		{"organization", account, finding.KindSpend, finding.SevHigh}, // no limit, no alerts
		{"project", "proj_prod", finding.KindSpend, finding.SevHigh},
		{"project", "proj_lab", finding.KindSpend, finding.SevInfo},
		{"api_key", "key_busy", finding.KindCredential, finding.SevHigh}, // nothing caps prod
		{"api_key", "key_orphan", finding.KindCredential, finding.SevHigh},
		{"api_key", "key_capped", finding.KindCredential, finding.SevInfo},
		{"api_key", "key_stale", finding.KindCredential, finding.SevMedium},
		{"api_key", "key_never", finding.KindCredential, finding.SevMedium},
		{"admin_api_key", "adm_used", finding.KindCredential, finding.SevInfo},
		{"admin_api_key", "adm_never", finding.KindCredential, finding.SevMedium},
	}
	if len(rec.Findings) != len(cases) {
		t.Fatalf("got %d findings, want %d", len(rec.Findings), len(cases))
	}
	for _, tc := range cases {
		f := rec.ByResource(t, tc.typ, tc.id)
		if f.Kind != tc.kind || f.Severity != tc.sev {
			t.Errorf("%s %s: kind=%s severity=%s, want %s %s (%s)", tc.typ, tc.id, f.Kind, f.Severity, tc.kind, tc.sev, f.Title)
		}
	}

	org := rec.ByResource(t, "organization", account)
	if org.Evidence["cost_30d_usd"] != 14.0 {
		t.Errorf("org 30-day cost = %v, want 14", org.Evidence["cost_30d_usd"])
	}
	if got := rec.ByResource(t, "project", "proj_prod").Evidence["cost_30d_usd"]; got != 12.5 {
		t.Errorf("prod cost = %v, want 12.5", got)
	}
	lab := rec.ByResource(t, "project", "proj_lab")
	if lab.Evidence["hard_limit_usd_per_month"] != 50.0 {
		t.Errorf("lab limit evidence: %v", lab.Evidence)
	}

	stale := rec.ByResource(t, "api_key", "key_stale")
	if stale.LastUsedAt == nil || stale.LastUsedAt.Unix() != ago(200) || stale.CreatedAt == nil {
		t.Errorf("dates not carried: created=%v last=%v", stale.CreatedAt, stale.LastUsedAt)
	}
	if never := rec.ByResource(t, "api_key", "key_never"); never.LastUsedAt != nil {
		t.Errorf("a never-used key got a last-used date: %v", never.LastUsedAt)
	}
	if stale.Evidence["redacted"] != "sk-proj-****key_stale" || stale.Evidence["owner"] != "key_stale@example.test" {
		t.Errorf("evidence: %v", stale.Evidence)
	}
}

func TestMissingSecretReportsHowToConfigure(t *testing.T) {
	rec := &httpxtest.Recorder{}
	c := &Connector{BaseURL: "http://127.0.0.1:1"} // any request would fail loudly
	if err := c.Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Findings) != 0 || len(rec.Statuses) != 1 {
		t.Fatalf("findings=%v statuses=%v", rec.Findings, rec.Statuses)
	}
	st := rec.Statuses[0]
	if st.State != finding.StateMissingCredentials || st.Detail != setupHint {
		t.Fatalf("status: %+v", st)
	}
}

func TestBadKeyIsAnErrorStatusNotAFailure(t *testing.T) {
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

func TestBudgetSeverity(t *testing.T) {
	cases := []struct {
		name string
		l    limitState
		a    alertState
		want finding.Severity
	}{
		{"hard limit", limitState{known: true, set: true}, alertState{known: true}, finding.SevInfo},
		{"nothing at all", limitState{known: true}, alertState{known: true}, finding.SevHigh},
		{"alerts only", limitState{known: true}, alertState{known: true, count: 2}, finding.SevMedium},
		{"limit unreadable", limitState{}, alertState{known: true}, finding.SevLow},
		{"alerts unreadable", limitState{known: true}, alertState{}, finding.SevLow},
	}
	for _, tc := range cases {
		if got := budgetSeverity(tc.l, tc.a); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestKeyAssessment(t *testing.T) {
	at := func(days int) *time.Time { v := now.Add(-time.Duration(days) * 24 * time.Hour); return &v }
	capped, open, unknown := limitCover{known: true, set: true}, limitCover{known: true}, limitCover{}
	cases := []struct {
		name      string
		lastUsed  *time.Time
		expires   *time.Time
		ownerGone bool
		cover     limitCover
		want      finding.Severity
	}{
		{"active and capped", at(1), nil, false, capped, finding.SevInfo},
		{"active, no limit anywhere", at(1), nil, false, open, finding.SevHigh},
		{"limit state unknown is not called uncapped", at(1), nil, false, unknown, finding.SevInfo},
		{"idle 91 days", at(91), nil, false, capped, finding.SevMedium},
		{"idle 89 days", at(89), nil, false, capped, finding.SevInfo},
		{"never used", nil, nil, false, capped, finding.SevMedium},
		{"owner left", at(1), nil, true, capped, finding.SevHigh},
		{"expired", nil, at(1), true, open, finding.SevInfo},
	}
	for _, tc := range cases {
		if got := keyAssessment(tc.lastUsed, tc.expires, tc.ownerGone, tc.cover, now); got.Severity != tc.want {
			t.Errorf("%s: got %s %v, want %s", tc.name, got.Severity, got.Reasons, tc.want)
		}
	}
}

// The live admin listing also returns project keys (sk-proj-…), and it is the only place their
// last use shows up. They must not be reported as admin keys, and must lend their last use.
func TestAdminListingProjectKeysAreNotAdminKeysButLendLastUse(t *testing.T) {
	adminEntry := func(id, redacted string, lastUsed any) map[string]any {
		return map[string]any{"object": "organization.admin_api_key", "id": id, "name": id,
			"redacted_value": redacted, "created_at": ago(400), "last_used_at": lastUsed,
			"owner": map[string]any{"name": "Owner"}}
	}
	srv := httpxtest.NewServer(t, http.Header{"Authorization": {"Bearer " + testKey}}, map[string]httpxtest.Route{
		"/organization/projects":                     httpxtest.Static(listOf(map[string]any{"id": "proj_a", "name": "a"})),
		"/organization/spend_limit":                  httpxtest.Fail(http.StatusNotFound, "no spend limit"),
		"/organization/spend_alerts":                 httpxtest.Static(listOf()),
		"/organization/projects/proj_a/spend_limit":  httpxtest.Fail(http.StatusNotFound, "no spend limit"),
		"/organization/projects/proj_a/spend_alerts": httpxtest.Static(listOf()),
		"/organization/projects/proj_a/api_keys":     httpxtest.Static(listOf(key("key_p", "p", nil, "active"))),
		"/organization/admin_api_keys": httpxtest.Static(listOf(
			adminEntry("key_p", "sk-proj-****abcd", ago(3)),
			adminEntry("key_admin", "sk-admin****wxyz", nil),
		)),
		"/organization/costs": httpxtest.Static(map[string]any{"data": []any{}, "has_more": false, "next_page": nil}),
	})
	rec := &httpxtest.Recorder{}
	c := &Connector{BaseURL: srv.URL, Now: func() time.Time { return now }}
	if err := c.Inventory(context.Background(), connector.Request{Secrets: map[string]string{secretName: testKey}}, rec); err != nil {
		t.Fatal(err)
	}
	var admins, projectKeys []finding.Finding
	for _, f := range rec.Findings {
		switch f.Resource.Type {
		case "admin_api_key":
			admins = append(admins, f)
		case "api_key":
			projectKeys = append(projectKeys, f)
		}
	}
	if len(admins) != 1 || admins[0].Resource.ID != "key_admin" {
		t.Fatalf("admin findings = %+v, want only key_admin", admins)
	}
	if len(projectKeys) != 1 || projectKeys[0].LastUsedAt == nil || projectKeys[0].LastUsedAt.Unix() != ago(3) {
		t.Fatalf("project key should take last use from the admin listing: %+v", projectKeys)
	}
}
