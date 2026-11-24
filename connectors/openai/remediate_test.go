package openai

import (
	"bytes"
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/connector/connectortest"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
)

const testWriteKey = "sk-admin-WRITE-not-a-real-key-111111111"

func quietIO() connector.IO {
	return connector.IO{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
}

// keysServer lists one project with a never-used, a stale and a busy key, and two admin keys, one
// of them the inventory's own.
func keysServer(t *testing.T) *httpxtest.Server {
	srv := httpxtest.NewServer(t, http.Header{"Authorization": {"Bearer " + testKey}}, map[string]httpxtest.Route{
		"/organization/projects/proj_lab/api_keys": httpxtest.Static(listOf(
			key("key_never", "never", nil, "active"),
			key("key_stale", "stale", nil, "active"), // its last use is only in the admin listing
			key("key_busy", "busy", ago(2), "active"),
		)),
		"/organization/projects": httpxtest.Static(listOf(map[string]any{"id": "proj_lab", "name": "lab"}, map[string]any{"id": "proj_prod", "name": "prod"})),
		"/organization/admin_api_keys": httpxtest.Static(listOf(
			map[string]any{"id": "key_stale", "redacted_value": "sk-proj-****stal", "last_used_at": ago(200)},
			map[string]any{"id": "adm_old", "name": "old", "redacted_value": "sk-admin-****dead", "last_used_at": nil},
			map[string]any{"id": "adm_self", "name": "segurata", "redacted_value": "sk-admin-****0000", "last_used_at": nil},
		)),
	})
	srv.DeleteAuth = http.Header{"Authorization": {"Bearer " + testWriteKey}}
	return srv
}

func creds(write bool) connector.Credentials {
	cs := connector.Credentials{Request: connector.Request{Secrets: map[string]string{secretName: testKey}},
		Resolve: func(context.Context, string) (string, error) { return testWriteKey, nil }}
	if write {
		cs.WriteRefs = map[string]string{writeSecret: "keychain:segurata-openai-admin-write"}
	}
	return cs
}

func keyFindingFor(typ, id string) finding.Finding {
	return finding.Finding{ID: id, Connector: name, Resource: finding.Resource{Type: typ, ID: id},
		Evidence:    map[string]any{"project_id": "proj_lab", "project": "lab"},
		Remediation: finding.Remediation{Action: ActionDeleteUnusedKey}}
}

func TestInventoryOffersDeletionOnlyForUnusedKeys(t *testing.T) {
	for _, c := range []struct {
		last, exp *time.Time
		want      string
	}{
		{nil, nil, ActionDeleteUnusedKey},
		{ptr(now.Add(-200 * 24 * time.Hour)), nil, ActionDeleteUnusedKey},
		{ptr(now.Add(-2 * 24 * time.Hour)), nil, ""},
		{nil, ptr(now.Add(-time.Hour)), ""}, // expired: nothing can use it anyway
	} {
		if got := unusedAction(c.last, c.exp, now); got != c.want {
			t.Errorf("last %v expires %v: %q, want %q", c.last, c.exp, got, c.want)
		}
	}
	f := projectKeyFinding(projectKey{ID: "k", Name: "n"}, project{ID: "proj_x"}, limitCover{}, now)
	if f.Evidence["project_id"] != "proj_x" || f.Remediation.Action != ActionDeleteUnusedKey {
		t.Fatalf("project key finding: %v %+v", f.Evidence, f.Remediation)
	}
}

func ptr(t time.Time) *time.Time { return &t }

func TestDeletePlanIsExactAndBlockedWithoutAWriteKey(t *testing.T) {
	srv := keysServer(t)
	c := &Connector{BaseURL: srv.URL, Now: func() time.Time { return now }}
	r := c.WithCredentials(creds(false))
	p, err := r.Plan(context.Background(), keyFindingFor("api_key", "key_stale"))
	if err != nil {
		t.Fatal(err)
	}
	want := []connector.Call{{Method: "DELETE", URL: srv.URL + "/organization/projects/proj_lab/api_keys/key_stale", Secret: writeSecret}}
	if !reflect.DeepEqual(p.Calls, want) || len(p.Commands) != 0 || len(p.Undo) != 0 {
		t.Fatalf("plan %+v", p)
	}
	if !strings.Contains(p.Summary, `project API key "stale" in project "lab" (sk-proj-…tale(?))`) || !strings.Contains(p.Summary, "200 days ago") {
		t.Errorf("summary %q", p.Summary)
	}
	if !strings.Contains(p.Blocked, "remediation_secrets") || !strings.Contains(p.SideEffects[0], "No undo") {
		t.Errorf("blocked %q side effects %v", p.Blocked, p.SideEffects)
	}
	if err := r.Apply(context.Background(), keyFindingFor("api_key", "key_stale"), p, quietIO()); err == nil || len(srv.Deleted) != 0 {
		t.Fatalf("apply without a write key: %v, deleted %v", err, srv.Deleted)
	}
}

func TestDeleteAppliesWithTheWriteKeyOnly(t *testing.T) {
	srv := keysServer(t)
	c := &Connector{BaseURL: srv.URL, Now: func() time.Time { return now }}
	r := c.WithCredentials(creds(true))
	for _, f := range []finding.Finding{keyFindingFor("api_key", "key_never"), keyFindingFor("admin_api_key", "adm_old")} {
		p, err := r.Plan(context.Background(), f)
		if err != nil || p.Blocked != "" {
			t.Fatalf("%s: %v %q", f.ID, err, p.Blocked)
		}
		if err := r.Apply(context.Background(), f, p, quietIO()); err != nil {
			t.Fatal(err)
		}
	}
	if want := []string{"/organization/projects/proj_lab/api_keys/key_never", "/organization/admin_api_keys/adm_old"}; !reflect.DeepEqual(srv.Deleted, want) {
		t.Fatalf("deleted %v, want %v", srv.Deleted, want)
	}
}

func TestDeleteRefusesKeysInUseGoneOrSegurataSOwn(t *testing.T) {
	srv := keysServer(t)
	c := &Connector{BaseURL: srv.URL, Now: func() time.Time { return now }}
	r := c.WithCredentials(creds(true))
	for id, f := range map[string]finding.Finding{
		"in use since the inventory": keyFindingFor("api_key", "key_busy"),
		"gone":                       keyFindingFor("api_key", "key_deleted"),
		"the inventory's own key":    keyFindingFor("admin_api_key", "adm_self"),
	} {
		if _, err := r.Plan(context.Background(), f); err == nil {
			t.Errorf("%s: planned", id)
		}
	}
	// A plan altered after the key was read is refused by the core before anything is sent.
	f := keyFindingFor("api_key", "key_never")
	altered, err := r.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	altered.Calls[0].URL = srv.URL + "/organization/projects/proj_lab/api_keys/key_busy"
	shown := &connectortest.ShownOnce{Remediator: r, Shown: &altered}
	opt := remediate.Options{Apply: true, Yes: true, IO: quietIO()}
	if err := remediate.Execute(context.Background(), f, shown, opt, nil); err == nil || len(srv.Deleted) != 0 {
		t.Fatalf("altered plan: %v, deleted %v", err, srv.Deleted)
	}
}

func TestReadOnlyWriteKeyIsExplained(t *testing.T) {
	srv := keysServer(t)
	srv.DeleteAuth = http.Header{"Authorization": {"Bearer some-other-key"}}
	c := &Connector{BaseURL: srv.URL, Now: func() time.Time { return now }}
	r := c.WithCredentials(creds(true))
	f := keyFindingFor("api_key", "key_never")
	p, err := r.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Apply(context.Background(), f, p, quietIO()); err == nil || !strings.Contains(err.Error(), writeSecret+" was refused") {
		t.Fatalf("want the read-only explanation, got %v", err)
	}
}

// A finding recorded before it carried the project id finds its project by name, if only one has it.
func TestDeletePlanFindsTheProjectOfAnOlderFindingByName(t *testing.T) {
	srv := keysServer(t)
	r := (&Connector{BaseURL: srv.URL, Now: func() time.Time { return now }}).WithCredentials(creds(true))
	f := keyFindingFor("api_key", "key_never")
	f.Evidence = map[string]any{"project": "lab"}
	p, err := r.Plan(context.Background(), f)
	if err != nil || p.Calls[0].URL != srv.URL+"/organization/projects/proj_lab/api_keys/key_never" {
		t.Fatalf("plan %+v %v", p.Calls, err)
	}
	f.Evidence = map[string]any{"project": "missing"}
	if _, err := r.Plan(context.Background(), f); err == nil {
		t.Fatal("a project name that matches nothing must not be planned")
	}
}
