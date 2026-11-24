package azure

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
)

type recordingExec struct{ ran []string }

func (r *recordingExec) Run(_ context.Context, s connector.Step, _ connector.IO) error {
	r.ran = append(r.ran, s.String())
	return nil
}

// withExpired is the fixture with two apps holding expired secrets, one of them two.
func withExpired() *fakeRunner {
	f := fixture()
	f.replies[appQuery] = `[{"appId":"11111111-1111-1111-1111-111111111111","displayName":"ci","passwordCredentials":[
			{"keyId":"k2","hint":"def","endDateTime":"2026-12-01T00:00:00Z"},
			{"keyId":"k3","hint":"ghi","endDateTime":"2025-01-01T00:00:00Z"}]},
		{"appId":"22222222-2222-2222-2222-222222222222","displayName":"crm","passwordCredentials":[
			{"keyId":"k4","hint":"jkl","endDateTime":"2024-06-01T00:00:00Z"},
			{"keyId":"k5","hint":"mno","endDateTime":"2024-07-01T00:00:00Z"}]}]`
	return f
}

func expiredGroup(t *testing.T, run *fakeRunner) []finding.Finding {
	t.Helper()
	rec := &httpxtest.Recorder{}
	c := &Connector{Run: run, Now: func() time.Time { return now }}
	if err := c.Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	var all []finding.Finding
	for _, f := range rec.Findings {
		f.Connector = "azure"
		f.Fill(now)
		all = append(all, f)
	}
	for _, f := range all {
		if f.Remediation.Action == ActionDeleteExpiredSecrets {
			return remediate.Members(all, f)
		}
	}
	t.Fatal("no expired secret offers the action")
	return nil
}

func TestExpiredSecretsAreOneTenantGroup(t *testing.T) {
	group := expiredGroup(t, withExpired())
	if len(group) != 3 {
		t.Fatalf("want the 3 expired secrets, got %d", len(group))
	}
	for _, f := range group {
		if f.Remediation.Group != "example.onmicrosoft.com" || f.Severity != finding.SevLow {
			t.Errorf("%s: %+v", f.Title, f.Remediation)
		}
	}
}

func TestDeleteExpiredPlanIsExactAndHasNoUndo(t *testing.T) {
	run := withExpired()
	group := expiredGroup(t, run)
	// Since the inventory, someone deleted k4 by hand.
	run.replies[appQuery] = strings.Replace(run.replies[appQuery], `{"keyId":"k4","hint":"jkl","endDateTime":"2024-06-01T00:00:00Z"},`, ``, 1)
	c := &Connector{Run: run, Now: func() time.Time { return now }}
	p, err := c.PlanGroup(context.Background(), group)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range p.Commands {
		got = append(got, s.String())
	}
	want := []string{
		"az ad app credential delete --id 11111111-1111-1111-1111-111111111111 --key-id k3 --only-show-errors",
		"az ad app credential delete --id 22222222-2222-2222-2222-222222222222 --key-id k5 --only-show-errors",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("commands\n got %v\nwant %v", got, want)
	}
	if p.Summary != "Delete 2 expired client secrets from 2 app registrations in tenant example.onmicrosoft.com." || len(p.Undo) != 0 {
		t.Errorf("summary %q undo %v", p.Summary, p.Undo)
	}
	effects := strings.Join(p.SideEffects, "\n")
	for _, w := range []string{"No undo", `Deletes secret ghi… of app "ci", expired 2025-01-01.`, "Left out: secret k4 of app 22222222-2222-2222-2222-222222222222 (no longer registered)."} {
		if !strings.Contains(effects, w) {
			t.Errorf("side effects lack %q:\n%s", w, effects)
		}
	}

	ex := &recordingExec{}
	c.Exec = ex
	io := connector.IO{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	if err := c.ApplyGroup(context.Background(), group, p, io); err != nil || !reflect.DeepEqual(ex.ran, want) {
		t.Fatalf("apply: %v ran %v", err, ex.ran)
	}
}

func TestDeleteExpiredRefusesLiveSecretsAndAnotherTenant(t *testing.T) {
	run := withExpired()
	group := expiredGroup(t, run)
	c := &Connector{Run: run, Now: func() time.Time { return now }}
	st, err := c.readSecrets(context.Background(), group)
	if err != nil {
		t.Fatal(err)
	}
	allow := st.allowlist()
	for _, s := range []connector.Step{
		deleteStep("11111111-1111-1111-1111-111111111111", "k2"), // still valid until December
		deleteStep("11111111-1111-1111-1111-111111111111", "k1"),
		{Argv: []string{"az", "ad", "app", "delete", "--id", "11111111-1111-1111-1111-111111111111"}},
	} {
		if err := allow.Check(ActionDeleteExpiredSecrets, s); !errors.Is(err, remediate.ErrRefused) {
			t.Errorf("%s: want refusal, got %v", s, err)
		}
	}

	// A secret that has not expired yet is never in the plan, even when a finding names it.
	live := group[0]
	live.Evidence = map[string]any{"app_id": "11111111-1111-1111-1111-111111111111", "key_id": "k2"}
	if _, err := c.PlanGroup(context.Background(), []finding.Finding{live}); err == nil || !strings.Contains(err.Error(), "nothing to do") {
		t.Fatalf("a live secret must not be planned: %v", err)
	}

	run.replies["account show"] = `{"tenantDefaultDomain":"other.onmicrosoft.com"}`
	if _, err := c.PlanGroup(context.Background(), group); err == nil || !strings.Contains(err.Error(), "az login --tenant example.onmicrosoft.com") {
		t.Fatalf("another tenant: %v", err)
	}
}
