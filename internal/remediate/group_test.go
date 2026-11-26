package remediate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/connector/connectortest"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/run"
)

// fakeGroup records the group it was asked to plan and apply.
type fakeGroup struct {
	fakeRemediator
	planned, appliedTo [][]string
}

func ids(fs []finding.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.ID
	}
	return out
}

func (g *fakeGroup) PlanGroup(_ context.Context, fs []finding.Finding) (connector.Plan, error) {
	g.planned = append(g.planned, ids(fs))
	return g.plan, nil
}

func (g *fakeGroup) ApplyGroup(_ context.Context, fs []finding.Finding, _ connector.Plan, _ connector.IO) error {
	g.appliedTo = append(g.appliedTo, ids(fs))
	return nil
}

func grouped(id, group string, sev finding.Severity) finding.Finding {
	return finding.Finding{ID: id, Connector: "github", Account: "github:me", Severity: sev, Title: "repo " + id,
		Remediation: finding.Remediation{Action: "github.secret-scanning.enable", Group: group}}
}

func TestMembersGatherTheSameActionAndGroupOfOneInstance(t *testing.T) {
	a, b := grouped("a", "me", finding.SevMedium), grouped("b", "me", finding.SevMedium)
	otherGroup := grouped("c", "acme", finding.SevMedium)
	otherAction := grouped("d", "me", finding.SevMedium)
	otherAction.Remediation.Action = "github.workflow-token.read"
	otherInstance := grouped("e", "me", finding.SevMedium)
	otherInstance.Instance = "work"
	accepted := grouped("f", "me", finding.SevMedium)
	accepted.Accepted = &finding.Acceptance{Reason: "kept"}
	got := ids(Members([]finding.Finding{a, b, otherGroup, otherAction, otherInstance, accepted}, b))
	if strings.Join(got, ",") != "b,a" {
		t.Fatalf("members %v, want the target first, then a", got)
	}
	alone := target
	if got := Members([]finding.Finding{alone, alone}, alone); len(got) != 1 {
		t.Fatalf("a finding without a group is its own group: %v", ids(got))
	}
}

func TestGroupPlanCoversEveryMemberAndVerifiesEach(t *testing.T) {
	a, b := grouped("a", "me", finding.SevMedium), grouped("b", "me", finding.SevMedium)
	g := &fakeGroup{fakeRemediator: fakeRemediator{plan: connector.Plan{Action: a.Remediation.Action, Summary: "Enable."}}}
	io := connectortest.QuietIO()
	if err := Execute(context.Background(), a, g, Options{IO: io, Group: []finding.Finding{a, b}}, neverReinventory(t)); err != nil {
		t.Fatal(err)
	}
	if out := io.Out.(*bytes.Buffer).String(); !strings.Contains(out, "Fixes these 2 findings:") || !strings.Contains(out, "b [medium] repo b") {
		t.Fatalf("the plan must list the group:\n%s", out)
	}
	fresh := func(fs ...finding.Finding) Reinventory {
		return func(context.Context) ([]*run.Result, error) {
			var tally finding.Tally
			tally.Declare("github:me", true, "")
			return []*run.Result{{Name: "github", Findings: fs, End: tally.End("github", "", target.ObservedAt, target.ObservedAt, nil)}}, nil
		}
	}
	opt := Options{Apply: true, Yes: true, IO: connectortest.QuietIO(), Group: []finding.Finding{a, b}}
	if err := Execute(context.Background(), a, g, opt, fresh(b)); !errors.Is(err, errStillPresent) {
		t.Fatalf("one member still offering the action: want errStillPresent, got %v", err)
	}
	// The same repository finding without the action (its deploy key is still there) is fixed as
	// far as this action goes.
	rest := b
	rest.Remediation = finding.Remediation{Summary: "Delete the deploy key."}
	if err := Execute(context.Background(), a, g, opt, fresh(rest)); err != nil {
		t.Fatalf("want fixed, got %v", err)
	}
	if len(g.appliedTo) != 2 || strings.Join(g.appliedTo[0], ",") != "a,b" {
		t.Fatalf("applied to %v", g.appliedTo)
	}
}

func TestAGroupNeedsAGroupRemediator(t *testing.T) {
	a, b := grouped("a", "me", finding.SevMedium), grouped("b", "me", finding.SevMedium)
	r := &fakeRemediator{plan: connector.Plan{Action: a.Remediation.Action}}
	err := Execute(context.Background(), a, r, Options{Apply: true, Yes: true, IO: connectortest.QuietIO(), Group: []finding.Finding{a, b}}, neverReinventory(t))
	if err == nil || r.applied != 0 {
		t.Fatalf("a single-finding remediator must not apply a group of two: err=%v applied=%d", err, r.applied)
	}
}

func TestBlockedPlansAreShownButNeverApplied(t *testing.T) {
	r := &fakeRemediator{plan: connector.Plan{Action: "openai.key.delete-unused", Summary: "Delete key k.",
		Calls:   []connector.Call{{Method: "DELETE", URL: "https://api.openai.com/v1/organization/admin_api_keys/k", Secret: "OPENAI_ADMIN_WRITE_KEY"}},
		Blocked: "set OPENAI_ADMIN_WRITE_KEY under connectors.openai.remediation_secrets"}}
	f := target
	f.Remediation.Action = r.plan.Action
	io := connectortest.QuietIO()
	if err := Execute(context.Background(), f, r, Options{IO: io}, neverReinventory(t)); err != nil {
		t.Fatal(err)
	}
	out := io.Out.(*bytes.Buffer).String()
	for _, want := range []string{"Requests, sent by segurata:", "DELETE https://api.openai.com/v1/organization/admin_api_keys/k (with OPENAI_ADMIN_WRITE_KEY)", "Blocked", "remediation_secrets"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
	err := Execute(context.Background(), f, r, Options{Apply: true, Yes: true, TTY: true, IO: connectortest.QuietIO()}, neverReinventory(t))
	if err == nil || !strings.Contains(err.Error(), "remediation_secrets") || r.applied != 0 {
		t.Fatalf("a blocked plan must be refused before asking: err=%v applied=%d", err, r.applied)
	}
}

func TestTerminalStepsNeedATerminalEvenWithYes(t *testing.T) {
	step := connector.Step{Argv: []string{"gh", "auth", "refresh", "-h", "github.com", "-r", "delete_repo"}, Terminal: true}
	r := &fakeRemediator{plan: connector.Plan{Action: "connected-apps.gh.drop-scopes", Summary: "Drop.", Commands: []connector.Step{step}}}
	err := Execute(context.Background(), target, r, Options{Apply: true, Yes: true, TTY: false, IO: connectortest.QuietIO()}, neverReinventory(t))
	if !errors.Is(err, errNeedsTerminal) || r.applied != 0 {
		t.Fatalf("err=%v applied=%d", err, r.applied)
	}
	io := connectortest.QuietIO()
	if err := Execute(context.Background(), target, r, Options{IO: io}, neverReinventory(t)); err != nil {
		t.Fatal(err)
	}
	if out := io.Out.(*bytes.Buffer).String(); !strings.Contains(out, "Runs in your terminal") {
		t.Fatalf("plan output:\n%s", out)
	}
	if step.Equal(connector.Step{Argv: step.Argv}) {
		t.Fatal("a terminal step and the same argv run without the terminal are different steps")
	}
}

func TestListShowsAGroupAsOneLineRankedByItsActionSeverity(t *testing.T) {
	all := []finding.Finding{
		grouped("a1", "me", finding.SevMedium), grouped("a2", "me", finding.SevHigh), grouped("a3", "me", finding.SevMedium),
		grouped("b1", "acme", finding.SevMedium),
		// A hardening chmod on a high finding ranks as low.
		{ID: "harden01", Connector: "local-secrets", Severity: finding.SevHigh, Title: "key in ~/x",
			Remediation: finding.Remediation{Action: connector.ActionChmod600, Severity: finding.SevLow, Group: "hardening:~/src"}},
	}
	var b bytes.Buffer
	List(&b, all, finding.SevMedium)
	out := b.String()
	if strings.Count(out, "github.secret-scanning.enable") != 2 {
		t.Fatalf("want one line per group:\n%s", out)
	}
	if !strings.Contains(out, "a2  [high") || !strings.Contains(out, "3 findings of me") {
		t.Fatalf("the group shows under its worst member with its size:\n%s", out)
	}
	if strings.Contains(out, "harden01") || !strings.Contains(out, "1 more below medium") {
		t.Fatalf("a hardening action ranks by its own severity:\n%s", out)
	}
}

func TestChmodGroupClosesEachFileOnceAndKeepsScriptsRunnable(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("X=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	env, script, done := write(".env", 0o644), write("deploy.sh", 0o755), write("closed", 0o600)
	member := func(id, path string) finding.Finding {
		return finding.Finding{ID: id, Connector: "local-secrets", Evidence: map[string]any{"path": path},
			Remediation: finding.Remediation{Action: connector.ActionChmod600, Group: "files in " + dir, Severity: finding.SevLow}}
	}
	// Two secrets in .env are two findings naming one file.
	group := []finding.Finding{member("a", env), member("b", env), member("c", script), member("d", done)}
	fs := files{}
	p, err := fs.PlanGroup(context.Background(), group)
	if err != nil {
		t.Fatal(err)
	}
	want := []connector.FileChange{{Path: env, Mode: 0o600, Was: 0o644}, {Path: script, Mode: 0o700, Was: 0o755}}
	if !reflect.DeepEqual(p.Files, want) || p.Summary != "Make 2 files readable and writable by their owner only." {
		t.Fatalf("plan %+v", p)
	}
	if len(p.Undo) != 2 || p.Undo[1].String() != "/bin/chmod 755 "+script {
		t.Fatalf("undo %v", p.Undo)
	}
	if !strings.Contains(strings.Join(p.SideEffects, "\n"), "Left out: "+done+" is already private") {
		t.Fatalf("side effects %v", p.SideEffects)
	}
	if err := fs.ApplyGroup(context.Background(), group, p, connectortest.QuietIO()); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{env: 0o600, script: 0o700} {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != mode {
			t.Errorf("%s: mode %o, want %o", path, fi.Mode().Perm(), mode)
		}
	}
	if _, err := fs.PlanGroup(context.Background(), group); err == nil || !strings.Contains(err.Error(), "nothing to change in 3 files") {
		t.Fatalf("all closed: %v", err)
	}
}
