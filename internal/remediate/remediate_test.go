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
	"time"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/connector/connectortest"
	"github.com/segurata/segurata/internal/fileacl/fileacltest"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/prompt"
	"github.com/segurata/segurata/internal/run"
)

var enable = connector.Step{Argv: []string{"/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"}, Sudo: true}

// fakeRemediator records Apply calls.
type fakeRemediator struct {
	plan    connector.Plan
	applied int
}

func (f *fakeRemediator) Plan(context.Context, finding.Finding) (connector.Plan, error) {
	return f.plan, nil
}

func (f *fakeRemediator) Apply(context.Context, finding.Finding, connector.Plan, connector.IO) error {
	f.applied++
	return nil
}

var target = finding.Finding{ID: "abc123", Connector: "macos", Account: "mac", Severity: finding.SevMedium, Title: "Firewall is off",
	Remediation: finding.Remediation{Action: "macos.firewall.enable", Automatable: true}}

// results is a check run that finished, inspected everything and reports ids.
func results(ids ...string) Reinventory {
	return func(context.Context) ([]*run.Result, error) {
		var tally finding.Tally
		tally.Declare("mac", true, "")
		r := &run.Result{Name: "macos", End: tally.End("macos", "", time.Now(), time.Now(), nil)}
		for _, id := range ids {
			r.Findings = append(r.Findings, finding.Finding{ID: id, Remediation: target.Remediation})
		}
		return []*run.Result{r}, nil
	}
}

func neverReinventory(t *testing.T) Reinventory {
	return func(context.Context) ([]*run.Result, error) {
		t.Fatal("reinventory ran without an apply")
		return nil, nil
	}
}

func TestDryRunPrintsThePlanAndNeverApplies(t *testing.T) {
	r := &fakeRemediator{plan: connector.Plan{Action: "macos.firewall.enable", Summary: "Turn on the firewall.", Commands: []connector.Step{enable},
		Undo: []connector.Step{{Argv: []string{"/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "off"}, Sudo: true}}}}
	io := connectortest.QuietIO()
	if err := Execute(context.Background(), target, r, Options{IO: io, TTY: true}, neverReinventory(t)); err != nil {
		t.Fatal(err)
	}
	out := io.Out.(*bytes.Buffer).String()
	for _, want := range []string{"sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on", "--setglobalstate off", "Dry run", "password"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan output lacks %q:\n%s", want, out)
		}
	}
	if r.applied != 0 {
		t.Fatal("dry run applied")
	}
}

func TestApplyNeedsAConfirmation(t *testing.T) {
	cases := []struct {
		answer   string
		yes, tty bool
		applied  int
		err      error
	}{
		{answer: "", tty: false, applied: 0, err: prompt.ErrNotTTY},
		{answer: "", yes: true, applied: 1},
		{answer: "y\n", tty: true, applied: 1},
		{answer: "YES\n", tty: true, applied: 1},
		{answer: "\n", tty: true},
		{answer: "n\n", tty: true},
		{answer: "", tty: true},
		{answer: "sure\n", tty: true},
	}
	for _, c := range cases {
		r := &fakeRemediator{plan: connector.Plan{Action: "macos.firewall.enable"}}
		io := connectortest.QuietIO()
		io.In = strings.NewReader(c.answer)
		check := results()
		if c.applied == 0 {
			check = neverReinventory(t)
		}
		err := Execute(context.Background(), target, r, Options{Apply: true, Yes: c.yes, TTY: c.tty, IO: io}, check)
		if !errors.Is(err, c.err) || r.applied != c.applied {
			t.Errorf("answer %q yes=%v tty=%v: err=%v applied=%d, want %v and %d", c.answer, c.yes, c.tty, err, r.applied, c.err, c.applied)
		}
	}
}

func TestMain(m *testing.M) {
	sleep = func(time.Duration) {}
	os.Exit(m.Run())
}

func TestVerifyAfterApply(t *testing.T) {
	r := &fakeRemediator{plan: connector.Plan{Action: "macos.firewall.enable"}}
	var slept []time.Duration
	sleep = func(d time.Duration) { slept = append(slept, d) }
	t.Cleanup(func() { sleep = func(time.Duration) {} })
	opt := Options{Apply: true, Yes: true, IO: connectortest.QuietIO()}
	if err := Execute(context.Background(), target, r, opt, results("other")); err != nil {
		t.Fatalf("finding gone should pass: %v", err)
	}
	if err := Execute(context.Background(), target, r, opt, results("other", target.ID)); !errors.Is(err, errStillPresent) {
		t.Fatalf("finding still there: want errStillPresent, got %v", err)
	}
	if len(slept) == 0 || slept[0] < time.Second {
		t.Fatalf("the check must wait for the fix to settle before looking, slept %v", slept)
	}
	// Gone on the first look, back on the second: a restart dropped the ports for a moment.
	looks := 0
	flapping := func(ctx context.Context) ([]*run.Result, error) {
		looks++
		if looks == 1 {
			return results("other")(ctx)
		}
		return results("other", target.ID)(ctx)
	}
	if err := Execute(context.Background(), target, r, opt, flapping); !errors.Is(err, errStillPresent) {
		t.Fatalf("a finding that comes back on a later check is not fixed: got %v", err)
	}
	failed := func(context.Context) ([]*run.Result, error) {
		return []*run.Result{{Name: "macos", Err: errors.New("could not start")}}, nil
	}
	if err := Execute(context.Background(), target, r, opt, failed); err == nil || errors.Is(err, errStillPresent) {
		t.Fatalf("a check that could not run must not count as fixed: %v", err)
	}
}

func TestForPicksCoreFileActionsAndRefusesManualFindings(t *testing.T) {
	if _, err := For(finding.Finding{ID: "x", Remediation: finding.Remediation{Summary: "by hand"}}, nil, nil); err == nil {
		t.Fatal("manual finding should not be remediable")
	}
	r, err := For(finding.Finding{Connector: "local-secrets", Remediation: finding.Remediation{Action: connector.ActionChmod600}}, nil, nil)
	if _, ok := r.(files); err != nil || !ok {
		t.Fatalf("file.chmod600 belongs to the core: %T %v", r, err)
	}
	if _, err := For(finding.Finding{Connector: "nope", Remediation: finding.Remediation{Action: "nope.fix"}}, nil, nil); err == nil {
		t.Fatal("missing connector should fail")
	}
	builtin := &fakeConnector{fakeRemediator: &fakeRemediator{}}
	if r, err := For(target, []connector.Connector{builtin}, nil); err != nil || r != builtin {
		t.Fatalf("a built-in remediator remediates itself: %v %v", r, err)
	}
	if _, err := For(target, []connector.Connector{inventoryOnly{}}, nil); err == nil || !strings.Contains(err.Error(), "cannot remediate") {
		t.Fatalf("a connector without remediation: %v", err)
	}
	cred := credentialed{}
	if _, err := For(target, []connector.Connector{cred}, nil); err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Fatalf("a credentialed remediator without credentials: %v", err)
	}
	r, err = For(target, []connector.Connector{cred}, func(finding.Finding) (connector.Credentials, error) {
		return connector.Credentials{WriteRefs: map[string]string{"K": "env:K"}}, nil
	})
	if got, ok := r.(credentialed); err != nil || !ok || got.creds.WriteRefs["K"] != "env:K" {
		t.Fatalf("the instance's credentials reach the remediator: %#v %v", r, err)
	}
}

type inventoryOnly struct{}

func (inventoryOnly) Describe() connector.Description { return connector.Description{Name: "macos"} }
func (inventoryOnly) Inventory(context.Context, connector.Request, connector.Emitter) error {
	return nil
}

type fakeConnector struct {
	inventoryOnly
	*fakeRemediator
}

type credentialed struct {
	inventoryOnly
	creds connector.Credentials
}

func (c credentialed) WithCredentials(cs connector.Credentials) connector.Remediator {
	return credentialed{creds: cs}
}
func (credentialed) Plan(context.Context, finding.Finding) (connector.Plan, error) {
	return connector.Plan{}, nil
}
func (credentialed) Apply(context.Context, finding.Finding, connector.Plan, connector.IO) error {
	return nil
}

func TestChmod600PlansExactlyAndApplies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	f := finding.Finding{Kind: finding.KindExposure, Evidence: map[string]any{"path": "~/.env"},
		Remediation: finding.Remediation{Action: connector.ActionChmod600}}
	fs := files{home: func() (string, error) { return dir, nil }}
	p, err := fs.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	want := connector.Plan{
		Action: connector.ActionChmod600, Summary: "Make " + path + " readable and writable by its owner only.",
		Files:       []connector.FileChange{{Path: path, Mode: 0o600, Was: 0o644}},
		Undo:        []connector.Step{{Argv: []string{"/bin/chmod", "644", path}}},
		SideEffects: p.SideEffects,
	}
	if !reflect.DeepEqual(want, p) || p.NeedsSudo() {
		t.Fatalf("plan %+v", p)
	}
	if err := fs.Apply(context.Background(), f, p, connectortest.QuietIO()); err != nil {
		t.Fatal(err)
	}
	fileacltest.AssertPrivate(t, path)
	if _, err := fs.Plan(context.Background(), f); err == nil {
		t.Fatal("an already private file has nothing to plan")
	}
}

func TestChmod600RefusesStalePlansSymlinksAndRelativePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	_ = os.WriteFile(path, nil, 0o600)
	_ = os.Chmod(path, 0o640)
	f := finding.Finding{Evidence: map[string]any{"path": path}, Remediation: finding.Remediation{Action: connector.ActionChmod600}}
	p, err := files{}.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	_ = os.WriteFile(other, nil, 0o600)
	_ = os.Chmod(other, 0o640)
	p.Files[0].Path = other
	altered := &connectortest.ShownOnce{Remediator: files{}, Shown: &p}
	if err := Execute(context.Background(), f, altered, Options{Apply: true, Yes: true, IO: connectortest.QuietIO()}, neverReinventory(t)); err == nil {
		t.Fatal("applied an altered plan")
	}
	if fi, _ := os.Stat(other); fi.Mode().Perm() != 0o640 {
		t.Fatalf("the altered plan changed %s to %o", other, fi.Mode().Perm())
	}
	link := filepath.Join(dir, "link")
	_ = os.Symlink(path, link)
	for _, bad := range []string{link, "relative/key", ""} {
		g := finding.Finding{Evidence: map[string]any{"path": bad}, Remediation: finding.Remediation{Action: connector.ActionChmod600}}
		if _, err := (files{}).Plan(context.Background(), g); err == nil {
			t.Errorf("planned chmod on %q", bad)
		}
	}
}

func TestPrintShowsEverySectionOfThePlan(t *testing.T) {
	f := finding.Finding{ID: "abc123", Severity: finding.SevMedium, Connector: "macos", Account: "mac", Title: "Firewall off"}
	p := connector.Plan{
		Action:      "macos.firewall.enable",
		Summary:     "Turn on the firewall.",
		Commands:    []connector.Step{enable},
		Files:       []connector.FileChange{{Path: "/tmp/a b", Mode: 0o600, Was: 0o644}},
		SideEffects: []string{"Prompts appear."},
		Undo:        []connector.Step{{Argv: []string{"/bin/echo", "off"}}},
	}
	var out bytes.Buffer
	printPlan(&out, f, p)
	want := "Finding  abc123 [" + string(finding.SevMedium) + "] macos · mac · Firewall off\n" +
		"Action   macos.firewall.enable\n" +
		"Plan     Turn on the firewall.\n" +
		"\nRuns (sudo asks for your password on this terminal; segurata never sees it):\n" +
		"  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on\n" +
		"\nChanges:\n" +
		"  chmod 600 '/tmp/a b' (now 644)\n" +
		"\nSide effects:\n" +
		"  - Prompts appear.\n" +
		"\nUndo:\n" +
		"  /bin/echo off\n"
	if out.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out.String(), want)
	}

	out.Reset()
	printPlan(&out, f, connector.Plan{Action: "a", Summary: "s", Commands: []connector.Step{{Argv: []string{"/bin/true"}}}})
	if !strings.Contains(out.String(), "\nRuns, as you:\n  /bin/true\n") || strings.Contains(out.String(), "Undo") {
		t.Fatalf("plan without sudo or undo printed:\n%s", out.String())
	}
}

func TestPrintEscapesControlCharactersInPlan(t *testing.T) {
	path := "/tmp/line\nwith\x1b-control\u202e"
	plan := connector.Plan{Summary: "Restrict " + path, Files: []connector.FileChange{{Path: path, Mode: 0o600, Was: 0o644}}}
	var out bytes.Buffer
	printPlan(&out, finding.Finding{Title: path}, plan)
	if strings.ContainsAny(out.String(), "\x1b\u202e") || !strings.Contains(out.String(), `line\nwith\x1b-control\u202e`) {
		t.Fatalf("unsafe plan rendering: %q", out.String())
	}
	if plan.Files[0].Path != path {
		t.Fatal("rendering changed the path that would be applied")
	}
}

func TestListHidesFindingsBelowTheMinimumSeverity(t *testing.T) {
	all := []finding.Finding{
		{Type: "finding", ID: "noise0001", Severity: finding.SevInfo, Remediation: finding.Remediation{Action: "file.chmod600"}},
		{Type: "finding", ID: "real00002", Severity: finding.SevMedium, Remediation: finding.Remediation{Action: "macos.firewall.enable"}},
	}
	var b bytes.Buffer
	List(&b, all, finding.SevLow)
	if strings.Contains(b.String(), "noise0001") || !strings.Contains(b.String(), "real00002") || !strings.Contains(b.String(), "1 more below low") {
		t.Fatalf("default list:\n%s", b.String())
	}
	b.Reset()
	List(&b, all, finding.SevInfo)
	if !strings.Contains(b.String(), "noise0001") {
		t.Fatalf("--all must include info:\n%s", b.String())
	}
}

// driftingRemediator states a different plan each time it is asked, and applies whatever it is
// handed without checking: what a remediator without a copy of the stale-plan guard does.
type driftingRemediator struct {
	plans   []connector.Plan
	applied []connector.Plan
}

func (d *driftingRemediator) Plan(context.Context, finding.Finding) (connector.Plan, error) {
	p := d.plans[0]
	if len(d.plans) > 1 {
		d.plans = d.plans[1:]
	}
	return p, nil
}

func (d *driftingRemediator) Apply(_ context.Context, _ finding.Finding, p connector.Plan, _ connector.IO) error {
	d.applied = append(d.applied, p)
	return nil
}

func TestTheCoreRefusesAPlanThatDriftedBetweenConfirmAndApply(t *testing.T) {
	shown := connector.Plan{Action: target.Remediation.Action, Summary: "Turn on the firewall.", Commands: []connector.Step{enable}}
	now := shown
	now.Summary = "Turn on the firewall, and more."
	r := &driftingRemediator{plans: []connector.Plan{shown, now}}
	err := Execute(context.Background(), target, r, Options{Apply: true, Yes: true, IO: connectortest.QuietIO()}, neverReinventory(t))
	if err == nil || !strings.Contains(err.Error(), "plan changed") {
		t.Fatalf("want a refusal, got %v", err)
	}
	if len(r.applied) != 0 {
		t.Fatalf("applied %v, a plan that is no longer the one confirmed", r.applied)
	}

	same := &driftingRemediator{plans: []connector.Plan{shown}}
	if err := Execute(context.Background(), target, same, Options{Apply: true, Yes: true, IO: connectortest.QuietIO()}, results()); err != nil {
		t.Fatal(err)
	}
	if len(same.applied) != 1 || same.applied[0].Summary != shown.Summary {
		t.Fatalf("applied %v, want the confirmed plan once", same.applied)
	}
}

type driftingGroup struct{ driftingRemediator }

func (d *driftingGroup) PlanGroup(ctx context.Context, fs []finding.Finding) (connector.Plan, error) {
	return d.Plan(ctx, fs[0])
}

func (d *driftingGroup) ApplyGroup(ctx context.Context, fs []finding.Finding, p connector.Plan, io connector.IO) error {
	return d.Apply(ctx, fs[0], p, io)
}

func TestTheCoreRefusesAGroupPlanThatDrifted(t *testing.T) {
	a, b := grouped("a1", "owner", finding.SevHigh), grouped("b2", "owner", finding.SevHigh)
	shown := connector.Plan{Action: a.Remediation.Action, Summary: "Enable secret scanning in 2 repositories."}
	now := shown
	now.Summary = "Enable secret scanning in 3 repositories."
	r := &driftingGroup{driftingRemediator{plans: []connector.Plan{shown, now}}}
	opt := Options{Apply: true, Yes: true, IO: connectortest.QuietIO(), Group: []finding.Finding{a, b}}
	if err := Execute(context.Background(), a, r, opt, neverReinventory(t)); err == nil || len(r.applied) != 0 {
		t.Fatalf("err=%v applied=%v", err, r.applied)
	}
}
