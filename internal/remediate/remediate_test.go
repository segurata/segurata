package remediate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/runtest"
)

var enable = connector.Step{Argv: []string{"/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"}, Sudo: true}

type recordingExec struct{ ran []connector.Step }

func (r *recordingExec) Run(_ context.Context, s connector.Step, _ connector.IO) error {
	r.ran = append(r.ran, s)
	return nil
}

func quietIO() connector.IO {
	return connector.IO{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
}

func TestAllowlistMatchesExactArgvAndSudo(t *testing.T) {
	allow := Allowlist{"a": {enable}}
	if err := allow.Check("a", enable); err != nil {
		t.Fatal(err)
	}
	refused := []connector.Step{
		{Argv: enable.Argv},                          // same argv without sudo
		{Argv: append(enable.Argv, "x"), Sudo: true}, // extra argument
		{Argv: []string{"/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "off"}, Sudo: true},
		{Argv: []string{"/bin/sh", "-c", "id"}, Sudo: true},
	}
	for _, s := range refused {
		if err := allow.Check("a", s); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: want refusal, got %v", s, err)
		}
	}
	if err := allow.Check("other", enable); !errors.Is(err, ErrRefused) {
		t.Errorf("a step allowed for one action must not run for another: %v", err)
	}
}

func TestRunChecksEveryStepBeforeRunningAny(t *testing.T) {
	ex := &recordingExec{}
	p := connector.Plan{Action: "a", Commands: []connector.Step{enable, {Argv: []string{"/bin/rm", "-rf", "/"}, Sudo: true}}}
	if err := Run(context.Background(), p, Allowlist{"a": {enable}}, ex, quietIO()); !errors.Is(err, ErrRefused) {
		t.Fatalf("want refusal, got %v", err)
	}
	if len(ex.ran) != 0 {
		t.Fatalf("ran %v before refusing the plan", ex.ran)
	}
	if err := Run(context.Background(), connector.Plan{Action: "a", Commands: []connector.Step{enable}}, Allowlist{"a": {enable}}, ex, quietIO()); err != nil || len(ex.ran) != 1 {
		t.Fatalf("err=%v ran=%v", err, ex.ran)
	}
}

func TestStepStringQuotesLikeAShell(t *testing.T) {
	s := connector.Step{Argv: []string{"/bin/chmod", "644", "/tmp/my file's"}, Sudo: true}
	if got, want := s.String(), `sudo /bin/chmod 644 '/tmp/my file'\''s'`; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

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
			r.Findings = append(r.Findings, finding.Finding{ID: id})
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
	io := quietIO()
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

func TestApplyRefusesWithoutATerminalUnlessYes(t *testing.T) {
	r := &fakeRemediator{plan: connector.Plan{Action: "macos.firewall.enable"}}
	err := Execute(context.Background(), target, r, Options{Apply: true, TTY: false, IO: quietIO()}, neverReinventory(t))
	if !errors.Is(err, ErrNotTTY) || r.applied != 0 {
		t.Fatalf("err=%v applied=%d", err, r.applied)
	}
	if err := Execute(context.Background(), target, r, Options{Apply: true, Yes: true, IO: quietIO()}, results()); err != nil || r.applied != 1 {
		t.Fatalf("--yes: err=%v applied=%d", err, r.applied)
	}
}

func TestApplyAsksAndOnlyAcceptsYes(t *testing.T) {
	for answer, want := range map[string]int{"y\n": 1, "YES\n": 1, "\n": 0, "n\n": 0, "": 0, "sure\n": 0} {
		r := &fakeRemediator{plan: connector.Plan{Action: "macos.firewall.enable"}}
		io := quietIO()
		io.In = strings.NewReader(answer)
		if err := Execute(context.Background(), target, r, Options{Apply: true, TTY: true, IO: io}, results()); err != nil {
			t.Fatalf("%q: %v", answer, err)
		}
		if r.applied != want {
			t.Errorf("answer %q applied %d times, want %d", answer, r.applied, want)
		}
	}
}

func TestMain(m *testing.M) {
	defaultSleep = func(time.Duration) {} // no real waiting in tests
	os.Exit(m.Run())
}

func TestVerifyAfterApply(t *testing.T) {
	r := &fakeRemediator{plan: connector.Plan{Action: "macos.firewall.enable"}}
	var slept []time.Duration
	opt := Options{Apply: true, Yes: true, IO: quietIO(), Sleep: func(d time.Duration) { slept = append(slept, d) }}
	if err := Execute(context.Background(), target, r, opt, results("other")); err != nil {
		t.Fatalf("finding gone should pass: %v", err)
	}
	if err := Execute(context.Background(), target, r, opt, results("other", target.ID)); !errors.Is(err, ErrStillPresent) {
		t.Fatalf("finding still there: want ErrStillPresent, got %v", err)
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
	if err := Execute(context.Background(), target, r, opt, flapping); !errors.Is(err, ErrStillPresent) {
		t.Fatalf("a finding that comes back on a later check is not fixed: got %v", err)
	}
	failed := func(context.Context) ([]*run.Result, error) {
		return []*run.Result{{Name: "macos", Err: errors.New("could not start")}}, nil
	}
	if err := Execute(context.Background(), target, r, opt, failed); err == nil || errors.Is(err, ErrStillPresent) {
		t.Fatalf("a check that could not run must not count as fixed: %v", err)
	}
}

func TestForPicksCoreFileActionsAndRefusesManualFindings(t *testing.T) {
	if _, err := For(finding.Finding{ID: "x", Remediation: finding.Remediation{Summary: "by hand"}}, nil, nil); err == nil {
		t.Fatal("manual finding should not be remediable")
	}
	r, err := For(finding.Finding{Connector: "local-secrets", Remediation: finding.Remediation{Action: ActionChmod600}}, nil, nil)
	if _, ok := r.(Files); err != nil || !ok {
		t.Fatalf("file.chmod600 belongs to the core: %T %v", r, err)
	}
	if _, err := For(finding.Finding{Connector: "nope", Remediation: finding.Remediation{Action: "nope.fix"}}, nil, nil); err == nil {
		t.Fatal("missing connector should fail")
	}
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
		Remediation: finding.Remediation{Action: ActionChmod600}}
	fs := Files{Home: func() (string, error) { return dir, nil }}
	p, err := fs.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	want := connector.Plan{
		Action: ActionChmod600, Summary: "Make " + path + " readable and writable by its owner only.",
		Files:       []connector.FileChange{{Path: path, Mode: 0o600, Was: 0o644}},
		Undo:        []connector.Step{{Argv: []string{"/bin/chmod", "644", path}}},
		SideEffects: p.SideEffects,
	}
	if err := SamePlan(want, p); err != nil || p.NeedsSudo() {
		t.Fatalf("plan %+v", p)
	}
	if err := fs.Apply(context.Background(), f, p, quietIO()); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if _, err := fs.Plan(context.Background(), f); err == nil {
		t.Fatal("an already private file has nothing to plan")
	}
}

func TestChmod600RefusesStalePlansSymlinksAndRelativePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	_ = os.WriteFile(path, nil, 0o600)
	_ = os.Chmod(path, 0o640)
	f := finding.Finding{Evidence: map[string]any{"path": path}, Remediation: finding.Remediation{Action: ActionChmod600}}
	p, err := Files{}.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	p.Files[0].Path = filepath.Join(dir, "other")
	if err := (Files{}).Apply(context.Background(), f, p, quietIO()); err == nil {
		t.Fatal("applied an altered plan")
	}
	link := filepath.Join(dir, "link")
	_ = os.Symlink(path, link)
	for _, bad := range []string{link, "relative/key", ""} {
		g := finding.Finding{Evidence: map[string]any{"path": bad}, Remediation: finding.Remediation{Action: ActionChmod600}}
		if _, err := (Files{}).Plan(context.Background(), g); err == nil {
			t.Errorf("planned chmod on %q", bad)
		}
	}
}

func TestLatestFilesTakeEachConnectorsNewestRun(t *testing.T) {
	out := t.TempDir()
	write := func(day, name string, recs ...any) { runtest.Write(t, filepath.Join(out, day, name), recs...) }
	_ = os.MkdirAll(filepath.Join(out, "notes"), 0o700)
	_ = os.WriteFile(filepath.Join(out, "2026-12-31.jsonl"), nil, 0o600) // a file, not a run directory
	write("2026-11-01", "macos.jsonl", finding.Finding{Type: "finding", ID: "old00000"})
	write("2026-11-23", "macos.jsonl",
		finding.Status{Type: "status", Connector: "macos", State: finding.StateOK},
		finding.Finding{Type: "finding", ID: "aaaa1111", Severity: finding.SevLow, Remediation: finding.Remediation{Action: "x.y"}},
		finding.Finding{Type: "finding", ID: "aaaa2222", Severity: finding.SevHigh},
		finding.Finding{Type: "finding", ID: "bbbb3333", Severity: finding.SevHigh, Remediation: finding.Remediation{Action: "x.z"}})
	// After midnight only another connector ran: macos must still come from 2026-11-23.
	write("2026-11-24", "local-secrets.jsonl", finding.Finding{Type: "finding", ID: "cccc4444"})

	files, err := LatestFiles(out)
	if err != nil || len(files) != 2 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	all, err := Load(files)
	if err != nil || len(all) != 4 {
		t.Fatalf("loaded %d err=%v", len(all), err)
	}
	if _, err := Find(all, "old00000"); err == nil {
		t.Fatal("an older run of the same connector must be ignored")
	}
	if f, err := Find(all, "bbbb"); err != nil || f.ID != "bbbb3333" {
		t.Fatalf("unique prefix from the previous day: %v %v", f.ID, err)
	}
	if _, err := Find(all, "cccc4444"); err != nil {
		t.Fatal("today's connector must be found too")
	}
	if _, err := Find(all, "aaaa"); err == nil {
		t.Fatal("ambiguous prefix accepted")
	}
	auto := Automatable(all)
	if len(auto) != 2 || auto[0].ID != "bbbb3333" {
		t.Fatalf("automatable worst first: %+v", auto)
	}
	if _, err := LatestFiles(t.TempDir()); err == nil {
		t.Fatal("empty out dir should explain how to run an inventory")
	}
}

func TestIsTerminalRejectsDevNullAndPipes(t *testing.T) {
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if IsTerminal(null) || IsTerminal(r) {
		t.Fatal("/dev/null and pipes are not terminals")
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
	Print(&out, f, p)
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
	Print(&out, f, connector.Plan{Action: "a", Summary: "s", Commands: []connector.Step{{Argv: []string{"/bin/true"}}}})
	if !strings.Contains(out.String(), "\nRuns, as you:\n  /bin/true\n") || strings.Contains(out.String(), "Undo") {
		t.Fatalf("plan without sudo or undo printed:\n%s", out.String())
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
