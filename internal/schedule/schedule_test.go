package schedule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/proc/proctest"
)

// fakeRunner records every command. launchctl print succeeds when loaded is set; the segurata
// inventory writes the findings in inventory to the --out directory, as a finished run.
type fakeRunner struct {
	calls     [][]string
	loaded    bool
	fail      map[string]error // by first argument
	inventory []finding.Finding
	exe       string
	deadlines map[string]time.Time // by first argument, of the commands that had one
}

func (r *fakeRunner) Run(ctx context.Context, name string, args []string, _, _ io.Writer) error {
	r.calls = append(r.calls, append([]string{name}, args...))
	if d, ok := ctx.Deadline(); ok {
		if r.deadlines == nil {
			r.deadlines = map[string]time.Time{}
		}
		r.deadlines[args[0]] = d
	}
	if err := r.fail[args[0]]; err != nil {
		return err
	}
	switch {
	case name == launchctl && args[0] == "print" && !r.loaded:
		return errors.New("Could not find service")
	case name == launchctl && args[0] == "bootstrap":
		r.loaded = true
	case name == launchctl && args[0] == "bootout":
		r.loaded = false
	case name == r.exe && args[0] == "inventory":
		dir := filepath.Join(args[2], "2026-11-24")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		var buf bytes.Buffer
		for _, f := range r.inventory {
			f.Type = "finding"
			_ = json.NewEncoder(&buf).Encode(f)
		}
		buf.WriteString(`{"type":"run_end","connector":"macos","complete":true}` + "\n")
		return os.WriteFile(filepath.Join(dir, "macos.jsonl"), buf.Bytes(), 0o600)
	}
	return nil
}

func (r *fakeRunner) ran(name, first string) [][]string {
	var out [][]string
	for _, c := range r.calls {
		if c[0] == name && c[1] == first {
			out = append(out, c)
		}
	}
	return out
}

type desc connector.Description

func (d desc) Describe() connector.Description { return connector.Description(d) }
func (desc) Inventory(context.Context, connector.Request, connector.Emitter) error {
	return nil
}

func testEnv(t *testing.T, goos string) (Env, *fakeRunner, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	exe := filepath.Join(home, "bin", "segurata")
	r := &fakeRunner{exe: exe}
	out := &bytes.Buffer{}
	return Env{
		GOOS: goos, Home: home, UID: 501, Exe: exe, Path: "/opt/homebrew/bin:/usr/bin:/bin", TmpDir: filepath.Join(home, "tmp"),
		Runner: r, IO: connector.IO{In: strings.NewReader(""), Out: out, Err: &bytes.Buffer{}}, TTY: false,
		Now: func() time.Time { return time.Date(2026, 11, 24, 3, 0, 0, 0, time.UTC) },
		Connectors: []connector.Connector{
			desc{Name: "macos"}, desc{Name: "google-personal", Needs: []string{"cdp"}},
			desc{Name: "connected-apps", Needs: []string{"cdp", "cli:gh"}}, desc{Name: "hibp", Needs: []string{"secret:HIBP_API_KEY"}},
		},
	}, r, out
}

func TestInstallDryRunPrintsThePlistAndCommandAndChangesNothing(t *testing.T) {
	env, r, out := testEnv(t, "darwin")
	if err := env.Install(context.Background(), Options{Connectors: []string{"macos", "local-secrets"}}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{
		"<string>com.segurata.inventory</string>",
		"<string>" + env.Exe + "</string>\n\t\t<string>schedule</string>\n\t\t<string>run</string>\n\t\t<string>--connectors</string>\n\t\t<string>macos,local-secrets</string>",
		"<integer>86400</integer>",
		"<false/>",
		filepath.Join(env.Home, ".segurata"),
		filepath.Join(env.Home, "Library/Logs/segurata/inventory.log"),
		"<string>/opt/homebrew/bin:/usr/bin:/bin</string>",
		"/bin/launchctl bootstrap gui/501 " + filepath.Join(env.Home, "Library/LaunchAgents/com.segurata.inventory.plist"),
		"Dry run",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	if _, err := os.Stat(env.Paths().Plist); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run wrote the plist")
	}
	if len(r.ran(launchctl, "bootstrap")) != 0 {
		t.Fatal("dry run loaded the agent")
	}
}

func TestInstallApplyNeedsATerminalOrYes(t *testing.T) {
	env, r, _ := testEnv(t, "darwin")
	if err := env.Install(context.Background(), Options{Apply: true}); err == nil {
		t.Fatal("applied without a terminal")
	}
	env.TTY, env.IO.In = true, strings.NewReader("n\n")
	if err := env.Install(context.Background(), Options{Apply: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(env.Paths().Plist); err == nil || len(r.ran(launchctl, "bootstrap")) != 0 {
		t.Fatal("installed after a no")
	}
}

func TestInstallApplyWritesLoadsAndReplaces(t *testing.T) {
	env, r, _ := testEnv(t, "darwin")
	env.TTY, env.IO.In = true, strings.NewReader("y\n")
	if err := env.Install(context.Background(), Options{Apply: true, Every: 6 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	p := env.Paths()
	raw, err := os.ReadFile(p.Plist)
	if err != nil || !strings.Contains(string(raw), "<integer>21600</integer>") {
		t.Fatalf("plist %s, %v", raw, err)
	}
	if st, _ := os.Stat(p.Plist); st.Mode().Perm() != 0o644 {
		t.Fatalf("plist mode %v", st.Mode().Perm())
	}
	for _, dir := range []string{p.Logs, p.State} {
		if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", dir, st, err)
		}
	}
	if got := r.ran(launchctl, "bootstrap"); len(got) != 1 || !slices.Equal(got[0], []string{launchctl, "bootstrap", "gui/501", p.Plist}) {
		t.Fatalf("bootstrap calls %v", got)
	}
	if len(r.ran(launchctl, "bootout")) != 0 {
		t.Fatal("booted out an agent that was not loaded")
	}
	// Installing again replaces the loaded agent.
	if err := env.Install(context.Background(), Options{Apply: true, Yes: true}); err != nil {
		t.Fatal(err)
	}
	if got := r.ran(launchctl, "bootout"); len(got) != 1 || got[0][2] != "gui/501/com.segurata.inventory" {
		t.Fatalf("bootout calls %v", got)
	}
	if raw, _ := os.ReadFile(p.Plist); !strings.Contains(string(raw), "<integer>86400</integer>") {
		t.Fatal("plist not replaced")
	}
}

func TestInstallRefusesABinaryThatWillNotStay(t *testing.T) {
	env, _, _ := testEnv(t, "darwin")
	env.Exe = filepath.Join(env.TmpDir, "go-build123", "exe", "segurata")
	if err := env.Install(context.Background(), Options{}); err == nil || !strings.Contains(err.Error(), "go run") {
		t.Fatalf("want refusal, got %v", err)
	}
	if err := env.Install(context.Background(), Options{Every: time.Minute}); err == nil {
		t.Fatal("an interval under an hour must be refused")
	}
}

func TestUninstall(t *testing.T) {
	env, r, out := testEnv(t, "darwin")
	if err := env.Uninstall(context.Background(), Options{Apply: true, Yes: true}); err != nil || !strings.Contains(out.String(), "No segurata agent") {
		t.Fatalf("nothing installed: %v %s", err, out)
	}
	if err := env.Install(context.Background(), Options{Apply: true, Yes: true}); err != nil {
		t.Fatal(err)
	}
	if err := env.Uninstall(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(env.Paths().Plist); err != nil || len(r.ran(launchctl, "bootout")) != 0 {
		t.Fatal("dry run uninstalled")
	}
	if err := env.Uninstall(context.Background(), Options{Apply: true, Yes: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(env.Paths().Plist); !errors.Is(err, os.ErrNotExist) || len(r.ran(launchctl, "bootout")) != 1 || r.loaded {
		t.Fatal("not uninstalled")
	}
}

func TestStatus(t *testing.T) {
	env, _, out := testEnv(t, "darwin")
	_ = env.Status(context.Background())
	if !strings.Contains(out.String(), "not installed, not loaded") || !strings.Contains(out.String(), "none yet") {
		t.Fatal(out.String())
	}
	out.Reset()
	_ = env.Install(context.Background(), Options{Apply: true, Yes: true})
	_ = os.WriteFile(env.Paths().Report, []byte("# r"), 0o600)
	out.Reset()
	_ = env.Status(context.Background())
	if !strings.Contains(out.String(), "installed, loaded") || !strings.Contains(out.String(), "written 20") {
		t.Fatal(out.String())
	}
}

func TestLinuxPrintsSystemdUnitsAndNeverApplies(t *testing.T) {
	env, r, out := testEnv(t, "linux")
	if err := env.Install(context.Background(), Options{Connectors: []string{"local-secrets"}}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{
		"segurata-inventory.service", "Type=oneshot", "ExecStart=" + env.Exe + " schedule run --connectors local-secrets",
		"OnUnitActiveSec=86400s", "WantedBy=timers.target", "systemctl --user enable --now segurata-inventory.timer",
		"Environment=PATH=/opt/homebrew/bin:/usr/bin:/bin",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	if err := env.Install(context.Background(), Options{Apply: true, Yes: true}); !errors.Is(err, ErrDarwinOnly) {
		t.Fatalf("want ErrDarwinOnly, got %v", err)
	}
	if err := env.Uninstall(context.Background(), Options{Apply: true, Yes: true}); !errors.Is(err, ErrDarwinOnly) {
		t.Fatalf("want ErrDarwinOnly, got %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("ran %v on Linux", r.calls)
	}
}

func TestDefaultConnectorsLeaveOutTheBrowser(t *testing.T) {
	env, _, _ := testEnv(t, "darwin")
	if got := env.DefaultConnectors(); !slices.Equal(got, []string{"hibp", "macos"}) {
		t.Fatalf("got %v", got)
	}
}

func high(id, title string) finding.Finding {
	return finding.Finding{ID: id, Connector: "macos", Severity: finding.SevHigh, Title: title}
}

func TestRunNotifiesOnlyNewHighOrCriticalFindings(t *testing.T) {
	env, r, out := testEnv(t, "darwin")
	accepted := high("acc", "Brave debugging port")
	accepted.Accepted = &finding.Acceptance{Reason: "agents"}
	r.inventory = []finding.Finding{high("a", "Firewall is off"), accepted,
		{ID: "m", Connector: "macos", Severity: finding.SevMedium, Title: "medium one"}}
	if err := env.Run(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	p := env.Paths()
	inv := r.ran(env.Exe, "inventory")
	if len(inv) != 1 || !slices.Equal(inv[0], []string{env.Exe, "inventory", "--out", p.Out, "hibp", "macos"}) {
		t.Fatalf("inventory calls %v", inv)
	}
	rep := r.ran(env.Exe, "report")
	if len(rep) != 1 || !slices.Equal(rep[0], []string{env.Exe, "report", "--format", "md", "--out", p.Report, "--dir", p.Out}) {
		t.Fatalf("report calls %v", rep)
	}
	notes := r.ran(osascript, "-e")
	if len(notes) != 1 || notes[0][2] != `display notification "Firewall is off" with title "segurata" subtitle "1 new high finding"` {
		t.Fatalf("notifications %v", notes)
	}
	if !strings.Contains(out.String(), "1 new high or critical findings") {
		t.Fatal(out.String())
	}

	// Same findings next time: nothing new. A new critical one: notified.
	if err := env.Run(context.Background(), Options{Connectors: []string{"macos"}}); err != nil {
		t.Fatal(err)
	}
	if len(r.ran(osascript, "-e")) != 1 {
		t.Fatal("notified again about known findings")
	}
	r.inventory = append(r.inventory, finding.Finding{ID: "c", Connector: "macos", Severity: finding.SevCritical, Title: `Share "Public" open to guests`})
	if err := env.Run(context.Background(), Options{Connectors: []string{"macos"}}); err != nil {
		t.Fatal(err)
	}
	notes = r.ran(osascript, "-e")
	if len(notes) != 2 || !strings.Contains(notes[1][2], `"Share \"Public\" open to guests"`) {
		t.Fatalf("notifications %v", notes)
	}
}

func TestRunOnLinuxLogsInsteadOfNotifying(t *testing.T) {
	env, r, out := testEnv(t, "linux")
	r.inventory = []finding.Finding{high("a", "Something bad")}
	if err := env.Run(context.Background(), Options{Connectors: []string{"local-secrets"}}); err != nil {
		t.Fatal(err)
	}
	if len(r.ran(osascript, "-e")) != 0 || !strings.Contains(out.String(), "Something bad") {
		t.Fatalf("calls %v out %s", r.calls, out)
	}
}

// A torn file from the previous run must not stop the run that writes the file replacing it: the
// "before" snapshot is best-effort.
func TestRunScansEvenWhenThePreviousRunIsUnreadable(t *testing.T) {
	env, r, out := testEnv(t, "darwin")
	dir := filepath.Join(env.Paths().Out, "2026-11-23")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	torn := "{\"type\":\"finding\",\"id\n{\"type\":\"run_end\",\"connector\":\"macos\"}\n"
	if err := os.WriteFile(filepath.Join(dir, "macos.jsonl"), []byte(torn), 0o600); err != nil {
		t.Fatal(err)
	}
	r.inventory = []finding.Finding{high("a", "Firewall is off")}
	if err := env.Run(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	if len(r.ran(env.Exe, "inventory")) != 1 || len(r.ran(env.Exe, "report")) != 1 {
		t.Fatalf("calls %v", r.calls)
	}
	if errs := env.IO.Err.(*bytes.Buffer).String(); !strings.Contains(errs, "macos.jsonl") {
		t.Errorf("no warning about the unreadable run: %q (out %s)", errs, out)
	}
}

// A scheduled run ends before the next one is due, and its inventory early enough to leave time
// for the report: launchd starts no run while one is still going, so a hung one would stop
// scheduled scanning for good. The interval reaches the run through the agent's command line.
func TestRunEndsBeforeTheNextIsDue(t *testing.T) {
	env, r, _ := testEnv(t, "darwin")
	every := 10 * time.Hour
	if args := env.runArgs(Options{Every: every}); !slices.Equal(args, []string{env.Exe, "schedule", "run", "--every", "10h0m0s"}) {
		t.Fatalf("agent command %v", args)
	}
	if args := env.runArgs(Options{Every: DefaultEvery}); slices.Contains(args, "--every") {
		t.Fatalf("the default interval is not spelled out: %v", args)
	}
	start := time.Now()
	if err := env.Run(context.Background(), Options{Every: every}); err != nil {
		t.Fatal(err)
	}
	inv, rep := r.deadlines["inventory"], r.deadlines["report"]
	if inv.IsZero() || rep.IsZero() || !inv.Before(rep) || rep.After(start.Add(every)) || inv.Before(start.Add(every/2)) {
		t.Fatalf("deadlines: inventory %v, report %v, run started %v", inv, rep, start)
	}
}

// At its deadline a command is asked to stop (an inventory then writes run_end and syncs), and
// killed if it has not after the grace period.
func TestSystemInterruptsThenKills(t *testing.T) {
	defer func(g time.Duration) { stopGrace = g }(stopGrace)
	stopGrace = 200 * time.Millisecond
	mark := filepath.Join(t.TempDir(), "stopped")
	polite := proctest.Hung(t, "polite", "trap 'echo stopped > "+mark+"; exit 0' INT\nsleep 60 &\nwait")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = System{}.Run(ctx, polite, nil, io.Discard, io.Discard)
	if _, err := os.Stat(mark); err != nil {
		t.Fatal("the command was not interrupted first")
	}
	start := time.Now()
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := (System{}).Run(ctx, proctest.Hung(t, "stubborn", ""), nil, io.Discard, io.Discard); err == nil {
		t.Fatal("a hung command succeeded")
	}
	if took := time.Since(start); took > stopGrace+5*time.Second {
		t.Fatalf("took %s", took)
	}
}

// A scheduled run that finished prunes run files past the retention; without one it keeps all.
func TestRunPrunesOldRunsAfterAFinishedRun(t *testing.T) {
	env, r, _ := testEnv(t, "darwin")
	r.inventory = []finding.Finding{high("a", "Firewall is off")}
	old := filepath.Join(env.Paths().Out, "2026-01-01", "macos.jsonl")
	prev := filepath.Join(env.Paths().Out, "2026-01-02", "macos.jsonl") // kept: the run before today's
	for _, p := range []string{old, prev} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(`{"type":"run_end","connector":"macos"}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := env.Run(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("pruned without a retention: %v", err)
	}
	env.Keep = 30 * 24 * time.Hour
	if err := env.Run(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("not pruned: %v", err)
	}
	if _, err := os.Stat(prev); err != nil {
		t.Fatalf("pruned the previous run: %v", err)
	}
}

func TestRunStopsWhenInventoryFailsAndReportsAReportFailure(t *testing.T) {
	env, r, _ := testEnv(t, "darwin")
	r.fail = map[string]error{"inventory": errors.New("exit 1")}
	if err := env.Run(context.Background(), Options{}); err == nil || len(r.ran(env.Exe, "report")) != 0 {
		t.Fatalf("err %v calls %v", err, r.calls)
	}
	r.fail = map[string]error{"report": errors.New("exit 2")}
	if err := env.Run(context.Background(), Options{}); err == nil || !strings.Contains(err.Error(), "report") {
		t.Fatalf("err %v", err)
	}
}

func TestNotificationNamesAtMostThreeTitles(t *testing.T) {
	var fs []finding.Finding
	for _, id := range []string{"1", "2", "3", "4", "5"} {
		fs = append(fs, high(id, "t"+id+"\nline"))
	}
	got := notification(fs)
	want := `display notification "t1 line; t2 line; t3 line; and 2 more" with title "segurata" subtitle "5 new high or critical findings"`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestUnitFilesQuoteWhatTheyEmbed(t *testing.T) {
	env, _, _ := testEnv(t, "darwin")
	env.Exe, env.Path = "/Users/a b/bin/segurata", "/x&y:/<z>"
	plist, err := env.Plist(Options{})
	if err != nil || !strings.Contains(plist, "<string>/x&amp;y:/&lt;z&gt;</string>") {
		t.Fatalf("plist not escaped: %v\n%s", err, plist)
	}
	svc, _, err := env.SystemdUnits(Options{})
	if err != nil || !strings.Contains(svc, `ExecStart="/Users/a b/bin/segurata" schedule run`) {
		t.Fatalf("unit not quoted: %v\n%s", err, svc)
	}
	if got := systemdQuote(`50%$"`); got != `"50%%$$\""` {
		t.Fatalf("got %s", got)
	}
}
