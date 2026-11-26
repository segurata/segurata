package schedule

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/segurata/segurata/internal/fileacl/fileacltest"
	"github.com/segurata/segurata/internal/finding"
)

func windowsEnv(t *testing.T) (Env, *fakeRunner) {
	t.Helper()
	env, r, _ := testEnv(t, "windows")
	env.Exe = filepath.Join(env.Home, "Program Files", "segurata", "segurata.exe")
	r.exe = env.Exe
	return env, r
}

func TestTaskXMLMatchesTheGoldenTask(t *testing.T) {
	env, _ := windowsEnv(t)
	env.Now = func() time.Time { return time.Date(2026, 11, 24, 3, 0, 0, 0, time.UTC) }
	got, err := env.TaskXML(Options{Every: 6 * time.Hour, Connectors: []string{"local-secrets", "github"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "task.xml"))
	if err != nil {
		t.Fatal(err)
	}
	p := env.Paths()
	want := strings.NewReplacer(
		"{{CONHOST}}", xmlText(windowsArg(env.Conhost)), "{{EXE}}", xmlText(windowsArg(env.Exe)), "{{LOG}}", xmlText(windowsArg(p.logFile())), "{{STATE}}", xmlText(p.State),
	).Replace(string(raw))
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestTaskXMLRefusesWhatTaskSchedulerWouldChange(t *testing.T) {
	env, _ := windowsEnv(t)
	for name, o := range map[string]Options{
		"percent":    {Connectors: []string{"%USERPROFILE%"}},
		"line break": {Connectors: []string{"a\nb"}},
		"too long":   {Every: 32 * 24 * time.Hour},
		"too short":  {Every: time.Minute},
	} {
		if _, err := env.TaskXML(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	env.Conhost = ""
	if _, err := env.TaskXML(Options{}); err == nil {
		t.Error("a task that would open a console window")
	}
	env.Conhost, env.UserSID = testConhost, ""
	if _, err := env.TaskXML(Options{}); err == nil {
		t.Error("a task with no account")
	}
}

func TestWindowsInstallDryRunPrintsTheTaskAndChangesNothing(t *testing.T) {
	env, r := windowsEnv(t)
	if err := env.Install(context.Background(), Options{Connectors: []string{"local-secrets"}}); err != nil {
		t.Fatal(err)
	}
	p := env.Paths()
	s := env.IO.Out.(interface{ String() string }).String()
	for _, want := range []string{
		"Task     " + p.Task,
		"Logs     " + filepath.Join(env.Home, "AppData", "Local", "segurata", "Logs"),
		"<UserId>" + testSID + "</UserId>",
		"<LogonType>InteractiveToken</LogonType>",
		"<Interval>P1D</Interval>",
		"write " + p.Task + " (private)",
		testSchTasks + ` /Create /TN segurata\inventory /XML ` + p.Task + " /F",
		"Dry run: nothing was changed. Run again with --apply to install this task.",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	if _, err := os.Stat(p.Task); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run wrote the task")
	}
	if len(r.ran(testSchTasks, "/Create")) != 0 || strings.Contains(s, launchctl) {
		t.Fatalf("calls %v", r.calls)
	}
}

func TestWindowsInstallRegistersAPrivateUTF16TaskAndReplacesIt(t *testing.T) {
	env, r := windowsEnv(t)
	ctx := context.Background()
	if err := env.Install(ctx, Options{Apply: true, Yes: true, Every: 12 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	p := env.Paths()
	raw, err := os.ReadFile(p.Task)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 2 || raw[0] != 0xFF || raw[1] != 0xFE || len(raw)%2 != 0 {
		t.Fatalf("not UTF-16LE with a BOM: % x", raw[:min(len(raw), 8)])
	}
	units := make([]uint16, 0, len(raw)/2-1)
	for i := 2; i < len(raw); i += 2 {
		units = append(units, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	if text := string(utf16.Decode(units)); !strings.HasPrefix(text, `<?xml version="1.0" encoding="UTF-16"?>`) ||
		!strings.Contains(text, "<Interval>PT12H</Interval>") {
		t.Fatalf("task:\n%s", text)
	}
	fileacltest.AssertPrivate(t, p.Task)
	for _, dir := range []string{p.Logs, p.State} {
		fileacltest.AssertPrivateDir(t, dir)
	}
	want := []string{testSchTasks, "/Create", "/TN", `segurata\inventory`, "/XML", p.Task, "/F"}
	if got := r.ran(testSchTasks, "/Create"); len(got) != 1 || !slices.Equal(got[0], want) {
		t.Fatalf("create calls %v", got)
	}
	// Installing again replaces the registered task in place: /F, no /Delete first.
	if err := env.Install(ctx, Options{Apply: true, Yes: true}); err != nil {
		t.Fatal(err)
	}
	if len(r.ran(testSchTasks, "/Create")) != 2 || len(r.ran(testSchTasks, "/Delete")) != 0 {
		t.Fatalf("calls %v", r.calls)
	}
	if !strings.Contains(env.IO.Out.(interface{ String() string }).String(), "(the task is registered now; it is replaced)") {
		t.Fatal("the dry run did not say the task is replaced")
	}
}

func TestWindowsUninstallAndStatus(t *testing.T) {
	env, r := windowsEnv(t)
	ctx := context.Background()
	out := env.IO.Out.(interface {
		String() string
		Reset()
	})
	if err := env.Uninstall(ctx, Options{Apply: true, Yes: true}); err != nil || !strings.Contains(out.String(), "No segurata task") {
		t.Fatalf("nothing installed: %v %s", err, out)
	}
	_ = env.Status(ctx)
	if !strings.Contains(out.String(), "not installed, not registered") || len(r.ran(testSchTasks, "/Query")) != 2 {
		t.Fatalf("status %s calls %v", out, r.calls)
	}
	if err := env.Install(ctx, Options{Apply: true, Yes: true}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	_ = env.Status(ctx)
	if !strings.Contains(out.String(), "installed, registered") {
		t.Fatal(out.String())
	}
	if q := r.ran(testSchTasks, "/Query"); !slices.Equal(q[len(q)-1], []string{testSchTasks, "/Query", "/TN", `segurata\inventory`, "/V", "/FO", "LIST"}) {
		t.Fatalf("query calls %v", q)
	}
	if err := env.Uninstall(ctx, Options{Apply: true, Yes: true}); err != nil {
		t.Fatal(err)
	}
	if got := r.ran(testSchTasks, "/Delete"); len(got) != 1 || !slices.Equal(got[0], []string{testSchTasks, "/Delete", "/TN", `segurata\inventory`, "/F"}) {
		t.Fatalf("delete calls %v", got)
	}
	if _, err := os.Stat(env.Paths().Task); !errors.Is(err, os.ErrNotExist) || r.loaded {
		t.Fatal("not uninstalled")
	}
}

func TestWindowsRunLogsInsteadOfNotifying(t *testing.T) {
	env, r := windowsEnv(t)
	r.inventory = []finding.Finding{high("a", "Something bad")}
	if err := env.Run(context.Background(), Options{Connectors: []string{"local-secrets"}}); err != nil {
		t.Fatal(err)
	}
	if len(r.ran(osascript, "-e")) != 0 || !strings.Contains(env.IO.Out.(interface{ String() string }).String(), "Something bad") {
		t.Fatalf("calls %v", r.calls)
	}
	if args := env.runArgs(Options{}); !slices.Equal(args[len(args)-2:], []string{"--log", filepath.Join(env.LocalAppData, "segurata", "Logs", "schedule.log")}) {
		t.Fatalf("the task's run writes no log: %v", args)
	}
}

func TestWindowsRefusesABinaryUnderTheTempDirWhateverTheCase(t *testing.T) {
	env, _ := windowsEnv(t)
	env.Exe = filepath.Join(strings.ToUpper(env.TmpDir), "go-build1", "segurata.exe")
	if err := env.Install(context.Background(), Options{}); err == nil || !strings.Contains(err.Error(), "go run") {
		t.Fatalf("want refusal, got %v", err)
	}
}

func TestWindowsArgQuotesAsCommandLineToArgvReads(t *testing.T) {
	for in, want := range map[string]string{
		"":                          `""`,
		"plain":                     "plain",
		`C:\Users\u\bin\x.exe`:      `C:\Users\u\bin\x.exe`,
		`C:\Program Files\x.exe`:    `"C:\Program Files\x.exe"`,
		`a"b`:                       `a\"b`,
		`a\"b`:                      `a\\\"b`,
		`C:\dir with space\`:        `"C:\dir with space\\"`,
		"tab\there":                 "\"tab\there\"",
		`say "hi" \\ now`:           `"say \"hi\" \\ now"`,
		`trailing\\ space \\`:       `"trailing\\ space \\\\"`,
		`no space but trailing \\`:  `"no space but trailing \\\\"`,
		`C:\a\b\`:                   `C:\a\b\`,
		`quote at end"`:             `"quote at end\""`,
		`\\server\share\segurata x`: `"\\server\share\segurata x"`,
	} {
		if got := windowsArg(in); got != want {
			t.Errorf("windowsArg(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestISODuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Hour:                       "PT1H",
		90 * time.Minute:                "PT1H30M",
		24 * time.Hour:                  "P1D",
		36*time.Hour + time.Second:      "P1DT12H1S",
		22*time.Hour + 48*time.Minute:   "PT22H48M",
		0:                               "PT0S",
		31 * 24 * time.Hour:             "P31D",
		time.Hour + 59*time.Minute + 59: "PT1H59M",
	} {
		if got := isoDuration(d); got != want {
			t.Errorf("isoDuration(%s) = %s, want %s", d, got, want)
		}
	}
}

func TestOpenLogAppendsPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Logs", "schedule.log")
	for _, line := range []string{"one\n", "two\n"} {
		f, err := OpenLog(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(line); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	if raw, _ := os.ReadFile(path); string(raw) != "one\ntwo\n" {
		t.Fatalf("log %q", raw)
	}
	fileacltest.AssertPrivate(t, path)
	fileacltest.AssertPrivateDir(t, filepath.Dir(path))
	fileacltest.Expose(t, path)
	f, err := OpenLog(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	fileacltest.AssertPrivate(t, path)
}
