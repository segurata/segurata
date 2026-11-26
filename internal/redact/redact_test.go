package redact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/localsecrets"
	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/fileacl/fileacltest"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/proc/proctest"
	"github.com/segurata/segurata/internal/prompt"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/testcorpus"
	"github.com/segurata/segurata/internal/tracker"
)

// Every secret here is generated at run time from a fixed seed: no real or real-looking literal
// sits in the source.

var rng = rand.New(rand.NewPCG(3, 5))

func fake(prefix string, n int) string { return testcorpus.Fake(rng, prefix, n, testcorpus.Alnum) }

type fixture struct {
	t       testing.TB
	home    string
	key     fingerprint.Key
	conn    *localsecrets.Connector
	state   string
	secrets map[string]string // name -> value
	open    []string          // files the fake lsof reports open
	lsofErr error
	old     time.Time
	during  func() // runs when lsof is asked, mid-run: another command at work meanwhile
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("ripgrep not installed")
	}
	home := t.TempDir()
	keyPath := filepath.Join(home, ".config", "segurata", "fingerprint.key")
	key, err := fingerprint.Load(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	conn := localsecrets.New()
	conn.Home = func() (string, error) { return home, nil }
	conn.KeyPath = func(string) string { return keyPath }
	fx := &fixture{t: t, home: home, key: key, conn: conn, state: filepath.Join(home, ".segurata", "tracker.json"),
		secrets: map[string]string{}, old: time.Now().Add(-3 * time.Hour).Truncate(time.Second)}
	return fx
}

func (fx *fixture) secret(name, value string) string {
	fx.secrets[name] = value
	return value
}

// write creates a file under home, old enough to be redacted.
func (fx *fixture) write(rel, content string, mode os.FileMode) string {
	fx.t.Helper()
	p := filepath.Join(fx.home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		fx.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		fx.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		fx.t.Fatal(err)
	}
	if err := os.Chtimes(p, fx.old, fx.old); err != nil {
		fx.t.Fatal(err)
	}
	return p
}

func (fx *fixture) cli(in string, tty bool) (CLI, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return CLI{Out: &out, Err: &errb, In: strings.NewReader(in), TTY: tty,
		Trails: func(ctx context.Context) (*localsecrets.Trails, error) { return fx.conn.Trails(ctx, nil) },
		Lsof: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "lsof" || strings.Join(args, " ") != "-Fn -c claude -c codex" {
				fx.t.Errorf("lsof called as %s %v", name, args)
			}
			if fx.during != nil {
				fx.during()
			}
			var b strings.Builder
			b.WriteString("p123\n")
			for _, f := range fx.open {
				b.WriteString("n" + f + "\n")
			}
			return []byte(b.String()), fx.lsofErr
		},
		Paths: tracker.Paths{Tracker: fx.state}, Now: time.Now}, &out, &errb
}

// run executes the command and checks that no planted secret appears in its output.
func (fx *fixture) run(in string, tty bool, args ...string) (int, string) {
	fx.t.Helper()
	c, out, errb := fx.cli(in, tty)
	code := c.Run(context.Background(), args)
	all := out.String() + errb.String()
	for name, v := range fx.secrets {
		if strings.Contains(all, v) {
			fx.t.Errorf("output shows the %s secret", name)
		}
	}
	return code, all
}

func (fx *fixture) read(p string) string {
	fx.t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		fx.t.Fatal(err)
	}
	return string(raw)
}

func (fx *fixture) tag(typ, name string) string {
	return "[REDACTED:" + typ + ":" + fx.key.Of(fx.secrets[name])[:8] + "]"
}

// transcript is a Claude Code style session, keys in non-alphabetical order: a plain secret, one
// next to escapes, an escaped private key, and JSON embedded in a string value.
func (fx *fixture) transcript() string {
	ant := fx.secret("anthropic", fake("sk-ant-api03-", 60))
	gh := fx.secret("github", fake("ghp_", 36))
	pem, body := testcorpus.PEM("RSA", testcorpus.Bytes(rng, 400))
	fx.secret("pem", body)
	cs := fx.secret("client-secret", fake("", 24))
	q := func(s string) string {
		enc, err := encodeString(s)
		if err != nil {
			fx.t.Fatal(err)
		}
		return enc
	}
	lines := []string{
		`{"uuid":"1","type":"user","message":{"role":"user","content":` + q("use "+ant+" please") + `}}`,
		`{"uuid":"2","type":"assistant","message":{"content":` + q("export GH=\""+gh+"\"\n\ttab <b>&amp;</b>") + `}}`,
		`{"uuid":"3","type":"tool_result","content":` + q("key:\n"+pem) + `}`,
		`{"uuid":"4","type":"tool_result","content":` + q(`{"client_secret": "`+cs+`", "note": "`+ant+`"}`) + `}`,
		`{"uuid":"5","type":"summary","content":"nothing secret here"}`,
	}
	return strings.Join(lines, "\n") + "\n"
}

func TestApplyKeepsJSONLValidModeAndMtime(t *testing.T) {
	fx := newFixture(t)
	orig := fx.transcript()
	p := fx.write(".claude/projects/-src-app/session.jsonl", orig, 0o640)

	code, out := fx.run("", false, "--trails", "--apply", "--yes")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	got := fx.read(p)
	for name, v := range fx.secrets {
		if name == "pem" {
			v = v[:64] // the body is split into lines in the file
		}
		if strings.Contains(got, v) {
			t.Errorf("%s still in the transcript", name)
		}
	}
	for _, want := range []string{fx.tag("anthropic", "anthropic"), fx.tag("github", "github"),
		fx.tag("private-key", "pem"), fx.tag("oauth-client-secret", "client-secret")} {
		if want == "" || !strings.Contains(got, want) {
			t.Errorf("missing %s", want)
		}
	}
	origLines, gotLines := strings.Split(orig, "\n"), strings.Split(got, "\n")
	if len(origLines) != len(gotLines) {
		t.Fatalf("line count %d, was %d", len(gotLines), len(origLines))
	}
	for i, l := range gotLines {
		if l == "" {
			continue
		}
		if !json.Valid([]byte(l)) {
			t.Errorf("line %d is no longer valid JSON", i+1)
		}
		// Field order is kept: the keys appear in the same order as before.
		if keys(t, l) != keys(t, origLines[i]) {
			t.Errorf("line %d: keys %s, were %s", i+1, keys(t, l), keys(t, origLines[i]))
		}
	}
	if gotLines[4] != origLines[4] {
		t.Error("a line without secrets changed")
	}
	if !strings.Contains(gotLines[1], `\"\n\ttab <b>&amp;</b>`) {
		t.Errorf("escapes around the secret changed: %s", gotLines[1])
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode %o, want 640", st.Mode().Perm())
	}
	if !st.ModTime().Equal(fx.old) {
		t.Errorf("mtime %v, want %v", st.ModTime(), fx.old)
	}
	if !strings.Contains(out, "Verified: no secret in scope is left") {
		t.Errorf("no verification:\n%s", out)
	}
	if entries, _ := os.ReadDir(filepath.Dir(p)); len(entries) != 1 {
		t.Errorf("leftover files next to the transcript: %d entries", len(entries))
	}
}

// failingRG runs ripgrep until fail is set, then exits as a broken one would.
type failingRG struct {
	rg interface {
		Run(ctx context.Context, args ...string) ([]byte, error)
	}
	fail *bool
}

func (r failingRG) Run(ctx context.Context, args ...string) ([]byte, error) {
	if *r.fail {
		return nil, errors.New("rg: exit status 2")
	}
	return r.rg.Run(ctx, args...)
}

// A rescan that cannot run must not be reported as a clean one.
func TestApplyFailsWhenTheRescanCannotRun(t *testing.T) {
	fx := newFixture(t)
	fx.write(".claude/projects/-src-app/session.jsonl", fx.transcript(), 0o600)
	broken := false
	fx.conn.RG = failingRG{fx.conn.RG, &broken}
	fx.during = func() { broken = true } // after the plan's scan, before the rescan

	code, out := fx.run("", false, "--trails", "--apply", "--yes")
	if code == 0 || !strings.Contains(out, "the check could not run") || strings.Contains(out, "Verified") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

// keys lists a JSON object's top-level keys in source order.
func keys(t *testing.T, line string) string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(line))
	var ks []string
	depth := 0
	expectKey := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				depth++
				expectKey = v == '{' && depth == 1
			case '}', ']':
				depth--
			}
			continue
		case string:
			if depth == 1 && expectKey {
				ks = append(ks, v)
				expectKey = false
				continue
			}
		}
		if depth == 1 {
			expectKey = true
		}
	}
	return strings.Join(ks, ",")
}

func TestDryRunWritesNothingAndCounts(t *testing.T) {
	fx := newFixture(t)
	orig := fx.transcript()
	p := fx.write(".claude/projects/-src-app/session.jsonl", orig, 0o600)

	code, out := fx.run("", false, "--trails")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if fx.read(p) != orig {
		t.Error("a dry run changed the file")
	}
	if st, _ := os.Stat(p); !st.ModTime().Equal(fx.old) {
		t.Error("a dry run touched the mtime")
	}
	for _, want := range []string{"~/.claude/projects/-src-app/session.jsonl", "anthropic 2", "github 1", "private-key 1",
		"oauth-client-secret 1", "Total: 1 file, 5 matches of 4 distinct secrets", "Dry run: nothing was changed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(fx.state); !errors.Is(err, os.ErrNotExist) {
		t.Error("a dry run wrote the ledger")
	}
}

func TestShellHistoryKeepsZshExtendedFormat(t *testing.T) {
	fx := newFixture(t)
	key := fx.secret("openai", fake("sk-proj-", 50))
	noise := fx.secret("noise", fake("", 15)+"7")
	hist := ": 1700000000:0;ls\n: 1700000100:3;export OPENAI_API_KEY=" + key + " && run\n: 1700000200:0;MY_SECRET=" + noise + " ./x\n"
	p := fx.write(".zsh_history", hist, 0o600)

	if code, out := fx.run("", false, "--trails", "--apply", "--yes"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	want := ": 1700000000:0;ls\n: 1700000100:3;export OPENAI_API_KEY=" + fx.tag("openai-project", "openai") + " && run\n: 1700000200:0;MY_SECRET=" + noise + " ./x\n"
	if got := fx.read(p); got != want {
		t.Errorf("history rewritten wrong (noise must stay without --include-noise)")
	}

	if code, out := fx.run("", false, "--trails", "--include-noise", "--apply", "--yes"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Contains(fx.read(p), noise) {
		t.Error("--include-noise left the generic match")
	}
}

func TestRecentAndOpenFilesAreLeftAlone(t *testing.T) {
	fx := newFixture(t)
	recent := fx.write(".claude/projects/a/recent.jsonl", fx.transcript(), 0o600)
	if err := os.Chtimes(recent, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	recentBefore := fx.read(recent)
	open := fx.write(".codex/sessions/2026/open.jsonl", fx.transcript(), 0o600)
	openBefore := fx.read(open)
	done := fx.write(".claude/projects/a/old.jsonl", fx.transcript(), 0o600)
	fx.open = []string{open, "/somewhere/else"}

	code, out := fx.run("", false, "--trails", "--apply", "--yes")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if fx.read(recent) != recentBefore {
		t.Error("a file modified within --min-age was rewritten")
	}
	if fx.read(open) != openBefore {
		t.Error("a file open by an agent was rewritten")
	}
	if strings.Contains(fx.read(done), fx.secrets["anthropic"]) {
		t.Error("the old, closed file was not redacted")
	}
	for _, want := range []string{"1 file " + skipRecent, "1 file " + skipOpen, "~/.codex/sessions/2026/open.jsonl"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	// A shorter --min-age reaches the recent file.
	if code, out := fx.run("", false, "--trails", "--min-age", "0s", "--apply", "--yes"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if fx.read(recent) == recentBefore {
		t.Error("--min-age 0s left the recent file alone")
	}
}

func TestLsofFailureRefuses(t *testing.T) {
	fx := newFixture(t)
	p := fx.write(".claude/projects/a/s.jsonl", fx.transcript(), 0o600)
	before := fx.read(p)
	fx.lsofErr = errors.New("lsof: not permitted")
	if code, _ := fx.run("", false, "--trails", "--apply", "--yes"); code == 0 {
		t.Error("ran without knowing which files agents have open")
	}
	if fx.read(p) != before {
		t.Error("file rewritten")
	}
}

func TestLsofExitOneIsNoMatch(t *testing.T) {
	fx := newFixture(t)
	fx.write(".claude/projects/a/s.jsonl", fx.transcript(), 0o600)
	fx.lsofErr = exitErr(t, 1)
	if code, out := fx.run("", false, "--trails"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func exitErr(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command(proctest.Shell(t), "-c", "exit 1").Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != code {
		t.Fatalf("could not make an exit error: %v", err)
	}
	return ee
}

func TestApplyNeedsATerminalOrYes(t *testing.T) {
	fx := newFixture(t)
	p := fx.write(".claude/projects/a/s.jsonl", fx.transcript(), 0o600)
	before := fx.read(p)
	code, out := fx.run("", false, "--trails", "--apply")
	if code == 0 || !strings.Contains(out, prompt.ErrNotTTY.Error()) {
		t.Errorf("exit %d without a terminal:\n%s", code, out)
	}
	if code, _ := fx.run("n\n", true, "--trails", "--apply"); code != 0 {
		t.Errorf("declining exited %d", code)
	}
	if fx.read(p) != before {
		t.Error("rewritten without confirmation")
	}
	if code, _ := fx.run("y\n", true, "--trails", "--apply"); code != 0 {
		t.Errorf("confirming exited %d", code)
	}
	if fx.read(p) == before {
		t.Error("confirmed but not rewritten")
	}
}

func TestItemOnlyAndLedgerNote(t *testing.T) {
	fx := newFixture(t)
	a := fx.write(".claude/projects/a/s.jsonl", fx.transcript(), 0o600)
	b := fx.write("Library/Logs/app/app.log", "token "+fx.secrets["anthropic"]+" and "+fx.secrets["github"]+"\n", 0o600)
	fp := fx.key.Of(fx.secrets["anthropic"])
	l := tracker.New(time.Now())
	l.SyncSecrets([]tracker.Sighting{{Evidence: secretrisk.Evidence{Fingerprint: fp, Type: "anthropic", Redacted: "sk-ant-…(73)",
		Source: "scan", Kind: "transcript", Path: "~/.claude/projects/a/s.jsonl", Mode: "600"}}}, time.Now(), false, attribution.Owned{})
	if err := l.Save(fx.state); err != nil {
		t.Fatal(err)
	}

	fx.during = func() {
		if err := tracker.Update(fx.state, time.Now(), func(l *tracker.Tracker) error { return l.Items[0].Note(time.Now(), "saved meanwhile") }); err != nil {
			t.Fatal(err)
		}
	}
	code, out := fx.run("", false, "--item", fp[:8], "--apply", "--yes")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, p := range []string{a, b} {
		got := fx.read(p)
		if strings.Contains(got, fx.secrets["anthropic"]) {
			t.Errorf("%s still holds the item's secret", p)
		}
		if !strings.Contains(got, fx.secrets["github"]) {
			t.Errorf("%s lost a secret outside --item", p)
		}
	}
	l, err := tracker.Load(fx.state)
	if err != nil {
		t.Fatal(err)
	}
	it, err := l.FindRotate(fp[:8])
	if err != nil {
		t.Fatal(err)
	}
	h := it.History
	if len(h) == 0 || h[len(h)-1].Action != "redacted" || h[len(h)-1].Detail != "redacted from 2 trail files" {
		t.Errorf("history: %+v", h)
	}
	if h := l.Items[0].History; h[len(h)-1].Detail != "saved meanwhile" {
		t.Error("a change another command saved during the run was lost")
	}
}

func TestPathAndPriorityScope(t *testing.T) {
	fx := newFixture(t)
	gh := fx.secret("github", fake("ghp_", 36))
	ant := fx.secret("anthropic", fake("sk-ant-api03-", 60))
	in := fx.write("Library/Logs/a/x.log", gh+" "+ant+"\n", 0o600)
	out := fx.write("Library/Logs/b/y.log", gh+"\n", 0o600)

	// Logs are local exposure: GitHub (high) is P2, Anthropic (medium) P3.
	if code, msg := fx.run("", false, "--path", "~/Library/Logs/a", "--min-priority", "P2", "--apply", "--yes"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, msg)
	}
	if got := fx.read(in); strings.Contains(got, gh) || !strings.Contains(got, ant) {
		t.Error("--min-priority P2 should take the GitHub token and leave the Anthropic key")
	}
	if !strings.Contains(fx.read(out), gh) {
		t.Error("--path reached a file outside it")
	}
}

func TestWorkingFilesAreNeverTouched(t *testing.T) {
	fx := newFixture(t)
	ant := fx.secret("anthropic", fake("sk-ant-api03-", 60))
	rc := fx.write(".zshrc", "export ANTHROPIC_API_KEY="+ant+"\n", 0o600)
	env := fx.write("src/app/.env", "ANTHROPIC_API_KEY="+ant+"\n", 0o600)
	if code, out := fx.run("", false, "--path", fx.home, "--apply", "--yes"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, p := range []string{rc, env} {
		if !strings.Contains(fx.read(p), ant) {
			t.Errorf("%s is a working file and was rewritten", p)
		}
	}
}

func TestBackupIsOptInAndLoud(t *testing.T) {
	fx := newFixture(t)
	p := fx.write(".claude/projects/a/s.jsonl", fx.transcript(), 0o600)
	before := fx.read(p)
	code, out := fx.run("", false, "--trails", "--apply", "--yes", "--backup")
	if code != 0 || !strings.Contains(out, "WARNING: --backup") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	matches, _ := filepath.Glob(p + ".segurata-bak-*")
	if len(matches) != 1 || fx.read(matches[0]) != before {
		t.Fatalf("backup: %v", matches)
	}
	fileacltest.AssertPrivate(t, matches[0])
}

func TestScopeIsRequired(t *testing.T) {
	fx := newFixture(t)
	for _, args := range [][]string{{}, {"--apply"}, {"--trails", "--backup"}, {"--trails", "--yes"}, {"--trails", "--min-age", "-1s"},
		{"--trails", "--min-priority", "P7"}, {"--trails", "x"}, {"--bogus"}} {
		if code, _ := fx.run("", false, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestMissingFingerprintKeyFails(t *testing.T) {
	fx := newFixture(t)
	fx.conn.KeyPath = func(string) string { return filepath.Join(fx.home, "nope.key") }
	code, out := fx.run("", false, "--trails")
	if code != 1 || !strings.Contains(out, "inventory local-secrets") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestAFileChangedAfterThePlanIsLeftAlone(t *testing.T) {
	fx := newFixture(t)
	p := fx.write(".claude/projects/a/s.jsonl", fx.transcript(), 0o600)
	calls := 0
	fx.during = func() {
		if calls++; calls == 2 { // apply's lsof: an agent appended after the plan
			f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.WriteString(`{"uuid":"6"}` + "\n")
			f.Close()
			if err := os.Chtimes(p, fx.old, fx.old); err != nil {
				t.Fatal(err)
			}
		}
	}
	code, out := fx.run("", false, "--trails", "--apply", "--yes")
	if code != 0 || !strings.Contains(out, "Left alone: ~/.claude/projects/a/s.jsonl ("+skipChanged+")") || !strings.Contains(out, "Rewrote 0 files") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(fx.read(p), fx.secrets["anthropic"]) || !strings.HasSuffix(fx.read(p), `{"uuid":"6"}`+"\n") {
		t.Error("a file changed after the plan was rewritten")
	}
}
