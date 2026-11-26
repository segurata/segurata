package rotation

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/tracker"
)

// fakeKey is an obviously fake Anthropic-shaped key, generated at run time: no secret-looking
// literal sits in the source.
func fakeKey(t *testing.T) string {
	t.Helper()
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := []byte("sk-ant-FAKE")
	for i := 0; i < 60; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alnum))))
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, alnum[n.Int64()])
	}
	return string(b)
}

// call is one external command a test runner saw.
type call struct {
	name  string
	args  []string
	stdin string
}

// fakeOS stands in for pbpaste, pbcopy and security: a clipboard and a Keychain in memory.
type fakeOS struct {
	mu        sync.Mutex
	calls     []call
	clip      string
	items     map[string]string // Keychain service → value
	keepStale bool              // security -i "succeeds" but stores nothing
	onPaste   func()            // runs when pbpaste is called: another command at work meanwhile
}

func (f *fakeOS) run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{name, args, string(stdin)})
	switch {
	case name == pbpaste:
		if f.onPaste != nil {
			f.onPaste()
		}
		return []byte(f.clip + "\n"), nil
	case name == pbcopy:
		f.clip = string(stdin)
		return nil, nil
	case name == security && len(args) == 1 && args[0] == "-i":
		fields := strings.Fields(string(stdin))
		if len(fields) != 8 || fields[0] != "add-generic-password" || fields[1] != "-U" || fields[2] != "-a" || fields[4] != "-s" || fields[6] != "-w" {
			return nil, errors.New("unexpected security -i input")
		}
		if !f.keepStale {
			f.items[fields[5]] = fields[7]
		}
		return []byte("security> "), nil
	case name == security && len(args) == 6 && args[0] == "find-generic-password":
		v, ok := f.items[args[4]]
		if !ok {
			return nil, errors.New("security: The specified item could not be found in the keychain.")
		}
		return []byte(v + "\n"), nil
	}
	return nil, errors.New("unexpected command " + name)
}

// fixture is a temporary HOME with an rc file and a .env holding the same fake key, and a ledger
// item for it as a sync would create it.
type fixture struct {
	home, state string
	old, new    string
	zshrc, env  string
	key         fingerprint.Key
	os          *fakeOS
}

const zshrcOld = "# shell\nexport ANTHROPIC_API_KEY=\"%s\"\nalias ll='ls -l'\n"

func newReplaceFixture(t *testing.T) *fixture {
	t.Helper()
	home := t.TempDir()
	key, err := fingerprint.Load(fingerprint.DefaultPath(home))
	if err != nil {
		t.Fatal(err)
	}
	fx := &fixture{home: home, state: filepath.Join(home, "state", "tracker.json"), old: fakeKey(t), new: fakeKey(t), key: key,
		zshrc: filepath.Join(home, ".zshrc"), env: filepath.Join(home, "src", "app", ".env")}
	fx.os = &fakeOS{clip: fx.new, items: map[string]string{}}
	write(t, fx.zshrc, strings.ReplaceAll(zshrcOld, "%s", fx.old), 0o640)
	write(t, fx.env, "ANTHROPIC_API_KEY="+fx.old+"\nOTHER=1\n# copy: "+fx.old+"\n", 0o600)

	redacted := secretrisk.Redact("anthropic", "sk-ant-", fx.old)
	evs := []secretrisk.Evidence{
		{Source: "scan", Kind: "config", Type: "anthropic", Redacted: redacted, Path: "~/.zshrc", Line: 2, Mode: "640", Fingerprint: key.Of(fx.old)},
		{Source: "scan", Kind: "repo", Type: "anthropic", Redacted: redacted, Path: "~/src/app/.env", Line: 1, Mode: "600", Fingerprint: key.Of(fx.old)},
		{Source: "scan", Kind: "transcript", Type: "anthropic", Redacted: redacted, Path: "~/.claude/projects/p/s.jsonl", Line: 9, Mode: "600", Fingerprint: key.Of(fx.old)},
	}
	l := tracker.New(t0)
	var s []tracker.Sighting
	for _, e := range evs {
		s = append(s, tracker.Sighting{Evidence: e})
	}
	l.SyncSecrets(s, t0, false)
	if err := l.Save(fx.state); err != nil {
		t.Fatal(err)
	}
	return fx
}

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (fx *fixture) id() string { return fx.key.Of(fx.old)[:8] }

// run executes one rotations command with stdin, as a terminal or not.
func (fx *fixture) run(t *testing.T, stdin string, tty bool, args ...string) (string, string, int) {
	t.Helper()
	return fx.runInput(t, strings.NewReader(stdin), tty, args...)
}

func (fx *fixture) runInput(t *testing.T, stdin io.Reader, tty bool, args ...string) (string, string, int) {
	t.Helper()
	var o, e bytes.Buffer
	code := CLI{Out: &o, Err: &e, In: stdin, TTY: tty, Paths: tracker.Paths{Tracker: fx.state}, User: "tester",
		Home: func() (string, error) { return fx.home, nil }, Exec: fx.os.run, Now: func() time.Time { return t0 }}.Run(args)
	fx.noLeak(t, o.String()+e.String())
	return o.String(), e.String(), code
}

type confirmInput func()

func (f confirmInput) Read(p []byte) (int, error) {
	f()
	return copy(p, "y\n"), io.EOF
}

func TestACLReportAllowsDenyEntriesOnly(t *testing.T) {
	const report = "drwx------@ 9 501 20 288 Nov 26 12:00 /Users/example\n 0: group:everyone deny delete\n"
	if !safeACLReport([]byte(report), 1) {
		t.Fatal("a deny-only ACL should keep the directory private")
	}
	granted := strings.Replace(report, "deny delete", "allow search", 1)
	if safeACLReport([]byte(granted), 1) || safeACLReport([]byte(report), 2) {
		t.Fatal("a granting ACL or incomplete listing was accepted")
	}
}

func TestReplaceChecksGitBeforeChangingTheKeychain(t *testing.T) {
	fixture := newReplaceFixture(t)
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is unavailable")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(git, args...)
		cmd.Dir = filepath.Dir(fixture.env)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q")
	service := "ANTHROPIC_API_KEY"
	fixture.os.items[service] = fixture.old
	_, stderr, code := fixture.runInput(t, confirmInput(func() {
		run("add", "--", ".env")
		t.Setenv("GIT_INDEX_FILE", filepath.Join(fixture.home, "empty-alternate-index"))
	}), true, "replace", fixture.id(), "--apply", "--to-keychain", service)
	if code != 1 || !strings.Contains(stderr, "tracked by Git") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if fixture.os.items[service] != fixture.old ||
		!strings.Contains(read(t, fixture.env), fixture.old) || !strings.Contains(read(t, fixture.zshrc), fixture.old) {
		t.Fatal("an unsafe plan changed a destination")
	}
}

func TestReplaceKeepsAFileModeChangedDuringConfirmation(t *testing.T) {
	fixture := newReplaceFixture(t)
	_, stderr, code := fixture.runInput(t, confirmInput(func() {
		if err := os.Chmod(fixture.zshrc, 0o600); err != nil {
			t.Fatal(err)
		}
	}), true, "replace", fixture.id(), "--apply")
	if code != 1 || !strings.Contains(stderr, "changed since the plan") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	st, err := os.Stat(fixture.zshrc)
	if err != nil || st.Mode().Perm() != 0o600 || !strings.Contains(read(t, fixture.zshrc), fixture.old) {
		t.Fatal("the confirmed plan overwrote a newer mode or credential")
	}
}

// noLeak checks that neither value reached the output nor any runner argument. Only the stdin of
// `security -i` may carry the new value.
func (fx *fixture) noLeak(t *testing.T, output string) {
	t.Helper()
	for _, v := range []string{fx.old, fx.new} {
		if strings.Contains(output, v) {
			t.Fatal("a secret value reached stdout or stderr")
		}
		if data, err := os.ReadFile(fx.state); err == nil && strings.Contains(string(data), v) {
			t.Fatal("a secret value reached the ledger")
		}
		for _, c := range fx.os.calls {
			if strings.Contains(strings.Join(c.args, " "), v) {
				t.Fatalf("a secret value reached the arguments of %s", c.name)
			}
			if strings.Contains(c.stdin, v) && !(c.name == security && c.args[0] == "-i" && v == fx.new) {
				t.Fatalf("a secret value reached the stdin of %s %v", c.name, c.args)
			}
		}
	}
}

func (fx *fixture) item(t *testing.T) *tracker.Item {
	t.Helper()
	l, err := tracker.Load(fx.state)
	if err != nil {
		t.Fatal(err)
	}
	it, err := l.FindRotate(fx.id())
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func (fx *fixture) lastAction(t *testing.T) string {
	t.Helper()
	h := fx.item(t).History
	return h[len(h)-1].Action
}

func (fx *fixture) cleared() bool {
	for _, c := range fx.os.calls {
		if c.name == pbcopy {
			return true
		}
	}
	return false
}

func TestReplaceDryRunChangesNothing(t *testing.T) {
	fx := newReplaceFixture(t)
	zBefore, eBefore := read(t, fx.zshrc), read(t, fx.env)
	o, e, code := fx.run(t, "", true, "replace", fx.id())
	if code != 0 {
		t.Fatalf("dry run: %d %s", code, e)
	}
	after := secretrisk.Redact("anthropic", "sk-ant-", fx.new)
	for _, want := range []string{fx.item(t).Secret.Redacted + " → " + after, "~/.zshrc", "mode 640", "line 2:", "~/src/app/.env", "mode 600", "line 1:", "line 3:", "No backup", "Dry run"} {
		if !strings.Contains(o, want) {
			t.Errorf("plan lacks %q:\n%s", want, o)
		}
	}
	if read(t, fx.zshrc) != zBefore || read(t, fx.env) != eBefore {
		t.Error("dry run changed a file")
	}
	if fx.lastAction(t) != tracker.ActReplacePlan || fx.item(t).Status != tracker.Open {
		t.Errorf("history %v", fx.item(t).History)
	}
	if fx.cleared() {
		t.Error("dry run cleared the clipboard, which --apply needs again")
	}
}

func TestReplaceApply(t *testing.T) {
	fx := newReplaceFixture(t)
	envBefore, err := os.Stat(fx.env)
	if err != nil {
		t.Fatal(err)
	}
	o, e, code := fx.run(t, "y\n", true, "replace", fx.id(), "--apply")
	if code != 0 {
		t.Fatalf("apply: %d %s\n%s", code, e, o)
	}
	if !strings.Contains(o, "Apply? [y/N]") || !strings.Contains(o, "Clipboard cleared") {
		t.Errorf("output:\n%s", o)
	}
	if got, want := read(t, fx.zshrc), strings.ReplaceAll(zshrcOld, "%s", fx.new); got != want {
		t.Error("rc file not rewritten as planned")
	}
	if got := read(t, fx.env); got != "ANTHROPIC_API_KEY="+fx.new+"\nOTHER=1\n# copy: "+fx.new+"\n" {
		t.Error(".env not rewritten on both lines")
	}
	for path, mode := range map[string]os.FileMode{fx.zshrc: 0o640, fx.env: 0o600} {
		if st, _ := os.Stat(path); st.Mode().Perm() != mode {
			t.Errorf("%s mode %o, want %o", path, st.Mode().Perm(), mode)
		}
	}
	if envAfter, _ := os.Stat(fx.env); os.SameFile(envBefore, envAfter) {
		t.Error("file rewritten in place, not replaced atomically")
	}
	if backups, _ := filepath.Glob(filepath.Join(fx.home, "src", "app", ".env.segurata-bak-*")); len(backups) != 0 {
		t.Error("backup written without --backup")
	}
	leftovers, _ := filepath.Glob(filepath.Join(fx.home, "src", "app", ".*-*"))
	if len(leftovers) != 0 {
		t.Errorf("temporary files left: %v", leftovers)
	}
	it := fx.item(t)
	if it.Status != tracker.Done || !strings.Contains(it.History[len(it.History)-1].Detail, "replaced in ~/.zshrc, ~/src/app/.env") {
		t.Errorf("item %s %v", it.Status, it.History)
	}
	if len(it.Secret.RotatedLocations) != len(it.Secret.Locations) || len(it.Secret.RotatedLocations) == 0 {
		t.Errorf("replace did not record the locations known at rotation: %v", it.Secret.RotatedLocations)
	}
	if !fx.cleared() || fx.os.clip != "" {
		t.Error("clipboard not cleared")
	}
	if _, e, code := fx.run(t, "y\n", true, "replace", fx.id(), "--apply"); code != 1 || !strings.Contains(e, "is rotated") {
		t.Errorf("second replace of a rotated item: %d %q", code, e)
	}
}

func TestReplaceFollowsSymlinks(t *testing.T) {
	fx := newReplaceFixture(t)
	dot := filepath.Join(fx.home, "dotfiles", "zshrc")
	write(t, dot, read(t, fx.zshrc), 0o600)
	if err := os.Remove(fx.zshrc); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dot, fx.zshrc); err != nil {
		t.Fatal(err)
	}
	o, e, code := fx.run(t, "", false, "replace", fx.id(), "--apply", "--yes")
	if code != 0 {
		t.Fatalf("apply: %d %s", code, e)
	}
	target, _ := filepath.EvalSymlinks(dot)
	if !strings.Contains(o, "~/.zshrc (→ "+target+")") || strings.Contains(o, "~/src/app/.env (→") {
		t.Errorf("plan does not name the link target:\n%s", o)
	}
	if fi, err := os.Lstat(fx.zshrc); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced by a file")
	}
	if !strings.Contains(read(t, dot), fx.new) {
		t.Error("link target not updated")
	}
}

// A used_in file deleted since the scan: a new scan and sync take it out of used_in, as the
// refusal advises, and replace goes ahead with the files left.
func TestReplaceAfterAUsedInFileWasDeletedAndRescanned(t *testing.T) {
	fx := newReplaceFixture(t)
	if err := os.Remove(fx.env); err != nil {
		t.Fatal(err)
	}
	if _, e, code := fx.run(t, "", false, "replace", fx.id()); code != 1 {
		t.Fatalf("before the rescan: %d %s", code, e)
	}
	redacted := fx.item(t).Secret.Redacted
	run := filepath.Join(fx.home, "out", "local-secrets.jsonl")
	writeFindings(t, run,
		secretrisk.Evidence{Source: "scan", Kind: "config", Type: "anthropic", Redacted: redacted, Path: "~/.zshrc", Line: 2, Mode: "640", Fingerprint: fx.key.Of(fx.old)},
		secretrisk.Evidence{Source: "scan", Kind: "transcript", Type: "anthropic", Redacted: redacted, Path: "~/.claude/projects/p/s.jsonl", Line: 9, Mode: "600", Fingerprint: fx.key.Of(fx.old)})
	if _, e, code := fx.run(t, "", false, "sync", "--from", run, "--out", filepath.Join(fx.home, "none")); code != 0 {
		t.Fatalf("sync: %s", e)
	}
	if got := strings.Join(fx.item(t).Secret.UsedIn, " "); got != "~/.zshrc" {
		t.Fatalf("used_in after the rescan %q", got)
	}
	if _, e, code := fx.run(t, "", false, "replace", fx.id(), "--apply", "--yes"); code != 0 || fx.item(t).Status != tracker.Done {
		t.Fatalf("apply: %d %s", code, e)
	}
}

// The dotfiles layout: ~/.zshrc links to ~/dotfiles/zshrc and the scan found the key under both
// names. The file is planned, written and checked once, under both names, and the item is rotated.
func TestReplaceWritesAFileUsedUnderTwoNamesOnce(t *testing.T) {
	fx := newReplaceFixture(t)
	dot := filepath.Join(fx.home, "dotfiles", "zshrc")
	write(t, dot, read(t, fx.zshrc), 0o640)
	if err := os.Remove(fx.zshrc); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dot, fx.zshrc); err != nil {
		t.Fatal(err)
	}
	l, _ := tracker.Load(fx.state)
	redacted := fx.item(t).Secret.Redacted
	l.SyncSecrets([]tracker.Sighting{{Evidence: secretrisk.Evidence{Source: "scan", Kind: "config", Type: "anthropic", Redacted: redacted,
		Path: "~/dotfiles/zshrc", Line: 2, Mode: "640", Fingerprint: fx.key.Of(fx.old)}}}, t0, false)
	if err := l.Save(fx.state); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fx.item(t).Secret.UsedIn, " "); got != "~/.zshrc ~/dotfiles/zshrc ~/src/app/.env" {
		t.Fatalf("used_in %q", got)
	}
	o, e, code := fx.run(t, "", false, "replace", fx.id(), "--apply", "--yes")
	if code != 0 {
		t.Fatalf("apply: %d %s\n%s", code, e, o)
	}
	if strings.Count(o, "line 2:") != 1 || !strings.Contains(o, "Replaced in 2 files and checked") {
		t.Errorf("output:\n%s", o)
	}
	if got, want := read(t, dot), strings.ReplaceAll(zshrcOld, "%s", fx.new); got != want {
		t.Error("link target not rewritten as planned")
	}
	if it := fx.item(t); it.Status != tracker.Done || !strings.Contains(it.History[len(it.History)-1].Detail, "~/.zshrc, ~/dotfiles/zshrc, ~/src/app/.env") {
		t.Errorf("item %s %+v", it.Status, it.History[len(it.History)-1])
	}
	if !fx.cleared() {
		t.Error("clipboard not cleared")
	}
}

// replace holds its copy of the tracker across the clipboard, the confirmation and the file
// writes; another command that saves meanwhile keeps its change, and the item is still rotated.
func TestReplaceRecordsIntoTheTrackerAsItIsAfterTheWrites(t *testing.T) {
	for _, apply := range []bool{false, true} {
		fx := newReplaceFixture(t)
		fx.os.onPaste = func() {
			if err := tracker.Update(fx.state, t0, func(l *tracker.Tracker) error { return l.Items[0].Note(t0, "saved meanwhile") }); err != nil {
				t.Fatal(err)
			}
		}
		args := []string{"replace", fx.id()}
		if apply {
			args = append(args, "--apply", "--yes")
		}
		if _, e, code := fx.run(t, "", false, args...); code != 0 {
			t.Fatalf("apply %v: %d %s", apply, code, e)
		}
		l, _ := tracker.Load(fx.state)
		if h := l.Items[0].History; h[len(h)-1].Detail != "saved meanwhile" {
			t.Errorf("apply %v: the other command's note was lost", apply)
		}
		want := map[bool]string{false: tracker.ActReplacePlan, true: "done"}[apply]
		if got := fx.lastAction(t); got != want {
			t.Errorf("apply %v: last action %q", apply, got)
		}
	}
}

func TestReplaceBackupIsPrivate(t *testing.T) {
	fx := newReplaceFixture(t)
	before := read(t, fx.zshrc)
	if _, e, code := fx.run(t, "y\n", true, "replace", fx.id(), "--apply", "--backup"); code != 0 {
		t.Fatalf("apply: %s", e)
	}
	backups, _ := filepath.Glob(fx.zshrc + ".segurata-bak-*")
	if len(backups) != 1 {
		t.Fatalf("backups %v", backups)
	}
	if st, _ := os.Stat(backups[0]); st.Mode().Perm() != 0o600 || read(t, backups[0]) != before {
		t.Errorf("backup mode %o or content differs", st.Mode().Perm())
	}
}

func TestReplaceRefusals(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, fx *fixture)
		stdin   string
		tty     bool
		args    []string
		wantErr string
	}{
		{"not a terminal and no --yes", nil, "", false, []string{"--apply"}, "not a terminal"},
		{"answered no", nil, "n\n", true, []string{"--apply"}, ""},
		{"new value is the old one", func(_ *testing.T, fx *fixture) { fx.os.clip = fx.old }, "y\n", true, []string{"--apply"}, "is the old one"},
		{"empty clipboard", func(_ *testing.T, fx *fixture) { fx.os.clip = "" }, "y\n", true, []string{"--apply"}, "empty"},
		{"value with a quote", func(_ *testing.T, fx *fixture) { fx.os.clip = fx.new[:20] + `"` + fx.new[20:] }, "y\n", true, []string{"--apply"}, "by hand"},
		{"value on two lines", func(_ *testing.T, fx *fixture) { fx.os.clip = fx.new + "\n" + fx.new }, "y\n", true, []string{"--apply"}, "several lines"},
		{"old value moved off the recorded line", func(t *testing.T, fx *fixture) {
			write(t, fx.env, "# new first line\n"+read(t, fx.env), 0o600)
		}, "y\n", true, []string{"--apply"}, "no longer on line 1"},
		{"old value gone from a file", func(t *testing.T, fx *fixture) {
			write(t, fx.zshrc, "export ANTHROPIC_API_KEY=\"$(other)\"\n", 0o640)
		}, "y\n", true, []string{"--apply"}, "no longer on line 2"},
		{"--stdin typed on a terminal", nil, "", true, []string{"--stdin"}, "echoed"},
		{"--stdin piped, --apply without --yes", func(_ *testing.T, fx *fixture) {}, "PIPED", false, []string{"--stdin", "--apply"}, "not a terminal"},
		{"--to-keychain with a bad service", nil, "y\n", true, []string{"--apply", "--to-keychain", "a b"}, "--to-keychain"},
		{"Keychain did not take the value", func(_ *testing.T, fx *fixture) { fx.os.keepStale = true }, "y\n", true,
			[]string{"--apply", "--to-keychain", "ANTHROPIC_API_KEY"}, "no such Keychain item: ANTHROPIC_API_KEY"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := newReplaceFixture(t)
			if c.setup != nil {
				c.setup(t, fx)
			}
			stdin := strings.ReplaceAll(c.stdin, "PIPED", fx.new)
			zBefore, eBefore := read(t, fx.zshrc), read(t, fx.env)
			_, e, code := fx.run(t, stdin, c.tty, append([]string{"replace", fx.id()}, c.args...)...)
			if c.wantErr == "" {
				if code != 0 {
					t.Fatalf("code %d: %s", code, e)
				}
			} else if code != 1 || !strings.Contains(e, c.wantErr) {
				t.Fatalf("want error %q, got %d %q", c.wantErr, code, e)
			}
			if read(t, fx.zshrc) != zBefore || read(t, fx.env) != eBefore {
				t.Error("a refused replace changed a file")
			}
			if fx.item(t).Status != tracker.Open || fx.cleared() {
				t.Error("a refused replace marked the item or cleared the clipboard")
			}
		})
	}
}

func TestReplaceFromStdin(t *testing.T) {
	fx := newReplaceFixture(t)
	fx.os.clip = "something else entirely"
	if _, e, code := fx.run(t, fx.new+"\n", false, "replace", fx.id(), "--stdin", "--apply", "--yes"); code != 0 {
		t.Fatalf("apply: %s", e)
	}
	if !strings.Contains(read(t, fx.env), fx.new) {
		t.Error("value from stdin not written")
	}
	for _, c := range fx.os.calls {
		if c.name == pbpaste || c.name == pbcopy {
			t.Errorf("--stdin touched the clipboard: %s", c.name)
		}
	}
}

func TestReplaceToKeychain(t *testing.T) {
	fx := newReplaceFixture(t)
	o, e, code := fx.run(t, "y\n", true, "replace", fx.id(), "--apply", "--to-keychain", "ANTHROPIC_API_KEY")
	if code != 0 {
		t.Fatalf("apply: %d %s\n%s", code, e, o)
	}
	want := strings.ReplaceAll(zshrcOld, `"%s"`, `"$(security find-generic-password -a "$USER" -s ANTHROPIC_API_KEY -w)"`)
	if got := read(t, fx.zshrc); got != want {
		t.Errorf("rc file:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(read(t, fx.zshrc), fx.new) {
		t.Error("the new value was written to the rc file")
	}
	if !strings.Contains(read(t, fx.env), fx.new) {
		t.Error("the .env file (not an rc file) did not get the new value")
	}
	if fx.os.items["ANTHROPIC_API_KEY"] != fx.new {
		t.Error("the Keychain does not hold the new value")
	}
	var stored bool
	for _, c := range fx.os.calls {
		if c.name == security && c.args[0] == "-i" {
			stored = strings.Contains(c.stdin, " -a tester -s ANTHROPIC_API_KEY -w ")
		}
	}
	if !stored {
		t.Error("security -i did not receive the add command on stdin")
	}
	if !strings.Contains(fx.item(t).History[len(fx.item(t).History)-1].Detail, "Keychain as ANTHROPIC_API_KEY") {
		t.Error("history does not record the Keychain service")
	}
}

func TestReplaceToKeychainNeedsAPlainAssignment(t *testing.T) {
	fx := newReplaceFixture(t)
	write(t, fx.zshrc, "# shell\nexport ANTHROPIC_API_KEY=\""+fx.old+"\" # main key\n", 0o640)
	_, e, code := fx.run(t, "y\n", true, "replace", fx.id(), "--apply", "--to-keychain", "ANTHROPIC_API_KEY")
	if code != 1 || !strings.Contains(e, "not a plain `export NAME=value` line") {
		t.Errorf("%d %q", code, e)
	}
	fx = newReplaceFixture(t)
	l, _ := tracker.Load(fx.state)
	it, _ := l.FindRotate(fx.id())
	it.Secret.UsedIn = []string{"~/src/app/.env"} // no rc file left
	_ = l.Save(fx.state)
	if _, e, code := fx.run(t, "y\n", true, "replace", fx.id(), "--to-keychain", "X"); code != 1 || !strings.Contains(e, "no used_in file is one") {
		t.Errorf("%d %q", code, e)
	}
}

func TestReplaceWriteRefusesAFileChangedAfterThePlan(t *testing.T) {
	fx := newReplaceFixture(t)
	l, _ := tracker.Load(fx.state)
	it, _ := l.FindRotate(fx.id())
	r, err := locate(it, fx.key, fx.home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.checkNew([]byte(fx.new), ""); err != nil {
		t.Fatal(err)
	}
	write(t, fx.env, read(t, fx.env)+"LATER=1\n", 0o600)
	rc := read(t, fx.zshrc)
	written, err := r.write(context.Background(), false, t0)
	if err == nil || !strings.Contains(err.Error(), "changed since the plan") || len(written) != 0 {
		t.Errorf("written %v err %v", written, err)
	}
	if read(t, fx.zshrc) != rc {
		t.Error("a file was written before every file was checked")
	}
	if err := r.verify(fx.new); err == nil {
		t.Error("verify passed with the old value still in a file")
	}
}

func TestReplaceRefusesItemsItCannotLocate(t *testing.T) {
	l := tracker.New(t0)
	key, _ := fingerprint.Load(filepath.Join(t.TempDir(), "k"))
	l.SyncSecrets([]tracker.Sighting{
		{Evidence: secretrisk.Evidence{Source: "scan", Kind: "config", Type: "private-key", Redacted: "PEM", Path: "~/k.pem", Line: 1, Mode: "600", Fingerprint: "1111111111111111"}},
		{Evidence: secretrisk.Evidence{Source: "scan", Kind: "transcript", Type: "anthropic", Redacted: "sk-ant-…abcd(60)", Path: "~/.claude/p.jsonl", Line: 1, Mode: "600", Fingerprint: "2222222222222222"}},
	}, t0, false)
	for id, want := range map[string]string{"11111111": "not a single value on one line", "22222222": "no working file holds"} {
		it, _ := l.FindRotate(id)
		if _, err := locate(it, key, t.TempDir()); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", id, err)
		}
	}
}

func TestNext(t *testing.T) {
	fx := newReplaceFixture(t)
	_, e, code := fx.run(t, "", true, "next")
	if code != 0 {
		t.Fatalf("next: %s", e)
	}
	if fx.lastAction(t) == tracker.ActNext {
		t.Error("next without --log wrote to the history")
	}
	o, e, code := fx.run(t, "", true, "next", "--log")
	if code != 0 {
		t.Fatalf("next: %s", e)
	}
	for _, want := range []string{
		"Next of 1 open (P1 1)",
		fx.id() + "  P1  Anthropic API key  sk-ant-…",
		"pasted into an agent transcript",
		"~/.claude/projects/p/s.jsonl:9  transcript",
		"at https://platform.claude.com/settings/keys",
		"1. Console > Settings > API keys",
		"Source: https://platform.claude.com/docs/",
		"~/.zshrc:2  (shell rc: --to-keychain",
		"~/src/app/.env:1",
		"segurata rotations replace " + fx.id() + " ",
		"--apply [--to-keychain <VAR_NAME>]",
	} {
		if !strings.Contains(o, want) {
			t.Errorf("next lacks %q:\n%s", want, o)
		}
	}
	if fx.lastAction(t) != tracker.ActNext {
		t.Error("next not recorded")
	}
	fx.run(t, "", true, "next", "--log")
	n := 0
	for _, h := range fx.item(t).History {
		if h.Action == tracker.ActNext {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d next entries in a row, want 1", n)
	}
	if o, _, _ := fx.run(t, "", true, "next", "--priority", "P0"); !strings.Contains(o, "Nothing open matches") {
		t.Errorf("filtered next:\n%s", o)
	}
	if o, _, _ := fx.run(t, "", true, "next", "--service", "anthropic"); !strings.Contains(o, fx.id()) {
		t.Errorf("--service next:\n%s", o)
	}
}
