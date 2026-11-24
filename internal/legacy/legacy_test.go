package legacy

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/tracker"
)

var t0 = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

const oldConfig = `{
  "connectors": {
    "vercel": {"secrets": {"VERCEL_TOKEN": "keychain:securizame-vercel"}},
    "openai": {"secrets": {"OPENAI_ADMIN_KEY": "keychain:securizame-openai-admin"}},
    "openrouter:work": {"secrets": {"OPENROUTER_KEY": "keychain:securizame-openai-admin"}}
  }
}
`

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
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

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func gone(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("%s should be gone: %v", path, err)
	}
}

// oldTracker is a tracker as the former binary wrote it: its own name in who takes the next step,
// the commands, a decision option and a theme, and in the owner's note and a file path, which stay.
func oldTracker(t *testing.T, path string) {
	t.Helper()
	tr := tracker.New(t0)
	tr.Themes[0].Description = "Secrets in files: securizame redact cleans the local copies."
	var decide *tracker.Item
	for _, it := range tr.Items {
		if it.Kind == tracker.KindDecide {
			decide = it
			break
		}
	}
	if decide == nil {
		t.Fatal("the seeded tracker has no decision")
	}
	decide.Next = &tracker.Next{Who: oldName, Action: "Check ~/.config/securizame/config.json; securizame puts it in ~/src/me/securizame/.env",
		Command: "securizame track decide " + decide.ID}
	decide.Decision.Options = []string{"yes: securizame schedule install --apply", "not now"}
	decide.History = append(decide.History, tracker.Event{At: t0, Event: tracker.EvNote, Detail: "asked securizame about it"})
	if err := tr.Save(path); err != nil {
		t.Fatal(err)
	}
}

type layout struct {
	home, key string
	fake      *fakeKeychain
	out       bytes.Buffer
}

func (l *layout) env() Env {
	return Env{Home: l.home, UID: 501, Keychain: l.fake.keychain(), Out: &l.out}
}

func (l *layout) path(p ...string) string { return filepath.Join(append([]string{l.home}, p...)...) }

// oldLayout is a machine set up under the former name, with every directory it used.
func oldLayout(t *testing.T) *layout {
	l := &layout{home: t.TempDir(), fake: newFake(map[string]item{
		"securizame-vercel": {"u", "vercel-old"}, "segurata-vercel": {"u", "vercel-old"},
		"securizame-openai-admin": {"u", "sk-admin-old"},
	})}
	oldTracker(t, l.path(".securizame", "tracker.json"))
	write(t, l.path(".securizame", "status.md"), "# status\n", 0o600)
	cfg := l.path(".config", "securizame")
	write(t, filepath.Join(cfg, "config.json"), oldConfig, 0o600)
	if _, err := fingerprint.Load(filepath.Join(cfg, "fingerprint.key")); err != nil {
		t.Fatal(err)
	}
	l.key = read(t, filepath.Join(cfg, "fingerprint.key"))
	if err := os.Chmod(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, l.path(".cache", "securizame", "gitleaks", "abc.json"), "{}", 0o600)
	write(t, l.path(".local", "state", "securizame", "rotations.json.migrated-2026-11-24"), "{}", 0o600)
	write(t, l.path(".local", "state", "securizame", "out", "macos-1.jsonl"), "{}\n", 0o600)
	write(t, l.path(".local", "state", "securizame", "last-report.md"), "# report\n", 0o600)
	write(t, l.path("Library", "Logs", "securizame", "inventory.log"), "", 0o600)
	return l
}

func TestMigrateMovesEveryOldDirectoryOnce(t *testing.T) {
	l := oldLayout(t)
	if err := Migrate(context.Background(), l.env()); err != nil {
		t.Fatal(err)
	}
	out := l.out.String()
	for _, m := range [][2]string{
		{".securizame", ".segurata"},
		{".config/securizame", ".config/segurata"},
		{".cache/securizame", ".cache/segurata"},
		{"Library/Logs/securizame", "Library/Logs/segurata"},
		{".local/state/securizame/out", ".segurata/out"},
		{".local/state/securizame/last-report.md", ".segurata/last-report.md"},
		{".local/state/securizame/rotations.json.migrated-2026-11-24", ".segurata/rotations.json.migrated-2026-11-24"},
	} {
		if want := "segurata: moved " + l.path(m[0]) + " to " + l.path(m[1]) + "\n"; !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
		gone(t, l.path(m[0]))
	}
	gone(t, l.path(".local", "state", "securizame"))
	if got := read(t, l.path(".segurata", "last-report.md")); got != "# report\n" {
		t.Errorf("last report %q", got)
	}
	if mode(t, l.path(".config", "segurata")) != 0o700 || mode(t, l.path(".config", "segurata", "config.json")) != 0o600 ||
		mode(t, l.path(".segurata", "tracker.json")) != 0o600 || mode(t, l.path(".cache", "segurata", "gitleaks", "abc.json")) != 0o600 {
		t.Error("a move changed a mode")
	}

	// A second run finds nothing to do and says nothing.
	l.out.Reset()
	if err := Migrate(context.Background(), l.env()); err != nil || l.out.Len() != 0 {
		t.Errorf("second run: %v %q", err, l.out.String())
	}
}

func TestMigrateKeepsTheFingerprintKey(t *testing.T) {
	l := oldLayout(t)
	before, err := fingerprint.Open(fingerprint.DefaultPath(l.home)) // not there yet: the new path
	if err == nil {
		t.Fatalf("the new key path existed before the move: %v", before)
	}
	oldKey, err := fingerprint.Open(l.path(".config", "securizame", "fingerprint.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(context.Background(), l.env()); err != nil {
		t.Fatal(err)
	}
	if got := read(t, fingerprint.DefaultPath(l.home)); got != l.key {
		t.Error("the moved fingerprint key does not hold the same bytes")
	}
	newKey, err := fingerprint.Open(fingerprint.DefaultPath(l.home))
	if err != nil {
		t.Fatal(err)
	}
	if a, b := oldKey.Of("sk-live-example"), newKey.Of("sk-live-example"); a != b {
		t.Errorf("fingerprints changed across the move: %s, %s", a, b)
	}
}

func TestMigrateRenamesTheTrackersOwnWords(t *testing.T) {
	l := oldLayout(t)
	if err := Migrate(context.Background(), l.env()); err != nil {
		t.Fatal(err)
	}
	path := l.path(".segurata", "tracker.json")
	if !strings.Contains(l.out.String(), "segurata: renamed the commands the tracker suggests in "+path) {
		t.Errorf("no tracker line in:\n%s", l.out.String())
	}
	tr, err := tracker.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Themes[0].Description != "Secrets in files: segurata redact cleans the local copies." {
		t.Errorf("theme %q", tr.Themes[0].Description)
	}
	for _, it := range tr.Items {
		if it.Kind != tracker.KindDecide || it.Next == nil || it.Next.Who != tracker.Segurata {
			continue
		}
		if it.Next.Command != "segurata track decide "+it.ID || it.Decision.Options[0] != "yes: segurata schedule install --apply" {
			t.Errorf("next %+v, options %v", it.Next, it.Decision.Options)
		}
		if want := "Check ~/.config/segurata/config.json; segurata puts it in ~/src/me/securizame/.env"; it.Next.Action != want {
			t.Errorf("action %q, want %q (a path that only contains the old name stays)", it.Next.Action, want)
		}
		if last := it.History[len(it.History)-1]; last.Detail != "asked securizame about it" {
			t.Errorf("the owner's note changed: %q", last.Detail)
		}
		return
	}
	t.Error("no decision item handed to segurata")
}

func TestMigrateRenamesOnlyReferencesWhoseNewItemExists(t *testing.T) {
	l := oldLayout(t)
	if err := Migrate(context.Background(), l.env()); err != nil {
		t.Fatal(err)
	}
	cfgPath := l.path(".config", "segurata", "config.json")
	cfg := read(t, cfgPath)
	want := strings.Replace(oldConfig, "keychain:securizame-vercel", "keychain:segurata-vercel", 1)
	if cfg != want {
		t.Errorf("config:\n%s\nwant:\n%s", cfg, want)
	}
	out := l.out.String()
	if !strings.Contains(out, cfgPath+" now references keychain:segurata-vercel") ||
		!strings.Contains(out, "(securizame-openai-admin)") || !strings.Contains(out, "segurata keychain-migrate") {
		t.Errorf("output:\n%s", out)
	}
	for _, c := range l.fake.calls {
		if _, _, w := flags(c.args); w || c.args[0] != "find-generic-password" {
			t.Errorf("Migrate may only look up attributes, it ran security %v", c.args)
		}
	}
	l.fake.assertNoLeak(t, out, "vercel-old", "sk-admin-old")
}

func TestMigrateNeverOverwritesTheNewLayout(t *testing.T) {
	l := oldLayout(t)
	write(t, l.path(".segurata", "tracker.json.keep"), "new", 0o600)
	write(t, l.path(".segurata", "last-report.md"), "newer report\n", 0o600)
	write(t, l.path(".config", "segurata", "config.json"), "{}", 0o600)
	if err := Migrate(context.Background(), l.env()); err != nil {
		t.Fatal(err)
	}
	out := l.out.String()
	for _, p := range [][2]string{{".securizame", ".segurata"}, {".config/securizame", ".config/segurata"},
		{".local/state/securizame/last-report.md", ".segurata/last-report.md"}} {
		if want := "segurata: both " + l.path(p[0]) + " and " + l.path(p[1]) + " exist; using " + l.path(p[1]); !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if read(t, l.path(".segurata", "last-report.md")) != "newer report\n" || read(t, l.path(".config", "segurata", "config.json")) != "{}" ||
		read(t, l.path(".securizame", "status.md")) != "# status\n" {
		t.Error("a file of either layout changed")
	}
	// What did not conflict still moved; the old state directory stays for the report it still holds.
	if read(t, l.path(".segurata", "out", "macos-1.jsonl")) != "{}\n" ||
		read(t, l.path(".local", "state", "securizame", "last-report.md")) != "# report\n" {
		t.Error("state entries")
	}
}

func TestMigrateSaysHowToReplaceTheOldAgent(t *testing.T) {
	l := &layout{home: t.TempDir(), fake: newFake(nil)}
	if err := Migrate(context.Background(), l.env()); err != nil || l.out.Len() != 0 {
		t.Fatalf("nothing to migrate: %v %q", err, l.out.String())
	}
	plist := l.path("Library", "LaunchAgents", "com.securizame.inventory.plist")
	write(t, plist, "<plist/>", 0o644)
	if err := Migrate(context.Background(), l.env()); err != nil {
		t.Fatal(err)
	}
	if out := l.out.String(); !strings.Contains(out, "launchctl bootout gui/501/com.securizame.inventory; rm "+plist) ||
		!strings.Contains(out, "segurata schedule install --apply") {
		t.Errorf("output:\n%s", out)
	}
}

func TestRenameText(t *testing.T) {
	for in, want := range map[string]string{
		"securizame rotations next":                 "segurata rotations next",
		"run `securizame inventory` first":          "run `segurata inventory` first",
		"keychain:securizame-cloudflare":            "keychain:segurata-cloudflare",
		"-s securizame-vercel -a \"$USER\"":         "-s segurata-vercel -a \"$USER\"",
		"in ~/.config/securizame/config.json":       "in ~/.config/segurata/config.json",
		"~/.securizame/status.md":                   "~/.segurata/status.md",
		"~/src/segurata/main.go":                    "~/src/segurata/main.go",
		"/Users/me/securizame-test/.env":            "/Users/me/securizame-test/.env",
		".env.securizame-bak-20261124T100000Z kept": ".env.securizame-bak-20261124T100000Z kept",
	} {
		if got := renameText(in); got != want {
			t.Errorf("renameText(%q) = %q, want %q", in, got, want)
		}
	}
}
