package tracker

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// cliFixture is an out/ tree with a macos run, a github run, a status needing a sign-in and a
// local-secrets run holding one Stripe key, and a tracker path in a fresh home.
type cliFixture struct {
	dir, out, path string
	value          string // the Stripe key: must appear nowhere segurata writes
	now            time.Time
}

func newCLIFixture(t *testing.T) *cliFixture {
	t.Helper()
	x := &cliFixture{dir: t.TempDir(), now: t0.Add(time.Hour), value: "sk_live_" + strings.Repeat("Zq9", 33)}
	x.out = filepath.Join(x.dir, "out")
	x.path = filepath.Join(x.dir, "home", "tracker.json")
	writeRun(t, x.out, t0, "macos.jsonl",
		fnd("macos", "", "Mac", "macos_setting", "backup-none", "backup-none", finding.SevHigh, "No Time Machine backup is configured", t0),
		okStatus("macos", "Mac"))
	writeRun(t, x.out, t0, "github.jsonl",
		fnd("github", "", "github:a", "github_org_setting", "org-2fa-not-required", "a", finding.SevHigh, "a does not require two-factor authentication", t0),
		fnd("github", "", "github:b", "github_org_setting", "org-2fa-not-required", "b", finding.SevHigh, "b does not require two-factor authentication", t0),
		finding.Status{Type: "status", Connector: "github", Account: "github:me", State: finding.StateNoScope, Detail: "gh lacks read:org"})
	f := fnd(SecretsConnector, "", "local", "secret", "scan:~/src/shop/.env#ffff", "Stripe live key", finding.SevCritical, "Stripe live secret key in ~/src/shop/.env", t0)
	raw, _ := json.Marshal(secretrisk.Evidence{Fingerprint: "ffffeeeeddddcccc", Type: "stripe-live", Redacted: secretrisk.Redact("stripe-live", "sk_live_", x.value),
		Path: "~/.claude/projects/p/s.jsonl", Source: "scan", Kind: "transcript", Mode: "600", Bucket: "b", Line: 4})
	_ = json.Unmarshal(raw, &f.Evidence)
	writeRun(t, x.out, t0, "local-secrets.jsonl", f, okStatus(SecretsConnector, "local"))
	return x
}

func (x *cliFixture) run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var o, e bytes.Buffer
	c := CLI{Out: &o, Err: &e, Paths: Paths{Tracker: x.path}, Now: func() time.Time { return x.now }}
	var code int
	if args[0] == "status" {
		code = c.Status(args[1:])
	} else {
		code = c.Track(args)
	}
	if strings.Contains(o.String()+e.String(), x.value) {
		t.Fatal("a secret value reached the output")
	}
	return o.String(), e.String(), code
}

func (x *cliFixture) item(t *testing.T, prefix string) *Item {
	t.Helper()
	tr, err := Load(x.path)
	if err != nil {
		t.Fatal(err)
	}
	return byTitle(t, tr, prefix)
}

func TestTrackCommands(t *testing.T) {
	x := newCLIFixture(t)
	o, e, code := x.run(t, "sync", "--out", x.out)
	if code != 0 || !strings.Contains(o, "Secrets: 1 (1 new") || !strings.Contains(o, "3 runs folded; 4 new items") {
		t.Fatalf("sync: %d %q %q", code, o, e)
	}
	o, _, _ = x.run(t, "list")
	for _, want := range []string{"Two-factor authentication not required in 2 GitHub orgs", "No Time Machine backup", "github · github:me: lacks a permission",
		"Install the daily scheduled inventory?", "Plus 1 secret to rotate"} {
		if !strings.Contains(o, want) {
			t.Errorf("list lacks %q:\n%s", want, o)
		}
	}
	if o, _, _ := x.run(t, "list", "--kind", "rotate"); !strings.Contains(o, "Stripe live secret key sk_live_") || !strings.Contains(o, "1 item\n") {
		t.Errorf("list --kind rotate:\n%s", o)
	}
	backup := x.item(t, "No Time Machine")
	id := backup.ID

	o, _, code = x.run(t, "show", id)
	for _, want := range []string{id, "kind:      fix", "theme:     This Mac", "findings (1):", "reported", "history:", "found"} {
		if code != 0 || !strings.Contains(o, want) {
			t.Errorf("show lacks %q:\n%s", want, o)
		}
	}
	if _, _, code := x.run(t, "start", id); code != 0 || x.item(t, "No Time Machine").Status != InProgress {
		t.Error("start")
	}
	if _, _, code := x.run(t, "note", id, "bought", "a", "disk"); code != 0 || lastAction(x.item(t, "No Time Machine")) != actNote {
		t.Error("note")
	}
	if _, e, code := x.run(t, "prioritize", id, "P0"); code != 1 || !strings.Contains(e, "--reason") {
		t.Errorf("prioritize without a reason: %d %q", code, e)
	}
	if _, _, code := x.run(t, "prioritize", id, "p0", "--reason", "the disk is old"); code != 0 || x.item(t, "No Time Machine").EffectivePriority() != secretrisk.P0 {
		t.Error("prioritize")
	}
	if o, _, _ := x.run(t, "list", "--priority", "P0"); !strings.Contains(o, id) {
		t.Errorf("list --priority P0 misses the override:\n%s", o)
	}
	if _, _, code := x.run(t, "prioritize", id, "auto"); code != 0 || x.item(t, "No Time Machine").PriorityOverride != nil {
		t.Error("prioritize auto")
	}
	if _, _, code := x.run(t, "done", id, "--note", "Time Machine on"); code != 0 || x.item(t, "No Time Machine").Status != Done {
		t.Error("done")
	}
	if _, _, code := x.run(t, "reopen", id); code != 0 || x.item(t, "No Time Machine").Status != Open {
		t.Error("reopen")
	}
	if _, e, code := x.run(t, "snooze", id, "--until", "2026-01-01"); code != 1 || !strings.Contains(e, "not in the future") {
		t.Errorf("snooze into the past: %d %q", code, e)
	}
	if _, _, code := x.run(t, "snooze", id, "--until", "2027-01-01"); code != 0 || x.item(t, "No Time Machine").SnoozedUntil != "2027-01-01" {
		t.Error("snooze")
	}
	if _, e, code := x.run(t, "ignore", id); code != 1 || !strings.Contains(e, "--reason") {
		t.Errorf("ignore without a reason: %d %q", code, e)
	}
	if _, _, code := x.run(t, "ignore", id, "--reason", "no Mac backups here"); code != 0 || x.item(t, "No Time Machine").Status != Ignored {
		t.Error("ignore")
	}

	dec := x.item(t, "Install the daily scheduled inventory?")
	if _, e, code := x.run(t, "decide", dec.ID); code != 1 || !strings.Contains(e, "--answer") {
		t.Errorf("decide without an answer: %d %q", code, e)
	}
	if _, _, code := x.run(t, "decide", dec.ID, "--answer", "not now"); code != 0 || x.item(t, "Install the daily").Decision.Answer != "not now" {
		t.Error("decide")
	}
	o, _, code = x.run(t, "add", "--kind", "decide", "--question", "Keep the old VPS?", "--option", "yes", "--option", "no")
	if code != 0 || !strings.Contains(o, "Keep the old VPS?") {
		t.Fatalf("add decide: %d %q", code, o)
	}
	if d := x.item(t, "Keep the old VPS?"); d.Theme != "decisions" || strings.Join(d.Decision.Options, ",") != "yes,no" {
		t.Errorf("added decision %+v", d)
	}
	if _, _, code := x.run(t, "add", "--title", "Buy a YubiKey", "--priority", "P1", "--theme", "mac"); code != 0 {
		t.Error("add")
	}
	if it := x.item(t, "Buy a YubiKey"); it.Priority != secretrisk.P1 || it.Theme != "mac" || it.Kind != KindFix {
		t.Errorf("added %+v", it)
	}
	for _, bad := range [][]string{{"add"}, {"add", "--kind", "rotate", "--title", "x"}, {"add", "--kind", "decide"}, {"add", "--title", "x", "--priority", "P9"}} {
		if _, _, code := x.run(t, bad...); code == 0 {
			t.Errorf("%v accepted", bad)
		}
	}
	if _, e, code := x.run(t, "show", "T-9999"); code != 1 || !strings.Contains(e, "no item") {
		t.Errorf("unknown id: %d %q", code, e)
	}
	if _, _, code := x.run(t, "bogus"); code != 2 {
		t.Error("unknown subcommand")
	}
	// A secret's short id works too.
	if o, _, code := x.run(t, "show", "ffffeeee"); code != 0 || !strings.Contains(o, "segurata rotations show ffffeeee") {
		t.Errorf("show by short id: %d\n%s", code, o)
	}
	x.noSecret(t)
}

func (x *cliFixture) noSecret(t *testing.T) {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(x.path), "*"))
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		if strings.Contains(string(raw), x.value) || strings.Contains(string(raw), x.value[8:30]) {
			t.Fatalf("a secret value reached %s", f)
		}
	}
}

func TestStatusBriefing(t *testing.T) {
	x := newCLIFixture(t)
	if _, _, code := x.run(t, "sync", "--out", x.out); code != 0 {
		t.Fatal("sync")
	}
	for _, f := range []string{"text", "md", "html"} {
		o, e, code := x.run(t, "status", "--format", f, "--theme", "github-orgs,rotations,setup,decisions,mac")
		if code != 0 {
			t.Fatalf("%s: %d %s", f, code, e)
		}
		for _, want := range []string{"Headline", "Do next", "Rotate 1 P0 secret", "segurata rotations next --priority P0",
			"Two-factor authentication not required in 2 GitHub orgs", "Pending decisions", "Install the daily scheduled inventory?",
			"Setup blockers", "github · github:me: lacks a permission", "gh lacks read:org", "Accepted risks"} {
			if !strings.Contains(o, want) {
				t.Errorf("%s status lacks %q:\n%s", f, want, o)
			}
		}
	}
	// A filtered status does not move the "since" mark; a full one does, and --write writes both views.
	o, e, code := x.run(t, "status", "--write")
	if code != 0 || !strings.Contains(o, "first status: everything") || !strings.Contains(o, "Other items: 10 new.") || !strings.Contains(e, "status.html") {
		t.Fatalf("status --write: %d %q\n%s", code, e, o)
	}
	for _, name := range []string{"status.md", "status.html"} {
		st, err := os.Stat(filepath.Join(filepath.Dir(x.path), name))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v", name, err)
		}
	}
	x.now = x.now.Add(time.Hour)
	// A plain status is read-only: the tracker file is not rewritten.
	before, _ := os.ReadFile(x.path)
	if _, _, code := x.run(t, "status"); code != 0 {
		t.Fatal("status")
	}
	if after, _ := os.ReadFile(x.path); !bytes.Equal(before, after) {
		t.Error("status without --mark-seen wrote the tracker")
	}
	backup := x.item(t, "No Time Machine")
	if _, _, code := x.run(t, "done", backup.ID); code != 0 {
		t.Fatal("done")
	}
	o, _, _ = x.run(t, "status", "--mark-seen")
	if !strings.Contains(o, "Since the last status (2026-11-23 11:00)") || !strings.Contains(o, "No Time Machine backup is configured") {
		t.Errorf("changes since the last status:\n%s", o)
	}
	if strings.Count(o, "Two-factor authentication not required") != 1 {
		t.Errorf("only the do-next list should name the 2FA item now:\n%s", o)
	}
	if o, _, _ = x.run(t, "status"); !strings.Contains(o, "Since the last status (2026-11-23 12:00)") {
		t.Errorf("--mark-seen did not move the mark:\n%s", o)
	}
	x.noSecret(t)
	if _, _, code := x.run(t, "status", "--format", "pdf"); code != 2 {
		t.Error("bad format accepted")
	}
}

func TestEveryCommandRefusesABrokenTracker(t *testing.T) {
	x := newCLIFixture(t)
	if err := os.MkdirAll(filepath.Dir(x.path), 0o700); err != nil {
		t.Fatal(err)
	}
	broken := []byte(`{"schema_version": 1, "next_id": 3, "items": [{"id": "T-0001"`)
	if err := os.WriteFile(x.path, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"sync", "--out", x.out}, {"list"}, {"status"}, {"add", "--title", "x"}} {
		if _, e, code := x.run(t, args...); code != 1 || !strings.Contains(e, "tracker.json.bak") {
			t.Errorf("%v: %d %q", args, code, e)
		}
	}
	if raw, _ := os.ReadFile(x.path); !bytes.Equal(raw, broken) {
		t.Error("a broken tracker was overwritten")
	}
}
