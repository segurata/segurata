package tracker

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/finding"
)

func reauthStatus(account string) finding.Status {
	return finding.Status{Type: "status", Connector: "google-personal", Account: account, State: finding.StateReauth,
		Detail: "Google asks to verify it's you before showing linked apps: sign in again in the browser"}
}

func TestExpectedStatusesCloseTheirSetupItems(t *testing.T) {
	out := t.TempDir()
	writeRun(t, out, t0, "google-personal.jsonl", okStatus("google-personal", "me@x.com"),
		reauthStatus("anna@x.com"), reauthStatus("me2@x.com"))
	tr := New(t0)
	syncOrDie(t, tr, out, t0.Add(time.Hour))
	anna := byTitle(t, tr, "google-personal · anna@x.com: needs a fresh sign-in")
	if anna.Status != Open {
		t.Fatalf("before the rule: %s", anna.Status)
	}
	cfg := config.Config{Connectors: map[string]config.ConnectorConfig{"google-personal": {Expected: []config.Expected{
		{State: finding.StateReauth, Account: "anna@*", Reason: "someone else's account"}}}}}
	writeRun(t, out, t0.Add(24*time.Hour), "google-personal.jsonl", okStatus("google-personal", "me@x.com"),
		reauthStatus("anna@x.com"), reauthStatus("me2@x.com"), reauthStatus("anna@y.com"))
	rep, err := tr.Sync(SyncOptions{OutDir: out, Expect: cfg.Expect}, t0.Add(25*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// The open item closes as expected; the new expected status makes no open item.
	newAnna := byTitle(t, tr, "google-personal · anna@y.com")
	if anna.Status != Expected || newAnna.Status != Expected || rep.Expected != 2 || rep.Created != 0 {
		t.Fatalf("after the rule: %s %s %+v", anna.Status, newAnna.Status, rep)
	}
	if last := anna.History[len(anna.History)-1]; last.Action != actExpected || !strings.Contains(last.Detail, "someone else's account") {
		t.Errorf("history %+v", last)
	}
	if !strings.HasPrefix(anna.Next.Action, "Nothing: expected by your config") {
		t.Errorf("next %+v", anna.Next)
	}
	if byTitle(t, tr, "google-personal · me2@x.com").Status != Open {
		t.Error("a status no rule covers was closed")
	}
	var b strings.Builder
	if err := doc.Render(&b, tr.Status("tracker.json", t0.Add(25*time.Hour), View{}), doc.Text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "2 expected (by your config): someone else's account (2).") || !strings.Contains(b.String(), "expected 2") {
		t.Errorf("status:\n%s", b.String())
	}
	if strings.Contains(b.String(), "anna@") {
		t.Errorf("an expected item is listed as a blocker:\n%s", b.String())
	}

	// The rule is removed: the item opens again.
	syncOrDie(t, tr, out, t0.Add(26*time.Hour))
	if anna.Status != Open {
		t.Errorf("rule removed: %s", anna.Status)
	}
	// Expected again, then the status disappears: the item is done, not left as expected.
	if _, err := tr.Sync(SyncOptions{OutDir: out, Expect: cfg.Expect}, t0.Add(27*time.Hour)); err != nil {
		t.Fatal(err)
	}
	writeRun(t, out, t0.Add(48*time.Hour), "google-personal.jsonl", okStatus("google-personal", "me@x.com"), reauthStatus("me2@x.com"))
	if _, err := tr.Sync(SyncOptions{OutDir: out, Expect: cfg.Expect}, t0.Add(49*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if anna.Status != Done {
		t.Errorf("expected status gone: %s", anna.Status)
	}
}

// An intermittent expected status (an ephemeral key's reauth, reported one day in two) moves its
// item between expected and done, and never onto the to-do list.
func TestAnIntermittentExpectedStatusNeverReopensItsItem(t *testing.T) {
	out := t.TempDir()
	cfg := config.Config{Connectors: map[string]config.ConnectorConfig{"google-personal": {Expected: []config.Expected{
		{State: finding.StateReauth, Account: "anna@*", Reason: "someone else's account"}}}}}
	tr := New(t0)
	var anna *Item
	for day := range 4 {
		at := t0.AddDate(0, 0, day)
		recs := []any{okStatus("google-personal", "me@x.com")}
		if day%2 == 0 {
			recs = append(recs, reauthStatus("anna@x.com"))
		}
		writeRun(t, out, at, "google-personal.jsonl", recs...)
		rep, err := tr.Sync(SyncOptions{OutDir: out, Expect: cfg.Expect}, at.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if anna == nil {
			anna = byTitle(t, tr, "google-personal · anna@x.com")
		}
		want := map[bool]Status{true: Expected, false: Done}[day%2 == 0]
		if anna.Status != want || rep.Reopened != 0 {
			t.Fatalf("day %d: %s, want %s; reopened %d", day, anna.Status, want, rep.Reopened)
		}
	}
	if slices.ContainsFunc(anna.History, func(e Event) bool { return e.Event == EvReopened }) {
		t.Errorf("reopened on the way: %+v", anna.History)
	}
}

// One of several statuses under a key expected: the item stays open.
func TestAPartlyExpectedSetupItemStaysOpen(t *testing.T) {
	out := t.TempDir()
	st := func(p string) finding.Status {
		return finding.Status{Type: "status", Connector: "gcp", Account: "a@x.com", Scope: p, State: finding.StateError, Detail: "project " + p + ": permission denied"}
	}
	writeRun(t, out, t0, "gcp.jsonl", okStatus("gcp", "a@x.com"), st("p1"), st("p2"))
	cfg := config.Config{Connectors: map[string]config.ConnectorConfig{"gcp": {Expected: []config.Expected{{Detail: "project p1:", Reason: "not mine"}}}}}
	tr := New(t0)
	if _, err := tr.Sync(SyncOptions{OutDir: out, Expect: cfg.Expect}, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if it := byTitle(t, tr, "gcp: permission denied on 2 projects"); it.Status != Open {
		t.Errorf("%s", it.Status)
	}
}

func TestTrackExpectWritesTheRuleAndClosesTheItem(t *testing.T) {
	x := newCLIFixture(t)
	cfgPath := filepath.Join(x.dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"connectors": {"github": {"config": {"orgs": ["a"]}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, string, int) {
		t.Helper()
		var o, e strings.Builder
		c := CLI{Out: &o, Err: &e, Paths: Paths{Tracker: x.path}, Config: cfgPath, Now: func() time.Time { return x.now }}
		code := c.Track(args)
		return o.String(), e.String(), code
	}
	if _, e, code := run("sync", "--out", x.out); code != 0 {
		t.Fatal(e)
	}
	it := x.item(t, "github · github:me: lacks a permission")
	o, e, code := run("expect", it.ID, "--reason", "read:org is not granted on purpose", "--dry-run")
	if code != 0 || !strings.Contains(o, `Would add to connectors."github".expected in `+cfgPath) || !strings.Contains(o, `"state": "noscope"`) ||
		!strings.Contains(o, `"account": "github:me"`) || !strings.Contains(o, "Nothing written") {
		t.Fatalf("dry run: %d %q %q", code, o, e)
	}
	if raw, _ := os.ReadFile(cfgPath); strings.Contains(string(raw), "expected") {
		t.Fatal("--dry-run wrote the config")
	}
	if x.item(t, "github · github:me").Status != Open {
		t.Fatal("--dry-run closed the item")
	}
	if o, e, code = run("expect", it.ID, "--reason", "read:org is not granted on purpose"); code != 0 {
		t.Fatalf("expect: %q %q", o, e)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil || len(cfg.Connectors["github"].Expected) != 1 || cfg.Connectors["github"].Config["orgs"] == nil {
		t.Fatalf("config %v %+v", err, cfg)
	}
	if got := x.item(t, "github · github:me"); got.Status != Expected {
		t.Errorf("item %s", got.Status)
	}
	// The next sync keeps it expected.
	if _, e, code := run("sync", "--out", x.out); code != 0 {
		t.Fatal(e)
	}
	if got := x.item(t, "github · github:me"); got.Status != Expected {
		t.Errorf("after sync: %s", got.Status)
	}
	if _, e, code := run("expect", x.item(t, "No Time Machine").ID, "--reason", "x"); code != 1 || !strings.Contains(e, "not a setup item") {
		t.Errorf("expect on a fix item: %d %q", code, e)
	}
}
