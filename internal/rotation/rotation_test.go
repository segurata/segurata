package rotation

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

var t0 = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

func ev(fp, typ, path, source, kind, mode string, tracked, remote bool) secretrisk.Evidence {
	return secretrisk.Evidence{Fingerprint: fp, Type: typ, Path: path, Source: source, Kind: kind, Mode: mode,
		Tracked: tracked, Remote: remote, Redacted: "hint-" + typ, Bucket: "b", Count: 1}
}

func sight(e secretrisk.Evidence) Sighting { return Sighting{Evidence: e} }

func TestSyncGroupsByFingerprintAndPrioritises(t *testing.T) {
	l := &Ledger{}
	rep := l.Sync([]Sighting{
		sight(ev("aaaaaaaaaaaaaaaa", "stripe-live", "~/src/shop/.env", "scan", "repo", "600", false, false)),
		sight(ev("aaaaaaaaaaaaaaaa", "stripe-live", "~/.claude/projects/p/s.jsonl", "scan", "transcript", "600", false, false)),
		sight(ev("aaaaaaaaaaaaaaaa", "generic-api-key", "~/src/shop/app.js", "gitleaks", "repo", "", true, false)),
		sight(ev("bbbbbbbbbbbbbbbb", "anthropic", "~/.zshrc", "scan", "config", "644", false, false)),
		sight(ev("cccccccccccccccc", "assignment", "~/.env", "scan", "config", "600", false, false)),
		sight(ev("dddddddddddddddd", "private-key", "~/k.json", "scan", "config", "600", false, false)),
		sight(ev("dddddddddddddddd", "gcp-service-account", "~/k.json", "scan", "config", "600", false, false)),
	}, t0, false)
	if rep.Secrets != 3 || rep.Created != 3 || rep.Skipped != 1 {
		t.Fatalf("report %+v", rep)
	}
	s, _ := l.Find("aaaaaaaa")
	if s.Type != "stripe-live" || s.Service != "stripe" || s.Priority != secretrisk.P0 || len(s.Locations) != 3 {
		t.Fatalf("stripe item %+v", s)
	}
	if s.Reasons[0] != "Stripe live secret key; pasted into an agent transcript, so it reached the model provider" {
		t.Errorf("reason %q", s.Reasons[0])
	}
	if len(s.Reasons) != 3 || !strings.Contains(s.Reasons[1], "local git repository") {
		t.Errorf("secondary reasons %q", s.Reasons)
	}
	if strings.Join(s.UsedIn, ",") != "~/src/shop/.env" || s.RotateURL != "https://dashboard.stripe.com/apikeys" {
		t.Errorf("used_in %v rotate %q", s.UsedIn, s.RotateURL)
	}
	if s.WorstLabel() != "transcript" || s.Status != Open || len(s.History) != 1 || s.History[0].Action != actFound {
		t.Errorf("stripe item state %+v", s)
	}
	a, _ := l.Find("bbbb")
	if a.Priority != secretrisk.P2 {
		t.Errorf("anthropic in a readable rc file: %s", a.Priority)
	}
	g, _ := l.Find("dddd")
	if g.Type != "gcp-service-account" || g.Priority != secretrisk.P2 || len(g.Locations) != 1 {
		t.Errorf("service account key %+v", g)
	}
	if _, err := l.Find("cccc"); err == nil {
		t.Error("noise-only secret tracked by default")
	}

	l.Sync([]Sighting{sight(ev("cccccccccccccccc", "assignment", "~/.env", "scan", "config", "600", false, false))}, t0, true)
	if c, err := l.Find("cccc"); err != nil || c.Priority != "" {
		t.Errorf("--include-noise item: %+v %v", c, err)
	}
}

func TestRotatedButStillPresentReopens(t *testing.T) {
	l := &Ledger{}
	in := []Sighting{sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.netrc", "scan", "config", "600", false, false))}
	l.Sync(in, t0, false)
	it, _ := l.Find("aaaa")
	it.Done(t0.Add(time.Hour), "new token in the Keychain")
	if it.Status != Rotated {
		t.Fatal("not rotated")
	}
	rep := l.Sync(in, t0.Add(24*time.Hour), false)
	if rep.Reopened != 1 || it.Status != Open || it.Reasons[0] != stillPresent {
		t.Fatalf("report %+v item %+v", rep, it)
	}
	if last := it.History[len(it.History)-1]; last.Action != actAutoReopen {
		t.Errorf("history %+v", it.History)
	}
	it.Done(t0.Add(48*time.Hour), "removed for real")
	if len(it.Reasons) > 0 && it.Reasons[0] == stillPresent {
		t.Error("stale reason kept after done")
	}
}

func TestRotatedSeenOnlyInHistoryStaysRotated(t *testing.T) {
	l := &Ledger{}
	rc := sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.zshrc", "scan", "config", "600", false, false))
	transcript := sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.claude/projects/p/s.jsonl", "scan", "transcript", "600", false, false))
	gitHistory := sight(ev("aaaaaaaaaaaaaaaa", "github", "~/src/app/config.yml", "gitleaks", "repo", "", true, true))
	l.Sync([]Sighting{rc, transcript, gitHistory}, t0, false)
	it, _ := l.Find("aaaa")
	it.Done(t0.Add(time.Hour), "")
	if strings.Join(it.RotatedLocations, ",") != "gitleaks:~/src/app/config.yml,scan:~/.claude/projects/p/s.jsonl,scan:~/.zshrc" {
		t.Fatalf("rotated locations %v", it.RotatedLocations)
	}

	// The rc file was fixed; the transcript and git history still hold the dead value, and a new
	// log copy appeared.
	log := sight(ev("aaaaaaaaaaaaaaaa", "github", "~/src/app/log/dev.log", "scan", "log", "600", false, false))
	for day := 1; day <= 3; day++ {
		rep := l.Sync([]Sighting{transcript, gitHistory, log}, t0.Add(time.Duration(day)*24*time.Hour), false)
		if it.Status != Rotated || rep.Reopened != 0 {
			t.Fatalf("day %d: reopened on history-only copies: %+v %+v", day, rep, it)
		}
		if want := map[bool]int{true: 1, false: 0}[day == 1]; rep.HistoryOnly != want {
			t.Errorf("day %d: history-only count %d, want %d", day, rep.HistoryOnly, want)
		}
	}
	notes := 0
	for _, e := range it.History {
		if e.Action == actHistory {
			notes++
			if e.Note != historyOnly {
				t.Errorf("note %q", e.Note)
			}
		}
	}
	if notes != 1 || len(it.Locations) != 4 {
		t.Errorf("want one note and four locations: %d %+v", notes, it.Locations)
	}

	// A second rotation gets its own note.
	it.Reopen(t0.Add(5*24*time.Hour), "")
	it.Done(t0.Add(5*24*time.Hour), "rotated again")
	if rep := l.Sync([]Sighting{transcript}, t0.Add(6*24*time.Hour), false); rep.HistoryOnly != 1 || it.Status != Rotated {
		t.Errorf("after a new rotation: %+v %s", rep, it.Status)
	}
}

func TestRotatedSeenInWorkingFileReopens(t *testing.T) {
	cases := []struct {
		name string
		see  []Sighting
		note string
	}{
		{"known working file", []Sighting{
			sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.zshrc", "scan", "config", "600", false, false)),
		}, "still in ~/.zshrc"},
		{"new working file", []Sighting{
			sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.claude/projects/p/s.jsonl", "scan", "transcript", "600", false, false)),
			sight(ev("aaaaaaaaaaaaaaaa", "github", "~/src/new/.env", "scan", "repo", "600", false, false)),
		}, "new working location ~/src/new/.env"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &Ledger{}
			l.Sync([]Sighting{
				sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.zshrc", "scan", "config", "600", false, false)),
				sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.claude/projects/p/s.jsonl", "scan", "transcript", "600", false, false)),
			}, t0, false)
			it, _ := l.Find("aaaa")
			it.Done(t0.Add(time.Hour), "")
			rep := l.Sync(tc.see, t0.Add(24*time.Hour), false)
			if rep.Reopened != 1 || rep.HistoryOnly != 0 || it.Status != Open || it.Reasons[0] != stillPresent {
				t.Fatalf("report %+v item %+v", rep, it)
			}
			last := it.History[len(it.History)-1]
			if last.Action != actAutoReopen || !strings.HasSuffix(last.Note, tc.note) {
				t.Errorf("history %+v", last)
			}
		})
	}
}

func TestItemsNotSeenKeepLastSeen(t *testing.T) {
	l := &Ledger{}
	l.Sync([]Sighting{sight(ev("aaaaaaaaaaaaaaaa", "xai", "~/.zshrc", "scan", "config", "600", false, false))}, t0, false)
	l.Sync([]Sighting{sight(ev("bbbbbbbbbbbbbbbb", "xai", "~/.zshrc", "scan", "config", "600", false, false))}, t0.Add(72*time.Hour), false)
	a, _ := l.Find("aaaa")
	b, _ := l.Find("bbbb")
	if !a.LastSeen.Equal(t0) || !b.LastSeen.Equal(t0.Add(72*time.Hour)) || len(l.Items) != 2 {
		t.Errorf("last seen %v %v", a.LastSeen, b.LastSeen)
	}
}

func TestSnoozeExpires(t *testing.T) {
	l := &Ledger{}
	l.Sync([]Sighting{sight(ev("aaaaaaaaaaaaaaaa", "notion", "~/.mcp/x.json", "scan", "config", "600", false, false))}, t0, false)
	it, _ := l.Find("aaaa")
	if err := it.Snooze(t0, "2026-11-20", ""); err == nil {
		t.Error("snooze into the past accepted")
	}
	if err := it.Snooze(t0, "next week", ""); err == nil {
		t.Error("bad date accepted")
	}
	if err := it.Snooze(t0, "2026-12-01", "after the release"); err != nil {
		t.Fatal(err)
	}
	if it.Active(t0) || !it.Active(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("snooze window")
	}
	rep := l.Sync(nil, time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC), false)
	if rep.Woken != 1 || it.Status != Open {
		t.Errorf("snooze did not expire: %+v %s", rep, it.Status)
	}
	if err := it.Ignore(t0, " "); err == nil {
		t.Error("ignore without a reason")
	}
}

func TestIDsGrowOnCollision(t *testing.T) {
	l := &Ledger{}
	l.Sync([]Sighting{
		sight(ev("abcdef0123456789", "github", "~/a", "scan", "config", "600", false, false)),
		sight(ev("abcdef0199999999", "github", "~/b", "scan", "config", "600", false, false)),
	}, t0, false)
	if l.Items[0].ID != "abcdef01" || l.Items[1].ID != "abcdef019" {
		t.Errorf("ids %s %s", l.Items[0].ID, l.Items[1].ID)
	}
	if _, err := l.Find("abcdef"); err == nil || !strings.Contains(err.Error(), "matches 2") {
		t.Errorf("ambiguous prefix: %v", err)
	}
}

func TestSortByPriorityExposureService(t *testing.T) {
	l := &Ledger{}
	l.Sync([]Sighting{
		sight(ev("1111111111111111", "anthropic", "~/a", "scan", "transcript", "600", false, false)),      // P1 transcript
		sight(ev("2222222222222222", "github", "~/b", "scan", "config", "644", false, false)),             // P1 readable
		sight(ev("3333333333333333", "aws-access-key-id", "~/c", "gitleaks", "repo", "", true, true)),     // P0
		sight(ev("4444444444444444", "openai-project", "~/d", "scan", "transcript", "600", false, false)), // P1 transcript
		sight(ev("5555555555555555", "sentry-dsn", "~/e", "scan", "config", "600", false, false)),         // P3
	}, t0, false)
	items := append([]*Item{}, l.Items...)
	Sort(items)
	var got []string
	for _, it := range items {
		got = append(got, it.Service)
	}
	if strings.Join(got, ",") != "aws,anthropic,openai,github,sentry" {
		t.Errorf("order %v", got)
	}
}

func writeFindings(t *testing.T, path string, evs ...secretrisk.Evidence) {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, e := range evs {
		raw, _ := json.Marshal(e)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		_ = enc.Encode(finding.Finding{Type: "finding", Connector: Connector, Evidence: m, ObservedAt: t0})
	}
	_ = enc.Encode(finding.Status{Type: "status", Connector: Connector, State: finding.StateOK})
	_ = enc.Encode(finding.Finding{Type: "finding", Connector: "aws", Evidence: map[string]any{"fingerprint": "zzzz"}})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCommands(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFindings(t, filepath.Join(out, "2026-11-01", "local-secrets.jsonl"),
		ev("1111111111111111", "anthropic", "~/old", "scan", "config", "600", false, false))
	writeFindings(t, filepath.Join(out, "2026-11-23", "local-secrets.jsonl"),
		ev("aaaaaaaaaaaaaaaa", "stripe-live", "~/src/shop/.env", "scan", "repo", "600", false, false),
		ev("aaaaaaaaaaaaaaaa", "stripe-live", "~/src/shop/x.env", "gitleaks", "repo", "", true, true),
		ev("bbbbbbbbbbbbbbbb", "sentry-dsn", "~/src/blog/.env", "scan", "repo", "600", false, false))
	state := filepath.Join(dir, "state", "rotations.json")
	run := func(args ...string) (string, string, int) {
		var o, e bytes.Buffer
		code := CLI{Out: &o, Err: &e, StatePath: state, Now: func() time.Time { return t0 }}.Run(args)
		return o.String(), e.String(), code
	}

	o, e, code := run("sync", "--out", out)
	if code != 0 || !strings.Contains(o, "2 secrets (2 new") || !strings.Contains(o, "P0 1") {
		t.Fatalf("sync: %d %q %q", code, o, e)
	}
	if st, err := os.Stat(state); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v", err)
	}
	o, _, _ = run("list", "--priority", "P0,P1")
	if !strings.Contains(o, "aaaaaaaa") || strings.Contains(o, "bbbbbbbb") || !strings.Contains(o, "git+remote") || !strings.Contains(o, "1 items") {
		t.Errorf("list P0,P1:\n%s", o)
	}
	o, _, _ = run("list", "--service", "sentry")
	if !strings.Contains(o, "bbbbbbbb") || strings.Contains(o, "aaaaaaaa") {
		t.Errorf("list --service:\n%s", o)
	}
	o, _, code = run("show", "aaaa")
	for _, want := range []string{"rotate at:   https://dashboard.stripe.com/apikeys", "~/src/shop/.env", "committed to a git repository with a remote", "found"} {
		if code != 0 || !strings.Contains(o, want) {
			t.Errorf("show lacks %q:\n%s", want, o)
		}
	}
	if _, _, code := run("done", "aaaa", "--note", "rolled in the dashboard"); code != 0 {
		t.Fatal("done failed")
	}
	if _, e, code := run("snooze", "bbbb"); code == 0 || !strings.Contains(e, "--until") {
		t.Errorf("snooze without --until: %d %q", code, e)
	}
	if _, _, code := run("snooze", "bbbb", "--until", "2027-01-01"); code != 0 {
		t.Error("snooze failed")
	}
	o, _, _ = run("list")
	if !strings.Contains(o, "0 items") {
		t.Errorf("default list should hide rotated and snoozed:\n%s", o)
	}
	o, _, _ = run("list", "--all")
	if !strings.Contains(o, "rotated") || !strings.Contains(o, "snoozed") {
		t.Errorf("list --all:\n%s", o)
	}
	if _, _, code := run("ignore", "bbbb", "--reason", "public DSN"); code != 0 {
		t.Error("ignore failed")
	}
	if _, _, code := run("reopen", "bbbb"); code != 0 {
		t.Error("reopen failed")
	}
	o, _, _ = run("sync", "--from", filepath.Join(out, "2026-11-23", "local-secrets.jsonl"))
	if !strings.Contains(o, "1 reopened") {
		t.Errorf("rotated secret still present should reopen: %q", o)
	}
	o, _, _ = run("show", "aaaa")
	if !strings.Contains(o, stillPresent) || !strings.Contains(o, "rolled in the dashboard") {
		t.Errorf("show after reopen:\n%s", o)
	}
	if _, e, code := run("show", "ffff"); code != 1 || !strings.Contains(e, "no item") {
		t.Errorf("unknown id: %d %q", code, e)
	}
	if _, _, code := run("bogus"); code != 2 {
		t.Error("unknown subcommand accepted")
	}
	if _, e, code := run("sync", "--out", filepath.Join(dir, "none")); code != 1 || !strings.Contains(e, "inventory local-secrets") {
		t.Errorf("sync without runs: %d %q", code, e)
	}
}

func TestBulkByPath(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "f.jsonl")
	writeFindings(t, src,
		ev("1111111111111111", "private-key", "~/src/app/log/test.log", "scan", "log", "644", false, false),
		ev("2222222222222222", "private-key", "~/src/app/log/test.log", "scan", "log", "644", false, false),
		ev("3333333333333333", "private-key", "~/src/app/log/test.log", "scan", "log", "644", false, false),
		ev("3333333333333333", "private-key", "~/.ssh/id_x", "ssh", "config", "600", false, false),
		ev("4444444444444444", "github", "~/src/app/log/test.log.old", "scan", "log", "644", false, false))
	state := filepath.Join(dir, "rotations.json")
	run := func(args ...string) (string, string, int) {
		var o, e bytes.Buffer
		code := CLI{Out: &o, Err: &e, StatePath: state, Now: func() time.Time { return t0 }}.Run(args)
		return o.String(), e.String(), code
	}
	run("sync", "--from", src)
	o, e, code := run("ignore", "--path", "~/src/app/log/test.log", "--reason", "test fixtures")
	if code != 0 || !strings.Contains(o, "2 items") {
		t.Fatalf("bulk ignore: %d %q %q", code, o, e)
	}
	l, _ := Load(state)
	for id, want := range map[string]Status{"1111": Ignored, "2222": Ignored, "3333": Open, "4444": Open} {
		if it, _ := l.Find(id); it.Status != want {
			t.Errorf("%s: %s, want %s", id, it.Status, want)
		}
	}
	if _, _, code := run("reopen", "--path", "~/src/app/log/"); code != 0 {
		t.Error("bulk reopen")
	}
	if _, e, code := run("done", "1111", "--path", "~/src"); code != 2 || !strings.Contains(e, "usage") {
		t.Errorf("id and --path together: %d %q", code, e)
	}
	if _, e, code := run("snooze", "--path", "~/nowhere", "--until", "2027-01-01"); code != 1 || !strings.Contains(e, "no open item") {
		t.Errorf("empty selection: %d %q", code, e)
	}
}

func TestDefaultPathHonoursEnv(t *testing.T) {
	t.Setenv("SECURIZAME_STATE", "/somewhere")
	if p, _ := DefaultPath(); p != "/somewhere/rotations.json" {
		t.Errorf("path %q", p)
	}
}

func TestLatestOutputWithoutRuns(t *testing.T) {
	if _, err := LatestOutput(t.TempDir()); err == nil || !strings.Contains(err.Error(), "securizame inventory local-secrets") {
		t.Errorf("err %v", err)
	}
}

func TestLoadRejectsNewerVersion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rotations.json")
	_ = os.WriteFile(p, []byte(`{"version": 99, "items": []}`), 0o600)
	if _, err := Load(p); err == nil {
		t.Error("newer ledger accepted")
	}
}

// A rule fix that lowers a secret's impact must reach existing items on the next sync.
func TestSyncLowersImpactWhenTheCurrentSightingIsLess(t *testing.T) {
	l := &Ledger{}
	high := ev("aaaaaaaaaaaaaaaa", "aws-access-key-id", "~/src/r/data.json", "gitleaks", "repo", "", true, true)
	high.Redacted = "AKIA…(20)"
	l.Sync([]Sighting{sight(high)}, t0, false)
	if p := l.Items[0].Priority; p != "P0" {
		t.Fatalf("pushed long-lived AWS key should be P0, got %s", p)
	}
	temp := high
	temp.Redacted = "ASIA…(20)"
	l.Sync([]Sighting{sight(temp)}, t0.Add(time.Hour), false)
	if it := l.Items[0]; it.Impact != "low" || it.Priority == "P0" {
		t.Fatalf("the same item seen as a temporary credential must drop: impact=%s priority=%s", it.Impact, it.Priority)
	}
}
