package report

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/doc"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/runtest"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/tracker"
)

var now = time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)

// fx is a synthetic out/ tree with two runs of macos, a first run of aws and a labelled
// openrouter instance, plus a tracker holding three accepted risks and five rotate items.
type fx struct {
	dir, out, tracker   string
	a, b, c, d, e, f, g finding.Finding
}

func mk(connector, instance, resID string, sev finding.Severity, title string) finding.Finding {
	f := finding.Finding{Connector: connector, Instance: instance, Account: "local", Kind: finding.KindSetting,
		Resource: finding.Resource{Type: "t", ID: resID}, Severity: sev, Title: title,
		Remediation: finding.Remediation{Summary: "Fix " + title + ".", URL: "https://example.com/fix"}}
	f.Fill(now)
	return f
}

var writeRun = runtest.Write

func status(connector, instance, account string, st finding.State, detail string) finding.Status {
	return finding.Status{Type: "status", Connector: connector, Instance: instance, Account: account, State: st, Detail: detail}
}

func newFx(t *testing.T) *fx {
	x := &fx{dir: t.TempDir()}
	x.out = filepath.Join(x.dir, "out")
	x.a = mk("macos", "", "a", finding.SevHigh, "Accepted debugging port")
	x.b = mk("macos", "", "b", finding.SevMedium, "Firewall off")
	x.c = mk("macos", "", "c", finding.SevLow, "Guest account <b>on</b>")
	x.d = mk("macos", "", "d", finding.SevHigh, "Port 5000 open")
	x.e = mk("macos", "", "e", finding.SevMedium, "New login item")
	x.f = mk("openrouter", "work", "f", finding.SevHigh, "Key file readable by others")
	x.f.Remediation.Action = "file.chmod600"
	x.f.Fill(now)
	x.g = mk("macos", "", "g", finding.SevLow, "Something fixed since")

	writeRun(t, filepath.Join(x.out, "2026-11-20", "macos.jsonl"), x.a, x.b, x.c, x.d)
	b2 := x.b
	b2.Severity = finding.SevCritical
	writeRun(t, filepath.Join(x.out, "2026-11-21", "macos.jsonl"), x.a, b2, x.c, x.e, status("macos", "", "local", finding.StateOK, ""))
	writeRun(t, filepath.Join(x.out, "2026-11-21", "openrouter-work.jsonl"), x.f, status("openrouter", "work", "org", finding.StateReauth, "session expired"))
	writeRun(t, filepath.Join(x.out, "2026-11-22", "aws.jsonl"), status("aws", "", "default", finding.StateMissingCredentials, "no profile"))
	// A log line and a day folder without this connector must not confuse the previous-run lookup.
	if err := os.MkdirAll(filepath.Join(x.out, "notadate"), 0o700); err != nil {
		t.Fatal(err)
	}

	tr := tracker.New(now)
	for _, acc := range []struct {
		f             finding.Finding
		reason, until string
		at            time.Time
	}{
		{x.a, "agents need it", "", now.AddDate(0, -1, 0)},
		{x.c, "kids", "2026-11-01", now.AddDate(0, -2, 0)},
		{x.g, "old", "", now.AddDate(0, -3, 0)},
	} {
		if _, err := tr.AcceptFinding(acc.f, acc.reason, acc.until, acc.at); err != nil {
			t.Fatal(err)
		}
	}
	// As a sync leaves it; the rotate items below stand for secrets folded before.
	if _, err := tr.Sync(tracker.SyncOptions{OutDir: x.out}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		id    string
		p     secretrisk.Priority
		st    tracker.Status
		until string
	}{
		{"aaaa1111", secretrisk.P0, tracker.Open, ""}, {"bbbb2222", secretrisk.P1, tracker.Open, ""},
		{"cccc3333", secretrisk.P2, tracker.Snoozed, "2026-11-01"}, {"dddd4444", secretrisk.P0, tracker.Snoozed, "2027-01-01"},
		{"eeee5555", secretrisk.P0, tracker.Done, ""},
	} {
		addRotate(tr, r.id, r.p, r.st, r.until)
	}
	x.tracker = filepath.Join(x.dir, "home", "tracker.json")
	if err := tr.Save(x.tracker); err != nil {
		t.Fatal(err)
	}
	return x
}

// addRotate adds a rotate item for a Stripe live key pushed to a remote, as a sync leaves it.
func addRotate(tr *tracker.Tracker, id string, p secretrisk.Priority, st tracker.Status, until string) {
	fp := id + "00000000"
	seen := now.AddDate(0, 0, -3)
	tr.Items = append(tr.Items, &tracker.Item{ID: fmt.Sprintf("T-%04d", tr.NextID), Key: "rotate:" + fp, Kind: tracker.KindRotate,
		Theme: "rotations", Title: "Stripe live key " + id, Status: st, SnoozedUntil: until, Priority: p, Severity: secretrisk.SeverityOf(p),
		Fingerprint: fp, StatusAt: seen, CreatedAt: seen, UpdatedAt: now,
		Secret: &tracker.Secret{ID: id, Service: "stripe", Type: "stripe-live", Redacted: "sk_live_…" + id[:4] + "(40)", Impact: "high",
			Reasons: []string{"Stripe live secret key; pushed to a remote"}, FirstSeen: seen, LastSeen: now, UsedIn: []string{},
			Locations: []tracker.Location{{Path: "~/src/shop/.env", Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, LastSeen: now}},
			RotateURL: "https://dashboard.stripe.com/apikeys"}})
	tr.NextID++
}

func (x *fx) build(t *testing.T) *Report {
	t.Helper()
	tr, err := tracker.Load(x.tracker)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Build(Inputs{OutDir: x.out, Now: now, Tracker: tr, TrackerPath: x.tracker, MinSev: finding.SevLow, Top: 10})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A tracker that never synced is synced in memory, so the report counts items before the first
// track sync too, from the same engine; the report saves nothing.
func TestBuildSyncsANewTrackerInMemory(t *testing.T) {
	x := newFx(t)
	home := filepath.Join(x.dir, "fresh")
	c := CLI{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, Paths: tracker.Paths{Tracker: filepath.Join(home, "tracker.json")}, Now: func() time.Time { return now }}
	var out bytes.Buffer
	c.Out = &out
	if code := c.Run([]string{"--dir", x.out}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"Firewall off", "openrouter:work · org: needs a fresh sign-in", "Changes in the last 7 days"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, out.String())
		}
	}
	if _, err := os.Stat(home); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the report wrote the tracker: %v", err)
	}
}

// Build annotates the latest runs' findings with the tracker's acceptances.
func TestBuildAnnotatesAcceptances(t *testing.T) {
	x := newFx(t)
	r := x.build(t)
	runs := map[string]*Run{}
	for _, run := range r.Runs {
		runs[run.Label] = run
	}
	m := runs["macos"]
	if m.Date != "2026-11-21" {
		t.Fatalf("macos date %s", m.Date)
	}
	for _, f := range m.Findings {
		switch f.ID {
		case x.a.ID:
			if !f.Hidden() {
				t.Error("accepted finding not hidden")
			}
		case x.c.ID:
			if f.Hidden() || f.DisplayTitle() != x.c.Title+" (acceptance expired)" {
				t.Errorf("expired acceptance: hidden %v title %q", f.Hidden(), f.DisplayTitle())
			}
		}
	}
}

func TestBuildAcceptedAndLedger(t *testing.T) {
	x := newFx(t)
	r := x.build(t)
	state := map[string]string{}
	for _, a := range r.Accepted {
		state[a.ID] = map[bool]string{true: "expired", false: "in force"}[a.Expired]
		if a.Gone {
			state[a.ID] += ", gone"
		}
	}
	if state[x.a.ID] != "in force" || state[x.c.ID] != "expired" || state[x.g.ID] != "in force, gone" {
		t.Errorf("accepted %v", state)
	}
	s := r.Rotations
	if s.Total != 5 || s.Open[secretrisk.P0] != 1 || s.Open[secretrisk.P1] != 1 || s.Open[secretrisk.P2] != 1 {
		t.Errorf("open %v of %d", s.Open, s.Total)
	}
	if len(s.TopP0) != 1 || s.TopP0[0].Secret.ID != "aaaa1111" {
		t.Errorf("top P0 %v", s.TopP0)
	}
	if len(s.SnoozesDue) != 1 || s.SnoozesDue[0].Secret.ID != "cccc3333" {
		t.Errorf("snoozes due %v", s.SnoozesDue)
	}
}

func render(t *testing.T, r *Report, f Format) string {
	t.Helper()
	var buf bytes.Buffer
	if err := r.Render(&buf, f); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestRenderEveryFormatSaysTheSame(t *testing.T) {
	x := newFx(t)
	r := x.build(t)
	for _, f := range []Format{Text, Markdown, HTML} {
		out := render(t, r, f)
		for _, want := range []string{
			"segurata remediate " + x.f.ID, // automatable
			"openrouter:work · org: needs a fresh sign-in", "segurata inventory aws", "segurata inventory openrouter:work",
			"Firewall off", "New login item", "Changes in the last 7 days",
			"acceptance expired",
			"1 accepted findings hidden",
			"sk_live_…aaaa(40)", "P0 1, P1 1, P2 1, P3 0", "Snoozes due", "cccc3333",
			"agents need it", "not reported",
		} {
			if !strings.Contains(out, want) && !strings.Contains(out, doc.EscapeMarkdown(want)) {
				t.Errorf("%s report lacks %q", f, want)
			}
		}
		// Only the accepted-risks table names a finding accepted in force.
		if n := strings.Count(out, "Accepted debugging port"); n != 1 {
			t.Errorf("%s report names a finding accepted in force %d times", f, n)
		}
		// Ledger items show redacted hints only, never where the secret sits.
		if strings.Contains(out, "~/src/shop/.env") {
			t.Errorf("%s report shows a ledger location", f)
		}
		if strings.Contains(out, "dddd4444") || strings.Contains(out, "eeee5555") {
			t.Errorf("%s report lists a snoozed or rotated item as open", f)
		}
	}
}

func TestHTMLIsSelfContainedAndEscaped(t *testing.T) {
	x := newFx(t)
	out := render(t, x.build(t), HTML)
	for _, bad := range []string{"<script", "<link", "src=", "@import", "Guest account <b>on</b>"} {
		if strings.Contains(out, bad) {
			t.Errorf("HTML contains %q", bad)
		}
	}
	for _, want := range []string{"Guest account &lt;b&gt;on&lt;/b&gt;", "prefers-color-scheme: dark", `name="viewport"`, `href="https://example.com/fix"`} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
}

func TestMarkdownEscapesTitles(t *testing.T) {
	x := newFx(t)
	out := render(t, x.build(t), Markdown)
	if strings.Contains(out, "<b>") || !strings.Contains(out, `Guest account \<b\>on\</b\>`) {
		t.Error("markdown does not escape a title's markup")
	}
}

func TestTopCapsEachConnector(t *testing.T) {
	x := newFx(t)
	r := x.build(t)
	r.Top = 1
	out := render(t, r, Text)
	if !strings.Contains(out, "… and 2 more in ") {
		t.Errorf("no cap note:\n%s", out)
	}
}

func TestCLIWritesPrivateFile(t *testing.T) {
	x := newFx(t)
	var stdout, stderr bytes.Buffer
	c := CLI{Out: &stdout, Err: &stderr, Paths: tracker.Paths{Tracker: x.tracker}, Now: func() time.Time { return now }}
	dest := filepath.Join(x.dir, "report.html")
	if err := os.WriteFile(dest, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := c.Run([]string{"--dir", x.out, "--format", "html", "--out", dest}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	st, err := os.Stat(dest)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("report not 0600: %v %v", err, st.Mode())
	}
	raw, _ := os.ReadFile(dest)
	if !strings.HasPrefix(string(raw), "<!doctype html>") {
		t.Error("not an HTML page")
	}
	for _, args := range [][]string{{"--format", "pdf"}, {"--min-severity", "urgent"}, {"--top", "0"}, {"extra"}} {
		if code := c.Run(append([]string{"--dir", x.out}, args...)); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	stdout.Reset()
	if code := c.Run([]string{"--dir", x.out}); code != 0 || !strings.HasPrefix(stdout.String(), "SEGURATA REPORT") {
		t.Errorf("text to stdout: exit %d", code)
	}
	if code := c.Run([]string{"--dir", filepath.Join(x.dir, "missing")}); code != 1 {
		t.Errorf("missing out dir: exit %d", code)
	}
}

// A status the config expects leaves "Needs attention" and is counted on one line with its reason.
func TestExpectedStatusesAreOneLine(t *testing.T) {
	x := newFx(t)
	tr := tracker.New(now) // synced in memory with the config's rules
	cfg := config.Config{Connectors: map[string]config.ConnectorConfig{"aws": {Expected: []config.Expected{
		{State: finding.StateMissingCredentials, Reason: "no AWS account on this Mac"}}}}}
	r, err := Build(Inputs{OutDir: x.out, Now: now, Tracker: tr, TrackerPath: x.tracker, MinSev: finding.SevLow, Top: 10, Sync: tracker.SyncOptions{Expect: cfg.Expect}})
	if err != nil {
		t.Fatal(err)
	}
	out := render(t, r, Text)
	if strings.Contains(out, "segurata inventory aws") || !strings.Contains(out, "1 expected (by your config): no AWS account on this Mac (1).") {
		t.Errorf("report:\n%s", out)
	}
	if !strings.Contains(out, "segurata inventory openrouter:work") {
		t.Error("a status no rule covers left the report")
	}
}

// With a synced tracker the report speaks in tracker items, as status does: the headline counts
// items (findings come second), setup blockers replace the runs' statuses, and the changes come
// from item history, not from diffing files.
func TestSyncedTrackerReportsItems(t *testing.T) {
	x := newFx(t)
	tr, err := tracker.Load(x.tracker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Sync(tracker.SyncOptions{OutDir: x.out}, now); err != nil {
		t.Fatal(err)
	}
	r, err := Build(Inputs{OutDir: x.out, Now: now.Add(time.Hour), Tracker: tr, TrackerPath: x.tracker, MinSev: finding.SevLow, Top: 10})
	if err != nil {
		t.Fatal(err)
	}
	out := render(t, r, Text)
	for _, want := range []string{"10 open: P0 4, P1 1, P2 3, P3 2.", "Findings in the latest runs: 1 critical, 1 high, 1 medium", "Findings by connector",
		"Setup blockers", "openrouter:work · org: needs a fresh sign-in", "Changes in the last 7 days", "Other items: 11 new, 1 reopened."} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	for _, gone := range []string{"Needs attention", "Changes since the previous run", "Gone (was high)"} {
		if strings.Contains(out, gone) {
			t.Errorf("report still has %q:\n%s", gone, out)
		}
	}
}
