package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/doc"

	"github.com/segurata/segurata/internal/accept"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/rotation"
	"github.com/segurata/segurata/internal/secretrisk"
)

var now = time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)

// fx is a synthetic out/ tree with two runs of macos, a first run of aws and a labelled
// openrouter instance, plus an accepted-risks file and a rotation ledger.
type fx struct {
	dir                                   string
	out, accepted, ledger                 string
	a, b, c, d, e, f                      finding.Finding
	ledgerPath                            string
	p0, p1, dueSnooze, laterSnooze, done_ *rotation.Item
}

func mk(connector, instance, resID string, sev finding.Severity, title string) finding.Finding {
	f := finding.Finding{Connector: connector, Instance: instance, Account: "local", Kind: finding.KindSetting,
		Resource: finding.Resource{Type: "t", ID: resID}, Severity: sev, Title: title,
		Remediation: finding.Remediation{Summary: "Fix " + title + ".", URL: "https://example.com/fix"}}
	f.Fill(now)
	return f
}

func writeRun(t *testing.T, path string, recs ...any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range recs {
		_ = enc.Encode(r)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

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

	x.accepted = filepath.Join(x.dir, "accepted.json")
	acc := &accept.Store{Version: 1, Entries: []*accept.Entry{
		{ID: x.a.ID, Connector: "macos", Title: x.a.Title, Reason: "agents need it", AcceptedAt: now.AddDate(0, -1, 0)},
		{ID: x.c.ID, Connector: "macos", Title: x.c.Title, Reason: "kids", AcceptedAt: now.AddDate(0, -2, 0), Until: "2026-11-01"},
		{ID: "ffffffffffffffff", Connector: "macos", Title: "Something fixed since", Reason: "old", AcceptedAt: now.AddDate(0, -3, 0)},
	}}
	if err := acc.Save(x.accepted); err != nil {
		t.Fatal(err)
	}

	x.ledgerPath = filepath.Join(x.dir, "state", "rotations.json")
	loc := []rotation.Location{{Path: "~/src/shop/.env", Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, LastSeen: now}}
	item := func(id string, p secretrisk.Priority, st rotation.Status, until string) *rotation.Item {
		return &rotation.Item{ID: id, Fingerprint: id + "00000000", Service: "stripe", Type: "stripe-live", Redacted: "sk_live_…" + id[:4] + "(40)",
			Impact: "high", Priority: p, Reasons: []string{"Stripe live secret key; pushed to a remote"}, Status: st, SnoozedUntil: until,
			FirstSeen: now.AddDate(0, 0, -3), LastSeen: now, Locations: loc, RotateURL: "https://dashboard.stripe.com/apikeys"}
	}
	x.p0 = item("aaaa1111", secretrisk.P0, rotation.Open, "")
	x.dueSnooze = item("cccc3333", secretrisk.P2, rotation.Snoozed, "2026-11-01")
	l := &rotation.Ledger{Version: 1, Items: []*rotation.Item{x.p0, item("bbbb2222", secretrisk.P1, rotation.Open, ""), x.dueSnooze,
		item("dddd4444", secretrisk.P0, rotation.Snoozed, "2027-01-01"), item("eeee5555", secretrisk.P0, rotation.Rotated, "")}}
	if err := l.Save(x.ledgerPath); err != nil {
		t.Fatal(err)
	}
	return x
}

func (x *fx) build(t *testing.T) *Report {
	t.Helper()
	acc, err := accept.Load(x.accepted)
	if err != nil {
		t.Fatal(err)
	}
	led, err := rotation.Load(x.ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Build(Inputs{OutDir: x.out, Now: now, Accepted: acc, Ledger: led, LedgerPath: x.ledgerPath, MinSev: finding.SevLow, Top: 10})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ids(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func TestBuildDiffsEachInstanceAgainstItsPreviousRun(t *testing.T) {
	x := newFx(t)
	r := x.build(t)
	var labels []string
	runs := map[string]*Run{}
	for _, run := range r.Runs {
		labels = append(labels, run.Label)
		runs[run.Label] = run
	}
	if strings.Join(labels, ",") != "aws,macos,openrouter:work" {
		t.Fatalf("runs %v", labels)
	}
	m := runs["macos"]
	if m.Date != "2026-11-21" || m.PrevDate != "2026-11-20" {
		t.Fatalf("macos dates %s vs %s", m.Date, m.PrevDate)
	}
	if got := ids(m.New); len(got) != 1 || got[0] != x.e.ID {
		t.Errorf("new %v", got)
	}
	if got := ids(m.Resolved); len(got) != 1 || got[0] != x.d.ID {
		t.Errorf("resolved %v", got)
	}
	if len(m.Changed) != 1 || m.Changed[0].ID != x.b.ID || m.Changed[0].From != finding.SevMedium || m.Changed[0].Severity != finding.SevCritical {
		t.Errorf("changed %+v", m.Changed)
	}
	if runs["aws"].PrevDate != "" || runs["openrouter:work"].PrevDate != "" {
		t.Error("first runs compared with something")
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
	if state[x.a.ID] != "in force" || state[x.c.ID] != "expired" || state["ffffffffffffffff"] != "in force, gone" {
		t.Errorf("accepted %v", state)
	}
	s := r.Rotations
	if s.Total != 5 || s.Open[secretrisk.P0] != 1 || s.Open[secretrisk.P1] != 1 || s.Open[secretrisk.P2] != 1 {
		t.Errorf("open %v of %d", s.Open, s.Total)
	}
	if len(s.TopP0) != 1 || s.TopP0[0].ID != x.p0.ID {
		t.Errorf("top P0 %v", s.TopP0)
	}
	if len(s.SnoozesDue) != 1 || s.SnoozesDue[0].ID != x.dueSnooze.ID {
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
			"securizame remediate " + x.f.ID, // automatable
			"reauth", "missing_credentials", "securizame inventory aws", "securizame inventory openrouter:work",
			"Was medium", "Firewall off", // severity change
			"Gone (was high)", "Port 5000 open", // resolved
			"New login item",
			"acceptance expired",
			"1 accepted findings hidden",
			"sk_live_…aaaa(40)", "P0 1, P1 1, P2 1, P3 0", "Snoozes due", "cccc3333",
			"First run, nothing to compare: aws, openrouter:work",
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
	c := CLI{Out: &stdout, Err: &stderr, AcceptedPath: x.accepted, LedgerPath: x.ledgerPath, Now: func() time.Time { return now }}
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
	if code := c.Run([]string{"--dir", x.out}); code != 0 || !strings.HasPrefix(stdout.String(), "SECURIZAME REPORT") {
		t.Errorf("text to stdout: exit %d", code)
	}
	if code := c.Run([]string{"--dir", filepath.Join(x.dir, "missing")}); code != 1 {
		t.Errorf("missing out dir: exit %d", code)
	}
}

func TestStatusActionPrefersTheConnectorsOwnFix(t *testing.T) {
	cases := []struct {
		st   finding.Status
		want string
	}{
		{finding.Status{State: finding.StateReauth, Detail: "projects list: credentials expired: run gcloud auth login for this account"}, "Do what the detail above says."},
		{finding.Status{State: finding.StateNoScope, Detail: "gh lacks the admin:gpg_key scope; run: gh auth refresh -h github.com -s admin:gpg_key"}, "Do what the detail above says."},
		{finding.Status{State: finding.StateNoScope, Detail: "the token lacks a permission"}, "Grant the permission the detail names to the credential this connector uses."},
	}
	for _, c := range cases {
		if got, _ := statusAction(c.st, "x"); got != c.want {
			t.Errorf("%s %q: got %q", c.st.State, c.st.Detail, got)
		}
	}
	// A reauth without a fix must not assume a browser connector.
	if got, _ := statusAction(finding.Status{State: finding.StateReauth, Detail: "InvalidClientTokenId"}, "aws"); strings.Contains(got, "drives over CDP") {
		t.Errorf("aws reauth should not point to the browser only: %q", got)
	}
}
