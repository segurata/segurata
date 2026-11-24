package report

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/runtest"
	"github.com/segurata/segurata/internal/tracker"
)

func runsByLabel(t *testing.T, out string, tr *tracker.Tracker) (*Report, map[string]*Run) {
	t.Helper()
	r, err := Build(Inputs{OutDir: out, Now: now, Tracker: tr, MinSev: finding.SevLow, Top: 10})
	if err != nil {
		t.Fatal(err)
	}
	runs := map[string]*Run{}
	for _, run := range r.Runs {
		runs[run.Label] = run
	}
	return r, runs
}

// A finding missing from a run that did not inspect its scope is "not checked", never resolved.
func TestFindingsOfUninspectedScopesAreNotResolved(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	path := func(day, file string) string { return filepath.Join(out, day, file) }
	repo := func(name string) finding.Finding {
		f := mk("github", "", name, finding.SevHigh, name+": secret scanning is off")
		f.Account, f.Scope = "github:acme", "repo:acme/"+name
		f.Fill(now)
		return f
	}
	a, b := repo("a"), repo("b")
	ok := status("github", "", "github:acme", finding.StateOK, "")
	runtest.Write(t, path("2026-11-20", "github.jsonl"), a, b, ok)
	runtest.Write(t, path("2026-11-21", "github.jsonl"), ok, finding.Skipped{Scope: "repo:acme/b", Reason: "GitHub API rate limit ran low"})
	runtest.WriteUnfinished(t, path("2026-11-22", "github.jsonl"), ok) // killed

	// macos: a legacy previous run, then a latest run whose account errored.
	fw, port := mk("macos", "", "fw", finding.SevMedium, "Firewall off"), mk("macos", "", "port", finding.SevHigh, "Port 5000 open")
	runtest.WriteUnfinished(t, path("2026-11-20", "macos.jsonl"), fw, port)
	runtest.Write(t, path("2026-11-21", "macos.jsonl"), status("macos", "", "local", finding.StateError, "dscl failed"))

	// aws: only legacy runs.
	key := mk("aws", "", "key", finding.SevHigh, "Old access key")
	runtest.WriteUnfinished(t, path("2026-11-20", "aws.jsonl"), key)
	runtest.WriteUnfinished(t, path("2026-11-21", "aws.jsonl"), status("aws", "", "local", finding.StateOK, ""))

	tr := &tracker.Tracker{}
	if _, err := tr.AcceptFinding(b, "kept on purpose", "", now); err != nil {
		t.Fatal(err)
	}
	r, runs := runsByLabel(t, out, tr)
	gh := runs["github"]
	if gh.Date != "2026-11-21" || gh.PrevDate != "2026-11-20" || gh.Unfinished != "2026-11-22" {
		t.Fatalf("github run %s prev %s unfinished %s", gh.Date, gh.PrevDate, gh.Unfinished)
	}
	if got := ids(gh.Resolved); len(got) != 1 || got[0] != a.ID {
		t.Errorf("resolved %v, want only %s", got, a.ID)
	}
	if len(gh.NotChecked) != 1 || gh.NotChecked[0].ID != b.ID || !strings.Contains(gh.NotChecked[0].Reason, "rate limit") {
		t.Errorf("not checked %+v", gh.NotChecked)
	}
	if m := runs["macos"]; len(m.Resolved) != 0 || len(m.NotChecked) != 2 {
		t.Errorf("macos: a legacy previous run against an incomplete latest one resolves nothing: %+v", m)
	}
	if w := runs["aws"]; len(w.Resolved) != 0 || len(w.NotChecked) != 1 || w.Coverage.Known {
		t.Errorf("aws: a latest run without run_end resolves nothing: %+v", w)
	}
	for _, acc := range r.Accepted {
		if acc.ID == b.ID && acc.Gone {
			t.Error("an accepted finding in an uninspected scope is not 'no longer reported'")
		}
	}

	for _, f := range []Format{Text, Markdown, HTML} {
		out := render(t, r, f)
		for _, want := range []string{
			"Run completeness", "2026-11-21 (partial)", "2026-11-21 (no run_end)",
			"the run of 2026-11-22 did not finish", "repo:acme/b", "completeness unknown",
			"0 new, 1 resolved, 1 not checked this run", "Not checked this run (was high): b: secret scanning is off",
			"Gone (was high): a: secret scanning is off",
		} {
			if !strings.Contains(out, want) && !strings.Contains(out, doc.EscapeMarkdown(want)) {
				t.Errorf("%s report lacks %q", f, want)
			}
		}
		if strings.Contains(out, "Gone (was high): b") || strings.Contains(out, "Gone (was high): Port 5000 open") {
			t.Errorf("%s report lists an unchecked finding as resolved", f)
		}
	}
}
