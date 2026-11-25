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

// The report names the runs that are not complete and what they left out; an accepted finding in
// a scope the latest run did not inspect is not "no longer reported".
func TestRunCompletenessAndUninspectedScopes(t *testing.T) {
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

	tr := tracker.New(now)
	if _, err := tr.AcceptFinding(b, "kept on purpose", "", now); err != nil {
		t.Fatal(err)
	}
	r, runs := runsByLabel(t, out, tr)
	if gh := runs["github"]; gh.Date != "2026-11-21" || gh.Unfinished != "2026-11-22" {
		t.Fatalf("github run %s unfinished %s", gh.Date, gh.Unfinished)
	}
	if w := runs["aws"]; w.Coverage.Known {
		t.Errorf("aws: a latest run without run_end has unknown coverage: %+v", w)
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
		} {
			if !strings.Contains(out, want) && !strings.Contains(out, doc.EscapeMarkdown(want)) {
				t.Errorf("%s report lacks %q", f, want)
			}
		}
	}
}
