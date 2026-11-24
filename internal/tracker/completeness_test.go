package tracker

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/runtest"
)

func scoped(f finding.Finding, scope string) finding.Finding {
	f.Scope = scope
	return f
}

func status(connector, account, scope string, st finding.State, detail string) finding.Status {
	return finding.Status{Type: "status", Connector: connector, Account: account, Scope: scope, State: st, Detail: detail}
}

func notes(it *Item) []string {
	var out []string
	for _, e := range it.History {
		if e.Action == actNotChecked {
			out = append(out, e.Detail)
		}
	}
	return out
}

// Each case: a first run reports two findings, kept and dropped; a second run reports neither.
// dropped vanished from a scope the second run inspected, so its item is verified done; kept
// vanished from a scope it did not inspect, so its item stays open with one "not checked" note.
func TestSyncNeverClosesWhatARunDidNotInspect(t *testing.T) {
	day1, day2 := t0, t0.AddDate(0, 0, 1)
	type pair struct{ kept, dropped finding.Finding }
	repo := func(owner, name string) finding.Finding {
		return scoped(fnd("github", "", "github:"+owner, "github_repo", owner+"/"+name, owner+"/"+name, finding.SevMedium, owner+"/"+name+": secret scanning is off", day1), "repo:"+owner+"/"+name)
	}
	dump := func(repo string) finding.Finding {
		return scoped(fnd(SecretsConnector, "", "local", "data_dump", repo+":db.sql", "db.sql", finding.SevHigh, "Database dump committed to "+repo, day1), repo)
	}
	gcpKey := func(project string) finding.Finding {
		f := fnd("gcp", "", "me@x.com", "api_key", project+"/k", "k", finding.SevHigh, "API key k in "+project+" has no API restrictions", day1)
		f.Evidence = map[string]any{"project": project}
		return scoped(f, project)
	}
	app := func(service, who, name string) finding.Finding {
		return scoped(fnd("connected-apps", "", service+":"+who, service+"_app", service+":"+name, name, finding.SevHigh, name+" can read your account", day1), service)
	}
	mac := func(id, title string) finding.Finding {
		return fnd("macos", "", "Mac", "macos_setting", id, id, finding.SevMedium, title, day1)
	}
	cases := []struct {
		name   string
		file   string
		first  pair
		second []any // records of the second run besides an ok status
		reason string
	}{
		{"github repositories left by the rate limit", "github.jsonl", pair{repo("globex", "b"), repo("acme", "a")},
			[]any{okStatus("github", "github:me"), okStatus("github", "github:acme"), okStatus("github", "github:globex"),
				finding.Skipped{Scope: "repo:globex/b", Reason: "GitHub API rate limit ran low"}},
			"repo:globex/b: GitHub API rate limit ran low"},
		{"gitleaks timed out on one repository", "local-secrets.jsonl", pair{dump("~/src/slow"), dump("~/src/fast")},
			[]any{okStatus(SecretsConnector, "local"), status(SecretsConnector, "~/src/slow", "", finding.StateError, "gitleaks: timed out after 2m0s")},
			"~/src/slow: error: gitleaks: timed out after 2m0s"},
		{"gcp project with permission denied", "gcp.jsonl", pair{gcpKey("locked"), gcpKey("open")},
			[]any{okStatus("gcp", "me@x.com"), status("gcp", "me@x.com", "locked", finding.StateError, "project locked: permission denied for api keys")},
			"locked: error: project locked: permission denied for api keys"},
		{"signed-out service", "connected-apps.jsonl", pair{app("x", "@me", "Klout"), app("github", "me", "Travis")},
			[]any{okStatus("connected-apps", "github:me"), status("connected-apps", "x", "", finding.StateSignedOut, "not signed in to X in the browser")},
			"x: signedout: not signed in to X in the browser"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			writeRun(t, out, day1, c.file, c.first.kept, c.first.dropped, okStatus(c.first.kept.Connector, "any"))
			tr := &Tracker{}
			syncOrDie(t, tr, out, day1)
			writeRun(t, out, day2, c.file, c.second...)
			for range 2 { // a second sync of the same run adds no second note
				syncOrDie(t, tr, out, day2.Add(time.Hour))
			}
			kept, dropped := tr.withFinding(c.first.kept.ID), tr.withFinding(c.first.dropped.ID)
			if kept == nil || dropped == nil || kept == dropped {
				t.Fatalf("items %v %v", kept, dropped)
			}
			if dropped.Status != Done || dropped.VerifiedAt == nil {
				t.Errorf("inspected and gone, so verified done: %+v", dropped)
			}
			if kept.Status != Open || kept.Findings[0].Gone {
				t.Errorf("not inspected, so still open: %+v", kept)
			}
			n := notes(kept)
			if len(n) != 1 || !strings.Contains(n[0], c.reason) || !strings.Contains(n[0], "not checked in run "+c.first.kept.Connector) {
				t.Errorf("notes %q, want one with %q", n, c.reason)
			}
		})
	}

	// Runs that prove nothing gone: they close nothing and note why once.
	whole := []struct {
		name   string
		write  func(t *testing.T, out string)
		reason string
	}{
		{"connector failed at start", func(t *testing.T, out string) {
			writeRun(t, out, day2, "macos.jsonl", errors.New("cannot reach the browser"))
		}, "cannot reach the browser"},
		{"no account inspected", func(t *testing.T, out string) {
			writeRun(t, out, day2, "macos.jsonl", status("macos", "Mac", "", finding.StateError, "dscl failed"))
		}, "Mac: error: dscl failed"},
		{"latest file without run_end, no finished run", func(t *testing.T, out string) {
			runtest.WriteUnfinished(t, filepath.Join(out, day2.Format(time.DateOnly), "macos.jsonl"), okStatus("macos", "Mac"))
		}, "no run_end record"},
	}
	for _, c := range whole {
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			fw := mac("firewall-off", "The firewall is off")
			// A legacy first run: findings written before run_end records.
			runtest.WriteUnfinished(t, filepath.Join(out, day1.Format(time.DateOnly), "macos.jsonl"), fw, okStatus("macos", "Mac"))
			tr := &Tracker{}
			syncOrDie(t, tr, out, day1)
			it := tr.withFinding(fw.ID)
			it.Done(day1.Add(time.Hour), "turned it on")
			done := tr.withFinding(fw.ID)
			c.write(t, out)
			syncOrDie(t, tr, out, day2.Add(time.Hour))
			syncOrDie(t, tr, out, day2.Add(2*time.Hour))
			if done.Status != Done || done.VerifiedAt != nil || done.Findings[0].Gone {
				t.Errorf("verified by a run that proves nothing: %+v", done)
			}
			if n := notes(done); len(n) != 1 || !strings.Contains(n[0], c.reason) {
				t.Errorf("notes %q, want one with %q", n, c.reason)
			}
		})
	}
}

// A run killed after a finished one: sync keeps reading the finished one.
func TestSyncPassesOverAKilledRun(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	day1, day2 := t0, t0.AddDate(0, 0, 1)
	fw := fnd("macos", "", "Mac", "macos_setting", "firewall-off", "firewall-off", finding.SevMedium, "The firewall is off", day1)
	writeRun(t, out, day1, "macos.jsonl", fw, okStatus("macos", "Mac"))
	tr := &Tracker{}
	syncOrDie(t, tr, out, day1)
	runtest.WriteUnfinished(t, filepath.Join(out, day2.Format(time.DateOnly), "macos.jsonl"), okStatus("macos", "Mac"))
	rep := syncOrDie(t, tr, out, day2)
	it := tr.withFinding(fw.ID)
	if it.Status != Open || it.Findings[0].Gone || rep.Verified != 0 || len(notes(it)) != 0 {
		t.Fatalf("a killed run closed or noted an item: %+v %+v", it, rep)
	}
}

// Refs recorded before scopes existed carry no scope: any skipped scope holds them.
func TestRefsWithoutScopeNeedACompleteRun(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	day1, day2 := t0, t0.AddDate(0, 0, 1)
	key := fnd("gcp", "", "me@x.com", "api_key", "p/k", "k", finding.SevHigh, "API key k has no API restrictions", day1)
	key.Evidence = map[string]any{"project": "p"}
	writeRun(t, out, day1, "gcp.jsonl", key, okStatus("gcp", "me@x.com"))
	tr := &Tracker{}
	syncOrDie(t, tr, out, day1)
	it := tr.withFinding(key.ID)
	it.Findings[0].Scope = "" // as an older segurata wrote it
	writeRun(t, out, day2, "gcp.jsonl", okStatus("gcp", "me@x.com"), status("gcp", "me@x.com", "other", finding.StateError, "permission denied"))
	syncOrDie(t, tr, out, day2)
	if it.Status != Open || it.Findings[0].Gone {
		t.Fatalf("a ref of unknown scope closed by a partial run: %+v", it)
	}
	day3 := t0.AddDate(0, 0, 2)
	writeRun(t, out, day3, "gcp.jsonl", okStatus("gcp", "me@x.com"))
	syncOrDie(t, tr, out, day3)
	if it.Status != Done {
		t.Fatalf("a complete run proves it gone: %+v", it)
	}
}
