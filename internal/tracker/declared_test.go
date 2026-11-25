package tracker

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

// A connector the tracker knows nothing about groups, kinds and titles its items as its findings
// declare, and files them under the theme its run declares.
func TestDeclaredGroupingThemeAndTitles(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	mk := func(check, project, uid string, sev finding.Severity) finding.Finding {
		f := fnd("scanner", "", "me@x.com", "scan_check", check+":"+project+":"+uid, uid, sev, check+" on "+uid, now)
		f.Scope = project
		f.Track = &finding.Track{Group: finding.GroupCheck, Key: check, Kind: finding.TrackReview, Count: finding.CountScopes,
			Noun: "project", Nouns: "projects", Title: check + " fails in {count}", TitleOne: check + " fails in " + project}
		return f
	}
	out := t.TempDir()
	theme := finding.Theme{ID: "scans", Title: "Scans", Description: "What the scanner found."}
	writeRun(t, out, now, "scanner.jsonl", mk("c1", "p1", "a", finding.SevHigh), mk("c1", "p2", "b", finding.SevLow),
		mk("c2", "p1", "a", finding.SevMedium), mk("c2", "p1", "b", finding.SevMedium), theme)
	tr := New(now)
	syncOrDie(t, tr, out, now)
	many, one := tr.ByKey("group:scanner|scan_check|check:c1"), tr.ByKey("group:scanner|scan_check|check:c2")
	if many == nil || one == nil {
		t.Fatalf("items: %+v", tr.Items)
	}
	if many.Title != "c1 fails in 2 projects (1 high, 1 low)" || one.Title != "c2 fails in p1" {
		t.Fatalf("titles %q, %q", many.Title, one.Title)
	}
	if many.Kind != KindReview || many.Theme != "scans" || tr.ThemeTitle("scans") != "Scans" {
		t.Fatalf("kind %s theme %s (%q)", many.Kind, many.Theme, tr.ThemeTitle("scans"))
	}
	// A finding accepted apart from its group keeps the group's theme.
	it, err := tr.AcceptFinding(mk("c1", "p1", "a", finding.SevHigh), "sandbox", "", now)
	if err != nil || it.Theme != "scans" {
		t.Fatalf("accepted %+v %v", it, err)
	}
}

// Findings of a run written before their connector declared how to group them stay in the items
// that hold them, under the titles they have; a run that declares it regroups them.
func TestUndeclaredFindingsStayInTheirItems(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	a := fnd("scanner", "", "acct", "scan_check", "a", "a", finding.SevHigh, "Check one failed on a", now)
	b := fnd("scanner", "", "acct", "scan_check", "b", "b", finding.SevHigh, "Check two failed on b", now)
	tr := New(now)
	old := &Item{Key: "group:scanner|scan_check|check:x", Title: "Checks that failed", Kind: KindFix, Status: Open,
		Findings: []FindingRef{refOf(a), refOf(b)}}
	tr.Items = append(tr.Items, old)
	out := filepath.Join(t.TempDir(), "out")
	writeRun(t, out, now, "scanner.jsonl", a, b)
	if rep := syncOrDie(t, tr, out, now); rep.Created != 0 || old.Title != "Checks that failed" || old.Status != Open {
		t.Fatalf("created %d, item %+v", rep.Created, old)
	}
	later := now.Add(time.Hour)
	a.Track, b.Track = &finding.Track{Group: finding.GroupFinding}, &finding.Track{Group: finding.GroupFinding}
	a.ObservedAt, b.ObservedAt = later, later
	writeRun(t, out, later, "scanner.jsonl", a, b)
	if rep := syncOrDie(t, tr, out, later); rep.Created != 2 || old.Status != Done {
		t.Fatalf("created %d, old item %s", rep.Created, old.Status)
	}
}
