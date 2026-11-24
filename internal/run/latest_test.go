package run

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/runtest"
)

func TestLatestRunsPreferFinishedRuns(t *testing.T) {
	out := t.TempDir()
	path := func(day, name string) string { return filepath.Join(out, day, name) }
	f := func(id string) finding.Finding { return finding.Finding{Type: "finding", Connector: "github", ID: id} }
	runtest.Write(t, path("2026-11-20", "github.jsonl"), f("a"))
	runtest.WriteUnfinished(t, path("2026-11-21", "github.jsonl"), f("a")) // killed
	runtest.Write(t, path("2026-11-22", "github.jsonl"), f("b"))
	runtest.WriteUnfinished(t, path("2026-11-23", "github.jsonl"), f("c"))
	// killed mid-record: the last line is cut short
	torn := path("2026-11-23", "github.jsonl")
	raw, _ := os.ReadFile(torn)
	if err := os.WriteFile(torn, append(raw, []byte(`{"type":"finding","id":"d`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	runtest.WriteUnfinished(t, path("2026-11-21", "macos.jsonl"), f("m1")) // legacy only
	runtest.WriteUnfinished(t, path("2026-11-22", "macos.jsonl"), f("m2"))

	runs, err := LatestRuns(out, time.Now())
	if err != nil || len(runs) != 2 {
		t.Fatalf("runs %+v err %v", runs, err)
	}
	gh, mac := runs[0], runs[1]
	if gh.File != path("2026-11-22", "github.jsonl") || gh.Prev != path("2026-11-20", "github.jsonl") || gh.Unfinished != torn {
		t.Fatalf("github: %+v", gh)
	}
	if mac.File != path("2026-11-22", "macos.jsonl") || mac.Prev != path("2026-11-21", "macos.jsonl") || mac.Unfinished != "" {
		t.Fatalf("legacy runs: newest file, %+v", mac)
	}

	rf, err := Read(torn)
	if err != nil || len(rf.Findings) != 1 || rf.End != nil || rf.Coverage().Known {
		t.Fatalf("a torn last line of an unfinished run is dropped: %+v %v", rf, err)
	}
	if _, none := rf.Coverage().NoneChecked(); !none {
		t.Fatal("an unfinished run proves nothing gone")
	}
	done, err := Read(gh.File)
	if err != nil || done.End == nil || !done.Coverage().Complete() {
		t.Fatalf("finished run: %+v %v", done, err)
	}
	middle := path("2026-11-24", "github.jsonl")
	runtest.WriteUnfinished(t, middle, f("x"))
	raw, _ = os.ReadFile(middle)
	_ = os.WriteFile(middle, append([]byte("{not json\n"), raw...), 0o600)
	if _, err := Read(middle); err == nil {
		t.Fatal("a broken line before the last one is an error, not a torn tail")
	}
}

// A date directory after the day of now (a clock set wrong once) never stands in for the latest run.
func TestHistorySkipsDaysAfterToday(t *testing.T) {
	out := t.TempDir()
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.Local)
	today := filepath.Join(out, "2026-11-24", "github.jsonl")
	runtest.Write(t, today, finding.Finding{Type: "finding", Connector: "github", ID: "a"})
	runtest.Write(t, filepath.Join(out, "2026-11-25", "github.jsonl"), finding.Finding{Type: "finding", Connector: "github", ID: "b"})
	h, err := History(out, now)
	if err != nil || len(h["github.jsonl"]) != 1 || h["github.jsonl"][0] != today {
		t.Fatalf("history %v, %v", h, err)
	}
}

// Prune removes run files older than the cutoff that no latest run needs, and nothing else: a
// connector that has not run for months keeps its last finished run and the one before it.
func TestPruneKeepsWhatLatestRunsNeed(t *testing.T) {
	out := t.TempDir()
	path := func(day, name string) string { return filepath.Join(out, day, name) }
	f := func(c string) finding.Finding { return finding.Finding{Type: "finding", Connector: c, ID: "x"} }
	runtest.Write(t, path("2026-01-01", "github.jsonl"), f("github"))
	runtest.Write(t, path("2026-01-02", "github.jsonl"), f("github"))
	runtest.Write(t, path("2026-11-20", "github.jsonl"), f("github"))
	runtest.Write(t, path("2026-11-21", "github.jsonl"), f("github"))
	runtest.Write(t, path("2026-01-01", "macos.jsonl"), f("macos")) // gone quiet: prev of the next
	runtest.Write(t, path("2026-01-02", "macos.jsonl"), f("macos")) // and its latest
	partial := path("2026-01-02", "github.jsonl.123.partial")
	other := path("2026-01-01", "notes.txt")
	for _, p := range []string{partial, other} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := Prune(out, time.Date(2026, 11, 24, 0, 0, 0, 0, time.Local), time.Date(2026, 11, 1, 0, 0, 0, 0, time.Local))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{path("2026-01-01", "github.jsonl"), path("2026-01-02", "github.jsonl"), partial}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed %v, want %v", removed, want)
	}
	for _, p := range append(want[:2:2], partial) {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still there", p)
		}
	}
	for _, p := range []string{other, path("2026-01-01", "macos.jsonl"), path("2026-01-02", "macos.jsonl"), path("2026-11-20", "github.jsonl")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s removed: %v", p, err)
		}
	}
}

func TestLatestFilesTakeEachConnectorsNewestRun(t *testing.T) {
	out := t.TempDir()
	write := func(day, name string, recs ...any) { runtest.Write(t, filepath.Join(out, day, name), recs...) }
	_ = os.MkdirAll(filepath.Join(out, "notes"), 0o700)
	_ = os.WriteFile(filepath.Join(out, "2026-12-31.jsonl"), nil, 0o600) // a file, not a run directory
	write("2026-11-01", "macos.jsonl", finding.Finding{Type: "finding", ID: "old00000"})
	write("2026-11-23", "macos.jsonl",
		finding.Status{Type: "status", Connector: "macos", State: finding.StateOK},
		finding.Finding{Type: "finding", ID: "aaaa1111", Severity: finding.SevLow, Remediation: finding.Remediation{Action: "x.y"}},
		finding.Finding{Type: "finding", ID: "aaaa2222", Severity: finding.SevHigh},
		finding.Finding{Type: "finding", ID: "bbbb3333", Severity: finding.SevHigh, Remediation: finding.Remediation{Action: "x.z"}})
	// After midnight only another connector ran: macos must still come from 2026-11-23.
	write("2026-11-24", "local-secrets.jsonl", finding.Finding{Type: "finding", ID: "cccc4444"})

	files, err := LatestFiles(out, time.Now())
	if err != nil || len(files) != 2 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	all, err := Load(files)
	if err != nil || len(all) != 4 {
		t.Fatalf("loaded %d err=%v", len(all), err)
	}
	if _, err := Find(all, "old00000"); err == nil {
		t.Fatal("an older run of the same connector must be ignored")
	}
	if f, err := Find(all, "bbbb"); err != nil || f.ID != "bbbb3333" {
		t.Fatalf("unique prefix from the previous day: %v %v", f.ID, err)
	}
	if _, err := Find(all, "cccc4444"); err != nil {
		t.Fatal("today's connector must be found too")
	}
	if _, err := Find(all, "aaaa"); err == nil {
		t.Fatal("ambiguous prefix accepted")
	}
	if _, err := LatestFiles(t.TempDir(), time.Now()); err == nil {
		t.Fatal("empty out dir should explain how to run an inventory")
	}
}
