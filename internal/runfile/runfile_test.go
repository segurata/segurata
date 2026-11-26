package runfile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/runtest"
)

func TestHistoryKeepsLegacyAndNewInstancesSeparate(t *testing.T) {
	out := t.TempDir()
	path := func(date, name string) string { return filepath.Join(out, date, name) }
	finished := path("2026-11-20", "github-work.jsonl")
	unfinished := path("2026-11-21", "github-work.jsonl")
	earlierThatDay := path("2026-11-22", "github-work.jsonl")
	current := path("2026-11-22", FileName("github:work"))
	plugin := path("2026-11-22", FileName("github-work"))
	otherCase := path("2026-11-22", FileName("github:Work"))
	status := finding.Status{Type: "status", Connector: "github", Instance: "work", State: finding.StateOK}
	runtest.Write(t, finished, status)
	runtest.WriteUnfinished(t, unfinished, status)
	observation := finding.Finding{Type: "finding", Connector: "github", Instance: "work", ObservedAt: time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)}
	runtest.Write(t, earlierThatDay, observation)
	observation.ObservedAt = observation.ObservedAt.Add(time.Hour)
	runtest.Write(t, current, observation)
	laterMtime := observation.ObservedAt.Add(time.Hour)
	if err := os.Chtimes(earlierThatDay, laterMtime, laterMtime); err != nil {
		t.Fatal(err)
	}
	runtest.Write(t, plugin, finding.Status{Type: "status", Connector: "github-work", State: finding.StateOK})
	status.Instance = "Work"
	runtest.Write(t, otherCase, status)

	h, err := History(out, time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h["github:work"], []string{finished, unfinished, earlierThatDay, current}) ||
		!slices.Equal(h["github-work"], []string{plugin}) || !slices.Equal(h["github:Work"], []string{otherCase}) {
		t.Fatalf("unexpected histories: %v", h)
	}
	latest, err := pick(h["github:work"])
	if err != nil || latest.File != current || latest.Prev != earlierThatDay {
		t.Fatalf("latest: %+v, %v", latest, err)
	}
	if strings.EqualFold(current, otherCase) {
		t.Fatal("case-insensitive filesystems would merge two instances")
	}
}

// A legacy dash-joined file a killed run left empty, or torn in its first line, names no
// instance: it joins the one instance its name spells, and is left out, and pruned once old, when
// none does.
func TestAnEmptyLegacyFileJoinsTheInstanceItsNameSpells(t *testing.T) {
	out := t.TempDir()
	path := func(date, name string) string { return filepath.Join(out, date, name) }
	empty, torn, stray := path("2026-11-01", "github-work.jsonl"), path("2026-11-02", "github-work.jsonl"), path("2026-11-01", "gcp-old.jsonl")
	for p, body := range map[string]string{empty: "", torn: `{"type":"find`, stray: ""} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	current := path("2026-11-25", FileName("github:work"))
	runtest.Write(t, current, finding.Status{Type: "status", Connector: "github", Instance: "work", State: finding.StateOK})
	now := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	h, err := History(out, now)
	if err != nil || len(h) != 1 || !slices.Equal(h["github:work"], []string{empty, torn, current}) {
		t.Fatalf("history %v, %v", h, err)
	}
	removed, err := Prune(out, now, now.AddDate(0, 0, -7))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(removed)
	if want := []string{stray, empty}; !slices.Equal(removed, want) {
		t.Fatalf("pruned %v, want %v", removed, want)
	}
}

func TestHistoryFindsAnInstanceWithALongLabel(t *testing.T) {
	out := t.TempDir()
	label := strings.Repeat("Aa", 100)
	path := filepath.Join(out, "2026-11-22", FileName("github:"+label))
	runtest.Write(t, path, finding.Status{Type: "status", Connector: "github", Instance: label, State: finding.StateOK})
	h, err := History(out, time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC))
	if err != nil || !slices.Equal(h["github:"+label], []string{path}) {
		t.Fatalf("long instance history: %v, %v", h, err)
	}
}

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
	if err != nil || len(h["github"]) != 1 || h["github"][0] != today {
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

// A run that inspected nothing (the browser was not reachable, the connector failed) is still the
// latest, but Evidence names the newest finished run that inspected something; nothing when the
// latest is that run, or when no finished run did.
func TestLatestRunsNameTheNewestRunThatInspectedSomething(t *testing.T) {
	out := t.TempDir()
	path := func(day, name string) string { return filepath.Join(out, day, name) }
	skip := errors.New("browser not reachable over CDP")
	f := finding.Finding{Type: "finding", Connector: "google-personal", ID: "a"}
	runtest.Write(t, path("2026-11-01", "google-personal.jsonl"), f)
	runtest.Write(t, path("2026-11-20", "google-personal.jsonl"), skip)
	runtest.Write(t, path("2026-11-21", "google-personal.jsonl"), skip)
	runtest.Write(t, path("2026-11-21", "macos.jsonl"), finding.Finding{Type: "finding", Connector: "macos", ID: "m"})
	runtest.Write(t, path("2026-11-21", "hibp.jsonl"), skip) // never inspected anything
	runtest.WriteUnfinished(t, path("2026-11-21", "aws.jsonl"), finding.Finding{Type: "finding", Connector: "aws", ID: "k"})

	runs, err := LatestRuns(out, time.Date(2026, 11, 24, 0, 0, 0, 0, time.Local))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Latest{}
	for _, l := range runs {
		got[filepath.Base(l.File)] = l
	}
	if g := got["google-personal.jsonl"]; g.File != path("2026-11-21", "google-personal.jsonl") ||
		g.Prev != path("2026-11-20", "google-personal.jsonl") || g.Evidence != path("2026-11-01", "google-personal.jsonl") {
		t.Fatalf("google-personal: %+v", g)
	}
	for _, name := range []string{"macos.jsonl", "hibp.jsonl", "aws.jsonl"} {
		if e := got[name].Evidence; e != "" {
			t.Errorf("%s: evidence %s", name, e)
		}
	}
}

// Weeks of skipped runs never prune the last run that inspected something.
func TestPruneKeepsTheLastRunThatInspectedSomething(t *testing.T) {
	out := t.TempDir()
	path := func(day string) string { return filepath.Join(out, day, "google-personal.jsonl") }
	skip := errors.New("browser not reachable over CDP")
	runtest.Write(t, path("2026-01-01"), finding.Finding{Type: "finding", Connector: "google-personal", ID: "a"})
	for _, day := range []string{"2026-01-02", "2026-01-03", "2026-11-20", "2026-11-21"} {
		runtest.Write(t, path(day), skip)
	}
	removed, err := Prune(out, time.Date(2026, 11, 24, 0, 0, 0, 0, time.Local), time.Date(2026, 11, 1, 0, 0, 0, 0, time.Local))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{path("2026-01-02"), path("2026-01-03")}; !slices.Equal(removed, want) {
		t.Fatalf("removed %v, want %v", removed, want)
	}
	if _, err := os.Stat(path("2026-01-01")); err != nil {
		t.Fatalf("pruned the last run that inspected something: %v", err)
	}
}

// A line torn by a kill can only be the last one of a run without run_end; anywhere else the file
// is corrupt. Records name the instance, the file name only when there is none.
func TestReadDropsOnlyATornLastLineAndLabelsFromRecords(t *testing.T) {
	dir := t.TempDir()
	st := finding.Status{Type: "status", Connector: "github", Instance: "work", Account: "a", State: finding.StateOK}
	f := finding.Finding{Type: "finding", ID: "abcdef12", Connector: "openrouter", Instance: "home"}
	torn := filepath.Join(dir, "torn.jsonl")
	runtest.WriteUnfinished(t, torn, st)
	appendTo(t, torn, `{"type":"finding","conn`)
	r, err := Read(torn)
	if err != nil || len(r.Statuses) != 1 || r.End != nil || r.Label(torn) != "github:work" {
		t.Fatalf("torn last line: %+v %v", r, err)
	}
	middle := filepath.Join(dir, "middle.jsonl")
	runtest.WriteUnfinished(t, middle, st)
	appendTo(t, middle, "{\n"+`{"type":"status"}`)
	if _, err := Read(middle); err == nil {
		t.Error("a torn line before another record was dropped")
	}
	ended := filepath.Join(dir, "ended.jsonl")
	runtest.WriteUnfinished(t, ended, json.RawMessage(`{"type":"run_end","connector":"aws"}`))
	if r, err := Read(ended); err != nil || r.End == nil {
		t.Fatalf("run_end not read: %+v %v", r, err)
	}
	appendTo(t, ended, "{")
	if _, err := Read(ended); err == nil {
		t.Error("a torn line after run_end was dropped")
	}

	for _, c := range []struct {
		recs []any
		want string
	}{
		{[]any{f, st}, "openrouter:home"},
		{[]any{st}, "github:work"},
		{nil, "github-x"},
	} {
		p := filepath.Join(dir, "github-x.jsonl")
		runtest.WriteUnfinished(t, p, c.recs...)
		if r, err := Read(p); err != nil || r.Label(p) != c.want {
			t.Errorf("%v: label %q, %v", c.recs, r.Label(p), err)
		}
	}
	finished := filepath.Join(dir, FileName("aws:x"))
	runtest.Write(t, finished, finding.Status{Type: "status", Connector: "aws", Instance: "x", State: finding.StateOK})
	if r, _ := Read(finished); r.Label(finished) != "aws:x" || FileLabel(finished) != "aws:x" {
		t.Errorf("finished run: %q %q", r.Label(finished), FileLabel(finished))
	}

	all, err := Load([]string{torn, finished})
	if err != nil || len(all) != 0 {
		t.Fatalf("Load: %v %v", all, err)
	}
	if _, err := Find([]finding.Finding{f}, ""); err == nil {
		t.Error("an empty id matched")
	}
}

func appendTo(t *testing.T, path, text string) {
	t.Helper()
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	if _, err := fh.WriteString(text); err != nil {
		t.Fatal(err)
	}
}
