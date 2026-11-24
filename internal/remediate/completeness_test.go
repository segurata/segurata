package remediate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/runtest"
)

// scripted is a connector whose inventory is a function, run for real through run.Inventory so the
// check sees the run_end record the core writes.
type scripted func(ctx context.Context, emit connector.Emitter) error

func (scripted) Describe() connector.Description {
	return connector.Description{Name: "macos", Version: "0", Protocol: 1}
}

func (s scripted) Inventory(ctx context.Context, _ connector.Request, emit connector.Emitter) error {
	return s(ctx, emit)
}

func checkRun(t *testing.T, s scripted) Reinventory {
	return func(ctx context.Context) ([]*run.Result, error) {
		cfg := config.Config{Connectors: map[string]config.ConnectorConfig{"macos": {}}}
		targets, err := run.Targets(cfg, []connector.Connector{s}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return run.Inventory(ctx, cfg, targets, t.TempDir(), nil, nil)
	}
}

// A fix is verified only by a check run that inspected the finding's scope.
func TestVerifyNeedsTheFindingsScopeInspected(t *testing.T) {
	scoped := target
	scoped.Scope = "repo:me/app"
	ok := func(emit connector.Emitter) { emit.Status(finding.Status{Account: "mac", State: finding.StateOK}) }
	cases := []struct {
		name   string
		f      finding.Finding
		s      scripted
		verify bool
	}{
		{"inspected and gone", target, func(_ context.Context, e connector.Emitter) error { ok(e); return nil }, true},
		{"account signed out", target, func(_ context.Context, e connector.Emitter) error {
			e.Status(finding.Status{Account: "mac", State: finding.StateSignedOut})
			return nil
		}, false},
		{"scope skipped by the rate limit", scoped, func(_ context.Context, e connector.Emitter) error {
			ok(e)
			e.Scope("repo:me/app", false, "rate limit")
			return nil
		}, false},
		{"other scope skipped", scoped, func(_ context.Context, e connector.Emitter) error {
			ok(e)
			e.Scope("repo:me/other", false, "rate limit")
			return nil
		}, true},
		{"nothing said ok", target, func(context.Context, connector.Emitter) error { return nil }, false},
		{"interrupted", target, func(ctx context.Context, e connector.Emitter) error { ok(e); return nil }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if c.name == "interrupted" {
				cancel()
			}
			r := &fakeRemediator{plan: connector.Plan{Action: "macos.firewall.enable"}}
			err := Execute(ctx, c.f, r, Options{Apply: true, Yes: true, IO: quietIO()}, checkRun(t, c.s))
			if c.verify && err != nil {
				t.Fatalf("want verified, got %v", err)
			}
			if !c.verify && !errors.Is(err, ErrUnverified) {
				t.Fatalf("want ErrUnverified, got %v", err)
			}
		})
	}
	killed := func(context.Context) ([]*run.Result, error) { return []*run.Result{{Name: "macos"}}, nil }
	r := &fakeRemediator{plan: connector.Plan{Action: "macos.firewall.enable"}}
	if err := Execute(context.Background(), target, r, Options{Apply: true, Yes: true, IO: quietIO()}, killed); !errors.Is(err, ErrUnverified) {
		t.Fatalf("a check run without run_end must not verify: %v", err)
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

	rf, err := ReadRun(torn)
	if err != nil || len(rf.Findings) != 1 || rf.End != nil || rf.Coverage().Known {
		t.Fatalf("a torn last line of an unfinished run is dropped: %+v %v", rf, err)
	}
	if _, none := rf.Coverage().NoneChecked(); !none {
		t.Fatal("an unfinished run proves nothing gone")
	}
	done, err := ReadRun(gh.File)
	if err != nil || done.End == nil || !done.Coverage().Complete() {
		t.Fatalf("finished run: %+v %v", done, err)
	}
	middle := path("2026-11-24", "github.jsonl")
	runtest.WriteUnfinished(t, middle, f("x"))
	raw, _ = os.ReadFile(middle)
	_ = os.WriteFile(middle, append([]byte("{not json\n"), raw...), 0o600)
	if _, err := ReadRun(middle); err == nil {
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
