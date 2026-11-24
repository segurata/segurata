// Package report builds `segurata report`: the latest run of every connector instance, what
// changed since each one's previous run, the statuses that need action, the rotation ledger and
// the accepted risks, as terminal text, Markdown or a self-contained HTML page. It reads only
// segurata's own files and never holds a secret value: findings carry none, and the tracker's
// rotate items only redacted hints. See docs/architecture.md, "Report".
package report

import (
	"io"

	"github.com/segurata/segurata/internal/doc"
	"path/filepath"
	"sort"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/tracker"
)

// Run is the latest run of one connector instance, compared with its previous one.
type Run struct {
	Label    string // "name" or "name:label"
	File     string
	Date     string // YYYY-MM-DD of the run
	PrevDate string // "" when there is no earlier run to compare with
	// Unfinished is the date of a newer run without run_end that was passed over, or "".
	Unfinished string
	Coverage   finding.Coverage
	Findings   []finding.Finding
	Statuses   []finding.Status
	New        []finding.Finding // in this run, not in the previous one
	Resolved   []finding.Finding // in the previous run, gone from this one, and its scope inspected
	NotChecked []NotChecked      // in the previous run, missing from this one, its scope not inspected
	Changed    []Change          // same finding, other severity
}

// NotChecked is a finding of the previous run that the latest run could not have seen.
type NotChecked struct {
	finding.Finding
	Reason string
}

// Change is a finding whose severity moved between runs.
type Change struct {
	finding.Finding
	From finding.Severity
}

// Accepted is one accepted risk and where it stands today.
type Accepted struct {
	ID, Connector, Title, Reason, Until string
	Expired                             bool
	Gone                                bool // its connector's latest run no longer reports it
}

// Rotations summarises the tracker's rotate items.
type Rotations struct {
	Path       string
	Total      int
	Open       map[secretrisk.Priority]int // active items by priority ("" for noise)
	ByStatus   map[tracker.Status]int
	TopP0      []*tracker.Item
	SnoozesDue []*tracker.Item // snoozed past their date, not yet woken by a sync
}

// Report is everything the renderers print.
type Report struct {
	Generated time.Time
	OutDir    string
	MinSev    finding.Severity
	Top       int
	Runs      []*Run
	Accepted  []Accepted
	Rotations Rotations
}

// Inputs are the files and options a report reads.
type Inputs struct {
	OutDir      string
	Now         time.Time
	Tracker     *tracker.Tracker
	TrackerPath string
	MinSev      finding.Severity
	Top         int // findings per connector in "Top findings"
}

// maxP0 is how many P0 rotation items the report names.
const maxP0 = 5

// Build reads the latest run of every connector instance and its previous run, and annotates
// every finding with the tracker's acceptances as of today.
func Build(in Inputs) (*Report, error) {
	latest, err := remediate.LatestRuns(in.OutDir)
	if err != nil {
		return nil, err
	}
	annotate := in.Tracker.Annotator(func() time.Time { return in.Now })
	r := &Report{Generated: in.Now, OutDir: in.OutDir, MinSev: in.MinSev, Top: in.Top}
	reported := map[string]bool{} // finding ids in a latest run
	byLabel := map[string]*Run{}
	for _, l := range latest {
		run, err := readRun(l, annotate)
		if err != nil {
			return nil, err
		}
		for _, x := range run.Findings {
			reported[x.ID] = true
		}
		byLabel[run.Label] = run
		r.Runs = append(r.Runs, run)
	}
	sort.SliceStable(r.Runs, func(i, j int) bool { return r.Runs[i].Label < r.Runs[j].Label })
	for _, it := range in.Tracker.AcceptedItems() {
		for _, f := range it.Findings {
			gone := false
			if run, ok := byLabel[f.Label()]; ok && !reported[f.ID] {
				_, unchecked := run.Coverage.Unchecked(f.Account, f.Scope)
				gone = !unchecked
			}
			r.Accepted = append(r.Accepted, Accepted{ID: f.ID, Connector: f.Connector, Title: it.Title, Reason: it.Accepted.Reason,
				Until: it.Accepted.Until, Expired: it.AcceptanceExpired(in.Now), Gone: gone})
		}
	}
	r.Rotations = summarise(in.Tracker, in.TrackerPath, in.Now)
	return r, nil
}

func dateOf(file string) string { return filepath.Base(filepath.Dir(file)) }

// readRun reads a latest run and diffs it with the previous one. A finding missing from it is
// resolved only when the run inspected its scope; findings of a previous run without run_end carry
// no reliable scope, so any skipped scope makes them not checked.
func readRun(l remediate.Latest, annotate func(*finding.Finding)) (*Run, error) {
	rf, err := remediate.ReadRun(l.File)
	if err != nil {
		return nil, err
	}
	run := &Run{File: l.File, Date: dateOf(l.File), Coverage: rf.Coverage(), Findings: rf.Findings, Statuses: rf.Statuses}
	run.Label = tracker.RunLabel(l.File, rf)
	if l.Unfinished != "" {
		run.Unfinished = dateOf(l.Unfinished)
	}
	for i := range run.Findings {
		annotate(&run.Findings[i])
	}
	if l.Prev == "" {
		return run, nil
	}
	prevRun, err := remediate.ReadRun(l.Prev)
	if err != nil {
		return nil, err
	}
	prev := prevRun.Findings
	run.PrevDate = dateOf(l.Prev)
	before := make(map[string]finding.Finding, len(prev))
	for _, f := range prev {
		before[f.ID] = f
	}
	for _, f := range run.Findings {
		old, ok := before[f.ID]
		switch {
		case !ok:
			run.New = append(run.New, f)
		case old.Severity != f.Severity:
			run.Changed = append(run.Changed, Change{Finding: f, From: old.Severity})
		}
		delete(before, f.ID)
	}
	for _, f := range prev { // file order, not map order
		if _, gone := before[f.ID]; !gone {
			continue
		}
		annotate(&f)
		scope := finding.ScopeOf(f)
		if prevRun.End == nil {
			scope = ""
		}
		if why, unchecked := run.Coverage.Unchecked(f.Account, scope); unchecked {
			run.NotChecked = append(run.NotChecked, NotChecked{Finding: f, Reason: why})
			continue
		}
		run.Resolved = append(run.Resolved, f)
	}
	return run, nil
}

func summarise(t *tracker.Tracker, path string, now time.Time) Rotations {
	s := Rotations{Path: path, Open: map[secretrisk.Priority]int{}, ByStatus: map[tracker.Status]int{}}
	if t == nil {
		return s
	}
	var p0 []*tracker.Item
	for _, it := range t.Items {
		if it.Kind != tracker.KindRotate {
			continue
		}
		s.Total++
		s.ByStatus[it.Status]++
		if !it.Active(now) {
			continue
		}
		p := it.EffectivePriority()
		s.Open[p]++
		if p == secretrisk.P0 {
			p0 = append(p0, it)
		}
		if it.Status == tracker.Snoozed {
			s.SnoozesDue = append(s.SnoozesDue, it)
		}
	}
	tracker.Sort(p0)
	s.TopP0 = p0[:min(len(p0), maxP0)]
	tracker.Sort(s.SnoozesDue)
	return s
}

// visible are the findings a report lists: not hidden by an acceptance, at or above minSev, worst
// first (stable, so ties keep the connector's order).
func visible(fs []finding.Finding, minSev finding.Severity) []finding.Finding {
	var out []finding.Finding
	for _, f := range fs {
		if !f.Hidden() && f.Severity.Rank() >= minSev.Rank() {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity.Rank() > out[j].Severity.Rank() })
	return out
}

// Format is an output format of `segurata report`.
type Format = doc.Format

const (
	Text     = doc.Text
	Markdown = doc.Markdown
	HTML     = doc.HTML
)

// Render writes the report in the given format.
func (r *Report) Render(w io.Writer, f Format) error { return doc.Render(w, r.document(), f) }
