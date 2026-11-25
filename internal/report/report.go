// Package report builds `segurata report`: the tracker's items as status counts them (setup
// blockers, changes from item history), the latest run of every connector instance and its
// completeness, the rotation ledger and the accepted risks, as terminal text, Markdown or a
// self-contained HTML page. Runs are compared in one place, the tracker's sync. It reads only
// segurata's own files and never holds a secret value: findings carry none, and the tracker's
// rotate items only redacted hints. See docs/architecture.md, "Report".
package report

import (
	"io"
	"path/filepath"
	"sort"
	"time"

	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/runfile"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/tracker"
)

// Run is the latest run of one connector instance.
type Run struct {
	Label string // "name" or "name:label"
	File  string
	Date  string // YYYY-MM-DD of the run
	// Unfinished is the date of a newer run without run_end that was passed over, or "".
	Unfinished string
	// InspectedNothing is the date of the latest run when it inspected nothing and reported no
	// finding, so this older run, the newest that inspected something, is shown instead; or "".
	// InspectedWhy is why it inspected nothing.
	InspectedNothing, InspectedWhy string
	Coverage                       finding.Coverage
	Findings                       []finding.Finding
	Statuses                       []finding.Status
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
	tr        *tracker.Tracker // names the setup item of each status
}

// Inputs are the files and options a report reads.
type Inputs struct {
	OutDir      string
	Now         time.Time
	Tracker     *tracker.Tracker
	TrackerPath string
	MinSev      finding.Severity
	Top         int // findings per connector in "Top findings"
	// Sync is how a tracker that was never synced is synced in memory, from OutDir, so the report
	// counts items before the first `track sync` too; nothing is saved. Its Expect also applies the
	// config's expected rules to the runs' statuses.
	Sync tracker.SyncOptions
}

// maxP0 is how many P0 rotation items the report names.
const maxP0 = 5

// Build reads the latest run of every connector instance and annotates every finding with the
// tracker's acceptances as of today.
func Build(in Inputs) (*Report, error) {
	latest, err := runfile.LatestRuns(in.OutDir, in.Now)
	if err != nil {
		return nil, err
	}
	if in.Tracker.LastSyncAt == nil {
		opt := in.Sync
		opt.OutDir = in.OutDir
		if _, err := in.Tracker.Sync(opt, in.Now); err != nil {
			return nil, err
		}
	}
	annotate := in.Tracker.Annotator(func() time.Time { return in.Now })
	r := &Report{Generated: in.Now, OutDir: in.OutDir, MinSev: in.MinSev, Top: in.Top, tr: in.Tracker}
	reported := map[string]bool{} // finding ids in a latest run
	byLabel := map[string]*Run{}
	for _, l := range latest {
		run, err := readRun(l, annotate)
		if err != nil {
			return nil, err
		}
		if in.Sync.Expect != nil {
			for i := range run.Statuses {
				in.Sync.Expect(&run.Statuses[i])
			}
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

// readRun reads a latest run, or the newest run that inspected something when the latest inspected
// nothing and found nothing (runfile.Latest.Evidence).
func readRun(l runfile.Latest, annotate func(*finding.Finding)) (*Run, error) {
	rf, err := runfile.Read(l.File)
	if err != nil {
		return nil, err
	}
	file, skipped, why := l.File, "", ""
	if l.Evidence != "" && len(rf.Findings) == 0 {
		why, _ = rf.Coverage().NoneChecked()
		if rf, err = runfile.Read(l.Evidence); err != nil {
			return nil, err
		}
		file, skipped = l.Evidence, dateOf(l.File)
	}
	run := &Run{File: file, Date: dateOf(file), InspectedNothing: skipped, InspectedWhy: why, Coverage: rf.Coverage(), Findings: rf.Findings, Statuses: rf.Statuses}
	run.Label = rf.Label(file)
	if l.Unfinished != "" {
		run.Unfinished = dateOf(l.Unfinished)
	}
	for i := range run.Findings {
		annotate(&run.Findings[i])
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
