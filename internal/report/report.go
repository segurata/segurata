// Package report builds `securizame report`: the latest run of every connector instance, what
// changed since each one's previous run, the statuses that need action, the rotation ledger and
// the accepted risks, as terminal text, Markdown or a self-contained HTML page. It reads only
// securizame's own files and never holds a secret value: findings carry none, and the ledger only
// redacted hints. See docs/architecture.md, "Report".
package report

import (
	"io"

	"github.com/segurata/segurata/internal/doc"
	"path/filepath"
	"sort"
	"time"

	"github.com/segurata/segurata/internal/accept"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/rotation"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Run is the latest run of one connector instance, compared with its previous one.
type Run struct {
	Label    string // "name" or "name:label"
	File     string
	Date     string // YYYY-MM-DD of the run
	PrevDate string // "" when there is no earlier run to compare with
	Findings []finding.Finding
	Statuses []finding.Status
	New      []finding.Finding // in this run, not in the previous one
	Resolved []finding.Finding // in the previous run, gone from this one
	Changed  []Change          // same finding, other severity
}

// Change is a finding whose severity moved between runs.
type Change struct {
	finding.Finding
	From finding.Severity
}

// Accepted is one accepted risk and where it stands today.
type Accepted struct {
	*accept.Entry
	Expired bool
	Gone    bool // its connector's latest run no longer reports it
}

// Rotations summarises the rotation ledger.
type Rotations struct {
	Path       string
	Total      int
	Open       map[secretrisk.Priority]int // active items by priority ("" for noise)
	ByStatus   map[rotation.Status]int
	TopP0      []*rotation.Item
	SnoozesDue []*rotation.Item // snoozed past their date, not yet woken by a sync
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
	OutDir     string
	Now        time.Time
	Accepted   *accept.Store
	Ledger     *rotation.Ledger
	LedgerPath string
	MinSev     finding.Severity
	Top        int // findings per connector in "Top findings"
}

// maxP0 is how many P0 rotation items the report names.
const maxP0 = 5

// Build reads the latest run of every connector instance and its previous run, and annotates
// every finding with today's accepted-risks file.
func Build(in Inputs) (*Report, error) {
	files, err := remediate.LatestFiles(in.OutDir)
	if err != nil {
		return nil, err
	}
	annotate := in.Accepted.Annotator(func() time.Time { return in.Now })
	r := &Report{Generated: in.Now, OutDir: in.OutDir, MinSev: in.MinSev, Top: in.Top}
	reported := map[string]bool{} // finding ids in a latest run
	ran := map[string]bool{}      // connectors with a latest run
	for _, f := range files {
		run, err := readRun(f, annotate)
		if err != nil {
			return nil, err
		}
		for _, x := range run.Findings {
			reported[x.ID] = true
			ran[x.Connector] = true
		}
		for _, st := range run.Statuses {
			ran[st.Connector] = true
		}
		r.Runs = append(r.Runs, run)
	}
	sort.SliceStable(r.Runs, func(i, j int) bool { return r.Runs[i].Label < r.Runs[j].Label })
	for _, e := range in.Accepted.Entries {
		r.Accepted = append(r.Accepted, Accepted{Entry: e, Expired: e.Expired(in.Now), Gone: ran[e.Connector] && !reported[e.ID]})
	}
	r.Rotations = summarise(in.Ledger, in.LedgerPath, in.Now)
	return r, nil
}

func readRun(file string, annotate func(*finding.Finding)) (*Run, error) {
	findings, statuses, err := remediate.ReadRun(file)
	if err != nil {
		return nil, err
	}
	run := &Run{File: file, Date: filepath.Base(filepath.Dir(file)), Findings: findings, Statuses: statuses}
	run.Label = labelOf(file, findings, statuses)
	for i := range run.Findings {
		annotate(&run.Findings[i])
	}
	prevFile, err := remediate.PreviousFile(file)
	if err != nil || prevFile == "" {
		return run, err
	}
	prev, _, err := remediate.ReadRun(prevFile)
	if err != nil {
		return nil, err
	}
	run.PrevDate = filepath.Base(filepath.Dir(prevFile))
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
		if _, gone := before[f.ID]; gone {
			annotate(&f)
			run.Resolved = append(run.Resolved, f)
		}
	}
	return run, nil
}

// labelOf names the connector instance from its records, which carry the exact connector name and
// instance label; an empty run falls back to the file name.
func labelOf(file string, findings []finding.Finding, statuses []finding.Status) string {
	switch {
	case len(findings) > 0:
		return label(findings[0].Connector, findings[0].Instance)
	case len(statuses) > 0:
		return label(statuses[0].Connector, statuses[0].Instance)
	}
	base := filepath.Base(file)
	return base[:len(base)-len(filepath.Ext(base))]
}

func label(connector, instance string) string {
	if instance == "" {
		return connector
	}
	return connector + ":" + instance
}

func summarise(l *rotation.Ledger, path string, now time.Time) Rotations {
	s := Rotations{Path: path, Open: map[secretrisk.Priority]int{}, ByStatus: map[rotation.Status]int{}}
	if l == nil {
		return s
	}
	var p0 []*rotation.Item
	for _, it := range l.Items {
		s.Total++
		s.ByStatus[it.Status]++
		if !it.Active(now) {
			continue
		}
		s.Open[it.Priority]++
		if it.Priority == secretrisk.P0 {
			p0 = append(p0, it)
		}
		if it.Status == rotation.Snoozed {
			s.SnoozesDue = append(s.SnoozesDue, it)
		}
	}
	rotation.Sort(p0)
	s.TopP0 = p0[:min(len(p0), maxP0)]
	rotation.Sort(s.SnoozesDue)
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

// Format is an output format of `securizame report`.
type Format = doc.Format

const (
	Text     = doc.Text
	Markdown = doc.Markdown
	HTML     = doc.HTML
)

// Render writes the report in the given format.
func (r *Report) Render(w io.Writer, f Format) error { return doc.Render(w, r.document(), f) }
