package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/docref"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
	"github.com/segurata/segurata/internal/tracker"
)

// foldLen is how much of a long step shows before the rest folds away.
const foldLen = 240

var severities = []finding.Severity{finding.SevCritical, finding.SevHigh, finding.SevMedium, finding.SevLow, finding.SevInfo}

// document lays the report out section by section.
func (r *Report) document() *doc.Doc {
	d := &doc.Doc{Title: "segurata report"}
	d.H(1, d.Title)
	d.P(fmt.Sprintf("Generated %s from the latest run of each connector instance under %s. Findings below %s and accepted risks are left out of the lists.",
		r.Generated.Format("2006-01-02 15:04"), r.OutDir, r.MinSev))
	r.headline(d)
	r.completeness(d)
	r.tr.Blockers(d, r.tr.Items, r.Generated, nil)
	d.H(2, "Changes in the last 7 days")
	tracker.Changes(d, r.tr.Items, r.Generated.AddDate(0, 0, -7), true)
	r.topFindings(d)
	r.rotations(d)
	r.accepted(d)
	d.H(2, "Manual review")
	d.P("Services without a connector are reviewed by hand every quarter, and right after a breach of a service you sign in with: " + docref.Docs + "manual-review.md.")
	return d
}

// headline counts tracker items, as status does, with the runs' findings as a secondary note and
// a table by connector.
func (r *Report) headline(d *doc.Doc) {
	d.H(2, "Headline")
	r.tr.Headline(d, r.tr.Items, r.Generated)
	head := []string{"Connector", "Run"}
	for _, s := range severities {
		head = append(head, textfmt.UpperFirst(string(s)))
	}
	head = append(head, "Accepted", "Attention")
	total := make([]int, len(severities)+2)
	var rows [][]doc.Cell
	for _, run := range r.Runs {
		counts := make([]int, len(severities)+2)
		for _, f := range run.Findings {
			if f.Hidden() {
				counts[len(severities)]++
				continue
			}
			counts[sevIndex(f.Severity)]++
		}
		counts[len(severities)+1] = len(needsAttention(run.Statuses))
		row := []doc.Cell{{Text: run.Label}, {Text: run.Date + coverageTag(run.Coverage)}}
		for i, n := range counts {
			total[i] += n
			row = append(row, doc.Cell{Text: strconv.Itoa(n), Num: true})
		}
		rows = append(rows, row)
	}
	var parts []string
	row := []doc.Cell{{Text: "Total"}, {Text: ""}}
	for i, n := range total {
		if i < len(severities) {
			parts = append(parts, fmt.Sprintf("%d %s", n, severities[i]))
		}
		row = append(row, doc.Cell{Text: strconv.Itoa(n), Num: true})
	}
	d.P("Findings in the latest runs: " + strings.Join(parts, ", ") + ". An item groups the findings one action fixes, and a secret is one item however many copies of it were found.")
	d.H(3, "Findings by connector")
	d.Table(head, append(rows, row))
}

// coverageTag marks a run in the headline that does not prove findings gone.
func coverageTag(c finding.Coverage) string {
	switch {
	case !c.Known:
		return " (no run_end)"
	case !c.CompleteAsConfigured():
		return " (partial)"
	case c.Unreadable() > 0:
		return " (" + textfmt.Count(c.Unreadable(), "unreadable path", "unreadable paths") + " left out as expected)"
	}
	return ""
}

// completeness names the runs that are not complete and what they left out.
func (r *Report) completeness(d *doc.Doc) {
	d.H(2, "Run completeness")
	var items []doc.Item
	for _, run := range r.Runs {
		c := run.Coverage
		if run.Unfinished != "" {
			items = append(items, doc.Item{Badge: "unfinished", Text: fmt.Sprintf("%s: the run of %s did not finish", run.Label, run.Unfinished),
				Meta: fmt.Sprintf("no run_end record: killed or still running; the run of %s is shown instead", run.Date)})
		}
		if run.InspectedNothing != "" {
			items = append(items, doc.Item{Badge: "skipped", Text: fmt.Sprintf("%s: the run of %s inspected nothing", run.Label, run.InspectedNothing),
				Meta: fmt.Sprintf("%s; the run of %s is shown instead", run.InspectedWhy, run.Date)})
		}
		switch {
		case !c.Known:
			why, _ := c.NoneChecked()
			items = append(items, doc.Item{Badge: "unknown", Text: fmt.Sprintf("%s (%s): completeness unknown", run.Label, run.Date), Meta: why})
		case !c.CompleteAsConfigured():
			sk := c.Missed()
			it := doc.Item{Badge: "partial", Text: fmt.Sprintf("%s (%s): %s not inspected", run.Label, run.Date, textfmt.Count(len(sk), "scope", "scopes"))}
			for _, s := range sk[:min(len(sk), r.Top)] {
				it.Details = append(it.Details, doc.Detail{Label: s.Scope, Text: s.Reason})
			}
			if len(sk) > r.Top {
				it.Details = append(it.Details, doc.Detail{Label: "…", Text: fmt.Sprintf("and %d more in %s", len(sk)-r.Top, run.File)})
			}
			items = append(items, it)
		}
	}
	if len(items) == 0 {
		d.P("Every latest run finished and inspected everything it covers.")
		return
	}
	d.List(items)
	d.P("Findings missing from a run that did not inspect their scope are listed as not checked, never as resolved, and the tracker does not close their items.")
}

func sevIndex(s finding.Severity) int {
	for i, x := range severities {
		if x == s {
			return i
		}
	}
	return len(severities) - 1 // unknown counts as info
}

func needsAttention(sts []finding.Status) []finding.Status {
	var out []finding.Status
	for _, st := range sts {
		if st.State != finding.StateOK && st.State != finding.StateExpected {
			out = append(out, st)
		}
	}
	return out
}

// more is the "and N more" line under a capped list, or an empty item when nothing was cut.
func more(total, shown int, what string) doc.Item {
	if total <= shown {
		return doc.Item{}
	}
	return doc.Item{Text: fmt.Sprintf("… and %d more %s", total-shown, what)}
}

func meta(f finding.Finding) string {
	parts := []string{}
	if f.Account != "" {
		parts = append(parts, f.Account)
	}
	return strings.Join(append(parts, "id "+f.ID), " · ")
}

func (r *Report) topFindings(d *doc.Doc) {
	d.H(2, "Top findings")
	type group struct {
		run   *Run
		shown []finding.Finding
	}
	var groups []group
	hidden := 0
	for _, run := range r.Runs {
		for _, f := range run.Findings {
			if f.Hidden() {
				hidden++
			}
		}
		if v := visible(run.Findings, r.MinSev); len(v) > 0 {
			groups = append(groups, group{run: run, shown: v})
		}
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].shown[0].Severity.Rank() > groups[j].shown[0].Severity.Rank() })
	if len(groups) == 0 {
		d.P(fmt.Sprintf("No finding at or above %s.", r.MinSev))
	}
	for _, g := range groups {
		d.H(3, fmt.Sprintf("%s (%d at or above %s)", g.run.Label, len(g.shown), r.MinSev))
		var items []doc.Item
		for _, f := range g.shown[:min(len(g.shown), r.Top)] {
			items = append(items, findingItem(f))
		}
		if m := more(len(g.shown), r.Top, "in "+g.run.File); m.Text != "" {
			items = append(items, m)
		}
		d.List(items)
	}
	if note := finding.HiddenNote(hidden); note != "" {
		d.P(note + ".")
	}
}

func findingItem(f finding.Finding) doc.Item {
	it := doc.Item{Badge: string(f.Severity), Text: f.DisplayTitle(), Meta: meta(f)}
	if s := f.Remediation.Summary; s != "" {
		it.Details = append(it.Details, doc.Fold("Fix", s, foldLen))
	}
	if u := f.Remediation.URL; u != "" {
		it.Details = append(it.Details, doc.Detail{Label: "Where", Text: u, Kind: doc.DLink})
	}
	if f.Remediation.Automatable {
		it.Details = append(it.Details, doc.Detail{Label: "Automatable", Text: "segurata remediate " + f.ID, Kind: doc.DCode})
	}
	return it
}

func (r *Report) rotations(d *doc.Doc) {
	d.H(2, "Rotation ledger")
	s := r.Rotations
	if s.Total == 0 {
		d.P("No secrets in the tracker yet ("+s.Path+"): after a local-secrets inventory, run ", doc.Code("segurata rotations sync"), ".")
		return
	}
	d.P(fmt.Sprintf("Open: P0 %d, P1 %d, P2 %d, P3 %d. %d items in all: %d rotated, %d snoozed, %d ignored, %d reclassified as noise.",
		s.Open[secretrisk.P0], s.Open[secretrisk.P1], s.Open[secretrisk.P2], s.Open[secretrisk.P3],
		s.Total, s.ByStatus[tracker.Done], s.ByStatus[tracker.Snoozed], s.ByStatus[tracker.Ignored], s.ByStatus[tracker.Reclassified]))
	if len(s.TopP0) > 0 {
		d.H(3, "Rotate first (P0)")
		var items []doc.Item
		for _, it := range s.TopP0 {
			items = append(items, rotationItem(it, "since "+it.Secret.FirstSeen.Format(time.DateOnly)))
		}
		if m := more(s.Open[secretrisk.P0], len(s.TopP0), "P0 items"); m.Text != "" {
			items = append(items, m)
		}
		d.List(items)
	}
	if len(s.SnoozesDue) > 0 {
		d.H(3, "Snoozes due")
		var items []doc.Item
		for _, it := range s.SnoozesDue {
			items = append(items, rotationItem(it, "snoozed until "+it.SnoozedUntil))
		}
		d.List(items)
		d.P("They count as open again; ", doc.Code("segurata rotations sync"), " records it.")
	}
	d.P("Full list: ", doc.Code("segurata rotations list"), "; one item: ", doc.Code("segurata rotations show <id>"), ".")
}

// rotationItem shows an item by its redacted hint only, never a location's content.
func rotationItem(it *tracker.Item, when string) doc.Item {
	s := it.Secret
	text := s.Service + "/" + s.Type
	if s.Redacted != "" {
		text += " " + s.Redacted
	}
	out := doc.Item{Badge: string(it.EffectivePriority()), Text: text, Meta: fmt.Sprintf("id %s · %s · %s · %s", s.ID, it.WorstLabel(), textfmt.Count(len(s.Locations), "location", "locations"), when)}
	if len(s.Reasons) > 0 {
		out.Details = append(out.Details, doc.Detail{Label: "Why", Text: s.Reasons[0]})
	}
	if s.RotateURL != "" {
		out.Details = append(out.Details, doc.Detail{Label: "Rotate at", Text: s.RotateURL, Kind: doc.DLink})
	}
	out.Details = append(out.Details, doc.Detail{Label: "Then", Text: "segurata rotations done " + s.ID, Kind: doc.DCode})
	return out
}

func (r *Report) accepted(d *doc.Doc) {
	d.H(2, "Accepted risks")
	if len(r.Accepted) == 0 {
		d.P("No accepted risks.")
		return
	}
	var rows [][]doc.Cell
	expired, gone := 0, 0
	for _, a := range r.Accepted {
		state := "accepted"
		switch {
		case a.Expired:
			state = "expired"
			expired++
		case a.Gone:
			state = "not reported"
			gone++
		}
		until := a.Until
		if until == "" {
			until = "no end"
		}
		rows = append(rows, []doc.Cell{{Text: a.ID}, {Text: a.Connector}, {Text: state, Badge: true}, {Text: until}, {Text: a.Reason}, {Text: a.Title}})
	}
	d.Table([]string{"ID", "Connector", "State", "Until", "Reason", "Title"}, rows)
	if expired > 0 {
		d.P(fmt.Sprintf("%d expired: those findings show in the lists again. Fix them, or accept again with a new date: ", expired),
			doc.Code("segurata accept <id> --reason \"…\" --until YYYY-MM-DD"), ".")
	}
	if gone > 0 {
		d.P(fmt.Sprintf("%d no longer reported by the latest run of their connector: ", gone), doc.Code("segurata unaccept <id>"), " tidies them up.")
	}
}
