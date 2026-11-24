package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/tracker"
)

var severities = []finding.Severity{finding.SevCritical, finding.SevHigh, finding.SevMedium, finding.SevLow, finding.SevInfo}

// document lays the report out section by section.
func (r *Report) document() *doc.Doc {
	d := &doc.Doc{Title: "segurata report"}
	d.H(1, d.Title)
	d.P(fmt.Sprintf("Generated %s from the latest run of each connector instance under %s. Findings below %s and accepted risks are left out of the lists.",
		r.Generated.Format("2006-01-02 15:04"), r.OutDir, r.MinSev))
	r.headline(d)
	r.completeness(d)
	r.attention(d)
	r.changes(d)
	r.topFindings(d)
	r.rotations(d)
	r.accepted(d)
	d.H(2, "Manual review")
	d.P("Services without a connector are reviewed by hand every quarter, and right after a breach of a service you sign in with: docs/manual-review.md.")
	return d
}

func (r *Report) headline(d *doc.Doc) {
	d.H(2, "Headline")
	head := []string{"Connector", "Run"}
	for _, s := range severities {
		head = append(head, strings.ToUpper(string(s[:1]))+string(s[1:]))
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
	row := []doc.Cell{{Text: "Total"}, {Text: ""}}
	for _, n := range total {
		row = append(row, doc.Cell{Text: strconv.Itoa(n), Num: true})
	}
	d.Table(head, append(rows, row))
}

// coverageTag marks a run in the headline that does not prove findings gone.
func coverageTag(c finding.Coverage) string {
	switch {
	case !c.Known:
		return " (no run_end)"
	case !c.Complete():
		return " (partial)"
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
		switch {
		case !c.Known:
			why, _ := c.NoneChecked()
			items = append(items, doc.Item{Badge: "unknown", Text: fmt.Sprintf("%s (%s): completeness unknown", run.Label, run.Date), Meta: why})
		case !c.Complete():
			sk := c.Skipped()
			it := doc.Item{Badge: "partial", Text: fmt.Sprintf("%s (%s): %s not inspected", run.Label, run.Date, count(len(sk), "scope"))}
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
		if st.State != finding.StateOK {
			out = append(out, st)
		}
	}
	return out
}

func (r *Report) attention(d *doc.Doc) {
	d.H(2, "Needs attention")
	var items []doc.Item
	for _, run := range r.Runs {
		for _, st := range needsAttention(run.Statuses) {
			action, cmd := tracker.StatusAction(st, run.Label)
			text := run.Label
			if st.Account != "" {
				text += " · " + st.Account
			}
			it := doc.Item{Badge: string(st.State), Text: text, Meta: st.Detail,
				Details: []doc.Detail{{Label: "Action", Text: action}, {Label: "Then", Text: cmd, Kind: doc.DCode}}}
			items = append(items, it)
		}
	}
	if len(items) == 0 {
		d.P("Nothing: every connector could inspect every account.")
		return
	}
	d.List(items)
}

func (r *Report) changes(d *doc.Doc) {
	d.H(2, "Changes since the previous run")
	var first []string
	compared := 0
	for _, run := range r.Runs {
		if run.PrevDate == "" {
			first = append(first, run.Label)
			continue
		}
		compared++
		added := visible(run.New, r.MinSev)
		resolved := atLeast(run.Resolved, r.MinSev)
		var unchecked []NotChecked
		for _, n := range run.NotChecked {
			if n.Severity.Rank() >= r.MinSev.Rank() {
				unchecked = append(unchecked, n)
			}
		}
		sort.SliceStable(unchecked, func(i, j int) bool { return unchecked[i].Severity.Rank() > unchecked[j].Severity.Rank() })
		var changed []Change
		for _, c := range run.Changed {
			if !c.Hidden() && max(c.Severity.Rank(), c.From.Rank()) >= r.MinSev.Rank() {
				changed = append(changed, c)
			}
		}
		sort.SliceStable(changed, func(i, j int) bool { return changed[i].Severity.Rank() > changed[j].Severity.Rank() })
		d.H(3, fmt.Sprintf("%s: %s to %s", run.Label, run.PrevDate, run.Date))
		if len(added)+len(resolved)+len(unchecked)+len(changed) == 0 {
			d.P(fmt.Sprintf("No change at or above %s.", r.MinSev))
			continue
		}
		d.P(fmt.Sprintf("%d new, %d resolved, %d not checked this run, %d with another severity.", len(added), len(resolved), len(unchecked), len(changed)))
		var items []doc.Item
		for _, f := range capped(added, r.Top) {
			items = append(items, doc.Item{Badge: string(f.Severity), Text: "New: " + f.DisplayTitle(), Meta: meta(f)})
		}
		items = append(items, more(len(added), r.Top, "new findings"))
		for _, c := range changed[:min(len(changed), r.Top)] {
			items = append(items, doc.Item{Badge: string(c.Severity), Text: fmt.Sprintf("Was %s: %s", c.From, c.DisplayTitle()), Meta: meta(c.Finding)})
		}
		items = append(items, more(len(changed), r.Top, "severity changes"))
		for _, f := range capped(resolved, r.Top) {
			items = append(items, doc.Item{Badge: "resolved", Text: fmt.Sprintf("Gone (was %s): %s", f.Severity, f.Title), Meta: meta(f)})
		}
		items = append(items, more(len(resolved), r.Top, "resolved findings"))
		for _, n := range unchecked[:min(len(unchecked), r.Top)] {
			items = append(items, doc.Item{Badge: "not checked", Text: fmt.Sprintf("Not checked this run (was %s): %s", n.Severity, n.Title),
				Meta: meta(n.Finding), Details: []doc.Detail{{Label: "Why", Text: n.Reason}}})
		}
		items = append(items, more(len(unchecked), r.Top, "findings not checked this run"))
		d.List(nonEmpty(items))
	}
	if len(first) > 0 {
		d.P("First run, nothing to compare: " + strings.Join(first, ", ") + ".")
	}
	if compared > 0 {
		d.P("A run is compared with the same connector instance's output in the newest earlier out/<date>/ folder; running a connector twice in one day overwrites that day's file.")
	}
}

// atLeast keeps the findings at or above minSev, worst first, hidden or not: a resolved finding
// is worth knowing about even if it had been accepted.
func atLeast(fs []finding.Finding, minSev finding.Severity) []finding.Finding {
	var out []finding.Finding
	for _, f := range fs {
		if f.Severity.Rank() >= minSev.Rank() {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity.Rank() > out[j].Severity.Rank() })
	return out
}

func capped(fs []finding.Finding, n int) []finding.Finding { return fs[:min(len(fs), n)] }

// more is the "and N more" line under a capped list, or an empty item when nothing was cut.
func more(total, shown int, what string) doc.Item {
	if total <= shown {
		return doc.Item{}
	}
	return doc.Item{Text: fmt.Sprintf("… and %d more %s", total-shown, what)}
}

func nonEmpty(items []doc.Item) []doc.Item {
	var out []doc.Item
	for _, it := range items {
		if it.Text != "" {
			out = append(out, it)
		}
	}
	return out
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
		for _, f := range capped(g.shown, r.Top) {
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
		it.Details = append(it.Details, doc.Detail{Label: "Fix", Text: s})
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
	d.P(fmt.Sprintf("Open: P0 %d, P1 %d, P2 %d, P3 %d. %d items in all: %d rotated, %d snoozed, %d ignored.",
		s.Open[secretrisk.P0], s.Open[secretrisk.P1], s.Open[secretrisk.P2], s.Open[secretrisk.P3],
		s.Total, s.ByStatus[tracker.Done], s.ByStatus[tracker.Snoozed], s.ByStatus[tracker.Ignored]))
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
	out := doc.Item{Badge: string(it.EffectivePriority()), Text: text, Meta: fmt.Sprintf("id %s · %s · %s · %s", s.ID, it.WorstLabel(), count(len(s.Locations), "location"), when)}
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

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
