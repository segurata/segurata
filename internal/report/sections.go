package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/rotation"
	"github.com/segurata/segurata/internal/secretrisk"
)

var severities = []finding.Severity{finding.SevCritical, finding.SevHigh, finding.SevMedium, finding.SevLow, finding.SevInfo}

// document lays the report out section by section.
func (r *Report) document() *doc {
	d := &doc{title: "securizame report"}
	d.h(1, d.title)
	d.p(fmt.Sprintf("Generated %s from the latest run of each connector instance under %s. Findings below %s and accepted risks are left out of the lists.",
		r.Generated.Format("2006-01-02 15:04"), r.OutDir, r.MinSev))
	r.headline(d)
	r.attention(d)
	r.changes(d)
	r.topFindings(d)
	r.rotations(d)
	r.accepted(d)
	d.h(2, "Manual review")
	d.p("Services without a connector are reviewed by hand every quarter, and right after a breach of a service you sign in with: docs/manual-review.md.")
	return d
}

func (r *Report) headline(d *doc) {
	d.h(2, "Headline")
	head := []string{"Connector", "Run"}
	for _, s := range severities {
		head = append(head, strings.ToUpper(string(s[:1]))+string(s[1:]))
	}
	head = append(head, "Accepted", "Attention")
	total := make([]int, len(severities)+2)
	var rows [][]cell
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
		row := []cell{{text: run.Label}, {text: run.Date}}
		for i, n := range counts {
			total[i] += n
			row = append(row, cell{text: strconv.Itoa(n), num: true})
		}
		rows = append(rows, row)
	}
	row := []cell{{text: "Total"}, {text: ""}}
	for _, n := range total {
		row = append(row, cell{text: strconv.Itoa(n), num: true})
	}
	d.table(head, append(rows, row))
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

// statusAction is what to do about a status, and the command that checks it afterwards.
func statusAction(st finding.Status, label string) (string, string) {
	rerun := "securizame inventory " + label
	switch st.State {
	case finding.StateReauth:
		return "Sign in to this account again in the browser securizame drives over CDP.", rerun
	case finding.StateSignedOut:
		return "Sign in to this account in that browser, or drop it from the config if it is gone.", rerun
	case finding.StateMissingCredentials:
		return "Check the secret reference for " + label + " in ~/.config/securizame/config.json (Keychain item, 1Password field or environment variable).", rerun
	case finding.StateUnsupported:
		return "Install what the detail names (respecting the 4-day quarantine), or remove " + label + " from the config.", rerun
	}
	return "Run it again with connector logs to see what failed.", rerun + " --verbose"
}

func (r *Report) attention(d *doc) {
	d.h(2, "Needs attention")
	var items []item
	for _, run := range r.Runs {
		for _, st := range needsAttention(run.Statuses) {
			action, cmd := statusAction(st, run.Label)
			text := run.Label
			if st.Account != "" {
				text += " · " + st.Account
			}
			it := item{badge: string(st.State), text: text, meta: st.Detail,
				details: []detail{{label: "Action", text: action}, {label: "Then", text: cmd, kind: dCode}}}
			items = append(items, it)
		}
	}
	if len(items) == 0 {
		d.p("Nothing: every connector could inspect every account.")
		return
	}
	d.list(items)
}

func (r *Report) changes(d *doc) {
	d.h(2, "Changes since the previous run")
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
		var changed []Change
		for _, c := range run.Changed {
			if !c.Hidden() && max(c.Severity.Rank(), c.From.Rank()) >= r.MinSev.Rank() {
				changed = append(changed, c)
			}
		}
		sort.SliceStable(changed, func(i, j int) bool { return changed[i].Severity.Rank() > changed[j].Severity.Rank() })
		d.h(3, fmt.Sprintf("%s: %s to %s", run.Label, run.PrevDate, run.Date))
		if len(added)+len(resolved)+len(changed) == 0 {
			d.p(fmt.Sprintf("No change at or above %s.", r.MinSev))
			continue
		}
		d.p(fmt.Sprintf("%d new, %d resolved, %d with another severity.", len(added), len(resolved), len(changed)))
		var items []item
		for _, f := range capped(added, r.Top) {
			items = append(items, item{badge: string(f.Severity), text: "New: " + f.DisplayTitle(), meta: meta(f)})
		}
		items = append(items, more(len(added), r.Top, "new findings"))
		for _, c := range changed[:min(len(changed), r.Top)] {
			items = append(items, item{badge: string(c.Severity), text: fmt.Sprintf("Was %s: %s", c.From, c.DisplayTitle()), meta: meta(c.Finding)})
		}
		items = append(items, more(len(changed), r.Top, "severity changes"))
		for _, f := range capped(resolved, r.Top) {
			items = append(items, item{badge: "resolved", text: fmt.Sprintf("Gone (was %s): %s", f.Severity, f.Title), meta: meta(f)})
		}
		items = append(items, more(len(resolved), r.Top, "resolved findings"))
		d.list(nonEmpty(items))
	}
	if len(first) > 0 {
		d.p("First run, nothing to compare: " + strings.Join(first, ", ") + ".")
	}
	if compared > 0 {
		d.p("A run is compared with the same connector instance's output in the newest earlier out/<date>/ folder; running a connector twice in one day overwrites that day's file.")
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
func more(total, shown int, what string) item {
	if total <= shown {
		return item{}
	}
	return item{text: fmt.Sprintf("… and %d more %s", total-shown, what)}
}

func nonEmpty(items []item) []item {
	var out []item
	for _, it := range items {
		if it.text != "" {
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

func (r *Report) topFindings(d *doc) {
	d.h(2, "Top findings")
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
		d.p(fmt.Sprintf("No finding at or above %s.", r.MinSev))
	}
	for _, g := range groups {
		d.h(3, fmt.Sprintf("%s (%d at or above %s)", g.run.Label, len(g.shown), r.MinSev))
		var items []item
		for _, f := range capped(g.shown, r.Top) {
			items = append(items, findingItem(f))
		}
		if m := more(len(g.shown), r.Top, "in "+g.run.File); m.text != "" {
			items = append(items, m)
		}
		d.list(items)
	}
	if note := finding.HiddenNote(hidden); note != "" {
		d.p(note + ".")
	}
}

func findingItem(f finding.Finding) item {
	it := item{badge: string(f.Severity), text: f.DisplayTitle(), meta: meta(f)}
	if s := f.Remediation.Summary; s != "" {
		it.details = append(it.details, detail{label: "Fix", text: s})
	}
	if u := f.Remediation.URL; u != "" {
		it.details = append(it.details, detail{label: "Where", text: u, kind: dLink})
	}
	if f.Remediation.Automatable {
		it.details = append(it.details, detail{label: "Automatable", text: "securizame remediate " + f.ID, kind: dCode})
	}
	return it
}

func (r *Report) rotations(d *doc) {
	d.h(2, "Rotation ledger")
	s := r.Rotations
	if s.Total == 0 {
		d.p("No rotation ledger yet at "+s.Path+": after a local-secrets inventory, run ", code("securizame rotations sync"), ".")
		return
	}
	d.p(fmt.Sprintf("Open: P0 %d, P1 %d, P2 %d, P3 %d. %d items in all: %d rotated, %d snoozed, %d ignored.",
		s.Open[secretrisk.P0], s.Open[secretrisk.P1], s.Open[secretrisk.P2], s.Open[secretrisk.P3],
		s.Total, s.ByStatus[rotation.Rotated], s.ByStatus[rotation.Snoozed], s.ByStatus[rotation.Ignored]))
	if len(s.TopP0) > 0 {
		d.h(3, "Rotate first (P0)")
		var items []item
		for _, it := range s.TopP0 {
			items = append(items, rotationItem(it, "since "+it.FirstSeen.Format(time.DateOnly)))
		}
		if m := more(s.Open[secretrisk.P0], len(s.TopP0), "P0 items"); m.text != "" {
			items = append(items, m)
		}
		d.list(items)
	}
	if len(s.SnoozesDue) > 0 {
		d.h(3, "Snoozes due")
		var items []item
		for _, it := range s.SnoozesDue {
			items = append(items, rotationItem(it, "snoozed until "+it.SnoozedUntil))
		}
		d.list(items)
		d.p("They count as open again; ", code("securizame rotations sync"), " records it.")
	}
	d.p("Full list: ", code("securizame rotations list"), "; one item: ", code("securizame rotations show <id>"), ".")
}

// rotationItem shows an item by its redacted hint only, never a location's content.
func rotationItem(it *rotation.Item, when string) item {
	text := it.Service + "/" + it.Type
	if it.Redacted != "" {
		text += " " + it.Redacted
	}
	out := item{badge: string(it.Priority), text: text, meta: fmt.Sprintf("id %s · %s · %s · %s", it.ID, it.WorstLabel(), count(len(it.Locations), "location"), when)}
	if len(it.Reasons) > 0 {
		out.details = append(out.details, detail{label: "Why", text: it.Reasons[0]})
	}
	if it.RotateURL != "" {
		out.details = append(out.details, detail{label: "Rotate at", text: it.RotateURL, kind: dLink})
	}
	out.details = append(out.details, detail{label: "Then", text: "securizame rotations done " + it.ID, kind: dCode})
	return out
}

func (r *Report) accepted(d *doc) {
	d.h(2, "Accepted risks")
	if len(r.Accepted) == 0 {
		d.p("No accepted risks.")
		return
	}
	var rows [][]cell
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
		rows = append(rows, []cell{{text: a.ID}, {text: a.Connector}, {text: state, badge: true}, {text: until}, {text: a.Reason}, {text: a.Title}})
	}
	d.table([]string{"ID", "Connector", "State", "Until", "Reason", "Title"}, rows)
	if expired > 0 {
		d.p(fmt.Sprintf("%d expired: those findings show in the lists again. Fix them, or accept again with a new date: ", expired),
			code("securizame accept <id> --reason \"…\" --until YYYY-MM-DD"), ".")
	}
	if gone > 0 {
		d.p(fmt.Sprintf("%d no longer reported by the latest run of their connector: ", gone), code("securizame unaccept <id>"), " tidies them up.")
	}
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
