package tracker

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

// Filter narrows the items a view shows; empty fields match everything.
type Filter struct {
	Themes, Kinds, Priorities map[string]bool
}

func (f Filter) keep(it *Item) bool {
	switch {
	case len(f.Themes) > 0 && !f.Themes[it.Theme]:
	case len(f.Kinds) > 0 && !f.Kinds[string(it.Kind)]:
	case len(f.Priorities) > 0 && !f.Priorities[string(it.EffectivePriority())]:
	default:
		return true
	}
	return false
}

// newFilter reads the comma-separated --theme, --kind and --priority flags.
func newFilter(themes, kinds, priorities string) Filter {
	return Filter{Themes: set(themes, false), Kinds: set(kinds, false), Priorities: set(priorities, true)}
}

func (f Filter) empty() bool { return len(f.Themes)+len(f.Kinds)+len(f.Priorities) == 0 }

// statusTop is how many entries "Do next" lists, and how many changes are listed one by one.
const (
	statusTop     = 10
	statusChanges = 20
	actionLen     = 240
)

var prios = []secretrisk.Priority{secretrisk.P0, secretrisk.P1, secretrisk.P2, secretrisk.P3}

// Status lays the briefing out: headline, what to do next, pending decisions, setup blockers,
// what changed since the last status, and the accepted risks. It never shows a secret value:
// rotate items are named by their redacted hint.
func (t *Tracker) Status(path string, now time.Time, f Filter) *doc.Doc {
	var items []*Item
	for _, it := range t.Items {
		if f.keep(it) {
			items = append(items, it)
		}
	}
	d := &doc.Doc{Title: "segurata status"}
	d.H(1, d.Title)
	sync := "never synced: run segurata track sync after an inventory"
	if t.LastSyncAt != nil {
		sync = "last synced " + t.LastSyncAt.In(now.Location()).Format("2006-01-02 15:04")
	}
	d.P(fmt.Sprintf("As of %s. Tracker %s, %s.", now.Format("2006-01-02 15:04"), path, sync))
	t.headline(d, items, now)
	t.doNext(d, items, now)
	decisions(d, items, now)
	blockers(d, items, now)
	t.changes(d, items, now)
	accepted(d, items, now)
	return d
}

func (t *Tracker) headline(d *doc.Doc, items []*Item, now time.Time) {
	d.H(2, "Headline")
	byTheme := map[string]map[secretrisk.Priority]int{}
	open := map[secretrisk.Priority]int{}
	byStatus := map[Status]int{}
	weekAgo := now.AddDate(0, 0, -7)
	doneWeek, verifiedWeek := 0, 0
	for _, it := range items {
		byStatus[it.Status]++
		if it.Status == Done && it.StatusAt.After(weekAgo) {
			doneWeek++
		}
		if it.VerifiedAt != nil && it.VerifiedAt.After(weekAgo) {
			verifiedWeek++
		}
		if !it.Active(now) {
			continue
		}
		p := it.EffectivePriority()
		open[p]++
		if byTheme[it.Theme] == nil {
			byTheme[it.Theme] = map[secretrisk.Priority]int{}
		}
		byTheme[it.Theme][p]++
	}
	active := 0
	for _, n := range open {
		active += n
	}
	d.P(fmt.Sprintf("%d open: P0 %d, P1 %d, P2 %d, P3 %d. Done in the last 7 days: %d (%d verified by a later run). Accepted %d, ignored %d, snoozed %d.",
		active, open[secretrisk.P0], open[secretrisk.P1], open[secretrisk.P2], open[secretrisk.P3], doneWeek, verifiedWeek,
		byStatus[Accepted], byStatus[Ignored], byStatus[Snoozed]))
	if active == 0 {
		return
	}
	head := []string{"Theme", "P0", "P1", "P2", "P3", "None", "Open"}
	var rows [][]doc.Cell
	for _, th := range t.Themes {
		c := byTheme[th.ID]
		if c == nil {
			continue
		}
		row := []doc.Cell{{Text: th.Title}}
		total := 0
		for _, p := range append(prios, "") {
			row = append(row, doc.Cell{Text: strconv.Itoa(c[p]), Num: true})
			total += c[p]
		}
		rows = append(rows, append(row, doc.Cell{Text: strconv.Itoa(total), Num: true}))
	}
	d.Table(head, rows)
}

// doNext lists the most urgent things to do. Secrets are one entry per priority (there can be
// hundreds), pointing to `segurata rotations next`; every other item is listed on its own.
func (t *Tracker) doNext(d *doc.Doc, items []*Item, now time.Time) {
	d.H(2, "Do next")
	type entry struct {
		prio secretrisk.Priority
		rank int // severity, for ties
		item doc.Item
	}
	var entries []entry
	secrets := map[secretrisk.Priority]int{}
	for _, it := range items {
		if !it.Active(now) || it.Kind == KindDecide || it.Kind == KindSetup {
			continue
		}
		if it.Kind == KindRotate {
			if p := it.EffectivePriority(); p != "" {
				secrets[p]++
			}
			continue
		}
		entries = append(entries, entry{it.EffectivePriority(), it.Severity.Rank(), itemDoc(it, t)})
	}
	for _, p := range prios {
		if n := secrets[p]; n > 0 {
			entries = append(entries, entry{p, 5, doc.Item{Badge: string(p), Text: fmt.Sprintf("Rotate %s", count(n, string(p)+" secret", string(p)+" secrets")),
				Meta: "Secrets to rotate · one at a time, most exposed first",
				Details: []doc.Detail{{Label: "Next", Text: "Rotate it at the provider, then let segurata put the new value where it is used."},
					{Label: "Command", Text: "segurata rotations next --priority " + string(p), Kind: doc.DCode}}}})
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if a, b := entries[i].prio.Rank(), entries[j].prio.Rank(); a != b {
			return a < b
		}
		return entries[i].rank > entries[j].rank
	})
	if len(entries) == 0 {
		d.P("Nothing open.")
		return
	}
	var list []doc.Item
	for _, e := range entries[:min(len(entries), statusTop)] {
		list = append(list, e.item)
	}
	d.List(list)
	if len(entries) > statusTop {
		d.P(fmt.Sprintf("… and %d more: ", len(entries)-statusTop), doc.Code("segurata track list"), ".")
	}
}

// itemDoc is one item in a list: priority, title, what it is, and its next step.
func itemDoc(it *Item, t *Tracker) doc.Item {
	meta := []string{it.ID, t.ThemeTitle(it.Theme), string(it.Kind)}
	if it.Severity != "" {
		meta = append(meta, string(it.Severity))
	}
	if n := len(it.Findings); n > 0 {
		meta = append(meta, count(n, "finding", "findings"))
	}
	out := doc.Item{Badge: textfmt.OrDash(string(it.EffectivePriority())), Text: it.Title, Meta: strings.Join(meta, " · ")}
	if n := it.Next; n != nil {
		out.Details = append(out.Details, doc.Detail{Label: "Next (" + string(n.Who) + ")", Text: textfmt.Truncate(oneLine(n.Action), actionLen)})
		if n.Command != "" {
			out.Details = append(out.Details, doc.Detail{Label: "Command", Text: n.Command, Kind: doc.DCode})
		}
		if n.URL != "" {
			out.Details = append(out.Details, doc.Detail{Label: "Where", Text: n.URL, Kind: doc.DLink})
		}
	}
	return out
}

func decisions(d *doc.Doc, items []*Item, now time.Time) {
	d.H(2, "Pending decisions")
	var list []doc.Item
	for _, it := range sorted(items, func(it *Item) bool { return it.Kind == KindDecide && it.Active(now) }) {
		out := doc.Item{Badge: textfmt.OrDash(string(it.EffectivePriority())), Text: it.Decision.Question, Meta: it.ID}
		if len(it.Decision.Options) > 0 {
			out.Details = append(out.Details, doc.Detail{Label: "Options", Text: strings.Join(it.Decision.Options, " | ")})
		}
		out.Details = append(out.Details, doc.Detail{Label: "Answer", Text: "segurata track decide " + it.ID + ` --answer "…"`, Kind: doc.DCode})
		list = append(list, out)
	}
	if len(list) == 0 {
		d.P("None.")
	}
	d.List(list)
}

func blockers(d *doc.Doc, items []*Item, now time.Time) {
	d.H(2, "Setup blockers")
	var list []doc.Item
	for _, it := range sorted(items, func(it *Item) bool { return it.Kind == KindSetup && it.Active(now) }) {
		out := doc.Item{Badge: textfmt.OrDash(string(it.EffectivePriority())), Text: it.Title, Meta: it.ID}
		if len(it.Findings) > 0 && it.Findings[0].Title != "" {
			out.Meta += " · " + textfmt.Truncate(oneLine(it.Findings[0].Title), actionLen)
		}
		if n := it.Next; n != nil {
			out.Details = append(out.Details, doc.Detail{Label: "Action", Text: textfmt.Truncate(oneLine(n.Action), actionLen)},
				doc.Detail{Label: "Then", Text: n.Command, Kind: doc.DCode})
		}
		list = append(list, out)
	}
	if len(list) == 0 {
		d.P("None: every connector could inspect every account.")
	}
	d.List(list)
}

// changes counts the history events since the last status, secrets apart, and lists the latest
// ones of other items. The first status only counts: everything is new.
func (t *Tracker) changes(d *doc.Doc, items []*Item, now time.Time) {
	since := time.Time{}
	if t.LastStatusAt != nil {
		since = *t.LastStatusAt
		d.H(2, "Since the last status ("+since.In(now.Location()).Format("2006-01-02 15:04")+")")
	} else {
		d.H(2, "Since the last status (first status: everything)")
	}
	type change struct {
		at   time.Time
		item doc.Item
	}
	var listed []change
	secretEvents, itemEvents := map[string]int{}, map[string]int{}
	for _, it := range items {
		for _, e := range it.History {
			if !e.At.After(since) || e.Action == ActNext || e.Action == ActReplacePlan {
				continue
			}
			if it.Kind == KindRotate {
				secretEvents[e.Action]++
				continue
			}
			itemEvents[e.Action]++
			text := e.Action
			if e.Detail != "" {
				text += ": " + textfmt.Truncate(oneLine(e.Detail), 120)
			}
			listed = append(listed, change{e.At, doc.Item{Badge: e.Event, Text: it.Title, Meta: it.ID + " · " + text}})
		}
	}
	if len(listed) == 0 && len(secretEvents) == 0 {
		d.P("No change.")
		return
	}
	for _, c := range []struct {
		what   string
		counts map[string]int
	}{{"Secrets", secretEvents}, {"Other items", itemEvents}} {
		if len(c.counts) == 0 {
			continue
		}
		var parts []string
		for _, a := range slices.Sorted(maps.Keys(c.counts)) {
			parts = append(parts, fmt.Sprintf("%s %d", a, c.counts[a]))
		}
		d.P(c.what + ": " + strings.Join(parts, ", ") + ".")
	}
	if t.LastStatusAt == nil {
		return
	}
	sort.SliceStable(listed, func(i, j int) bool { return listed[i].at.After(listed[j].at) })
	var list []doc.Item
	for _, c := range listed[:min(len(listed), statusChanges)] {
		list = append(list, c.item)
	}
	d.List(list)
	if len(listed) > statusChanges {
		d.P(fmt.Sprintf("… and %d more changes: ", len(listed)-statusChanges), doc.Code("segurata track show <id>"), ".")
	}
}

func accepted(d *doc.Doc, items []*Item, now time.Time) {
	d.H(2, "Accepted risks")
	var rows [][]doc.Cell
	for _, it := range items {
		if it.Accepted == nil {
			continue
		}
		state := "accepted"
		if it.AcceptanceExpired(now) {
			state = "expired"
		}
		until := it.Accepted.Until
		if until == "" {
			until = "no end"
		}
		rows = append(rows, []doc.Cell{{Text: it.ID}, {Text: state, Badge: true}, {Text: until}, {Text: it.Accepted.Reason}, {Text: it.Title}})
	}
	if len(rows) == 0 {
		d.P("None.")
		return
	}
	d.Table([]string{"Item", "State", "Until", "Reason", "Title"}, rows)
}

func sorted(items []*Item, keep func(*Item) bool) []*Item {
	var out []*Item
	for _, it := range items {
		if keep(it) {
			out = append(out, it)
		}
	}
	Sort(out)
	return out
}

// oneLine folds a multi-line text (a connector's step-by-step detail) onto one line.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
