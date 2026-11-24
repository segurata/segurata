package tracker

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

// Ranking for "Do next": how much doing an item now is worth.
//
//	score = impact × blast × exposure × liveness × confidence ÷ effort × quick win
//
// Every factor comes from a table below and is shown by `status --explain`, so the order can be
// argued with. Impact is the priority; blast radius says what is at stake beyond the severity a
// connector gave one finding (every repository of five orgs, a Mac with no backup, a Google
// account that opens bank accounts); exposure, liveness and attribution weigh secrets; confidence
// discounts what needs judgment; effort divides; a quick win (segurata does it, one change closes
// many findings, an answer unblocks many items) multiplies. A pending decision is worth part of
// what it unblocks. See docs/architecture.md, "Do next".

// Factor is one term of a score, with why it has that value.
type Factor struct {
	Name  string
	Value float64
	Why   string
}

// Score is an item's worth for "Do next" and the factors it is the product of.
type Score struct {
	Total   float64
	Factors []Factor
}

// Explain is the score as a formula: "27.0 = impact 6 (P1) × blast 3 (…) ÷ effort 1 (…)".
// Factors of 1 other than impact and effort are left out.
func (s Score) Explain() string {
	parts := []string{strconv.FormatFloat(s.Total, 'f', 1, 64) + " ="}
	for i, f := range s.Factors {
		if f.Value == 1 && f.Name != "impact" && f.Name != "effort" {
			continue
		}
		op := "×"
		switch {
		case i == 0:
			op = ""
		case f.Name == "effort":
			op = "÷"
		}
		term := strings.TrimSpace(op + " " + f.Name + " " + strconv.FormatFloat(f.Value, 'g', 3, 64))
		if f.Why != "" {
			term += " (" + f.Why + ")"
		}
		parts = append(parts, term)
	}
	return strings.Join(parts, " ")
}

func newScore(factors ...Factor) Score {
	total := 1.0
	for _, f := range factors {
		if f.Name == "effort" {
			total /= f.Value
		} else {
			total *= f.Value
		}
	}
	return Score{Total: math.Round(total*10) / 10, Factors: factors}
}

// impacts weighs priorities: a P0 is worth a little under twice a P1.
var impacts = map[secretrisk.Priority]float64{secretrisk.P0: 10, secretrisk.P1: 6, secretrisk.P2: 3, secretrisk.P3: 1}

// blast is one row of the blast-radius table: what an item puts at stake beyond its severity.
type blast struct {
	match  func(it *Item) bool
	factor float64
	why    string
}

// refHas reports whether one of the item's findings has that resource type and, when id is not
// "", that resource id.
func refHas(typ, id string) func(*Item) bool {
	return func(it *Item) bool {
		return slices.ContainsFunc(it.Findings, func(r FindingRef) bool { return r.Type == typ && (id == "" || r.Resource == id) })
	}
}

// keyHas matches items by a part of their grouping key, which names the connector, resource type
// and check ("group:github|github_org_setting|check:org-2fa-not-required").
func keyHas(part string) func(*Item) bool {
	return func(it *Item) bool { return strings.Contains(it.Key, part) }
}

func titleHas(part string) func(*Item) bool {
	return func(it *Item) bool { return strings.Contains(strings.ToLower(it.Title), part) }
}

func anyOf(ms ...func(*Item) bool) func(*Item) bool {
	return func(it *Item) bool { return slices.ContainsFunc(ms, func(m func(*Item) bool) bool { return m(it) }) }
}

func allOf(ms ...func(*Item) bool) func(*Item) bool {
	return func(it *Item) bool {
		return !slices.ContainsFunc(ms, func(m func(*Item) bool) bool { return !m(it) })
	}
}

func severityAtLeast(rank int) func(*Item) bool {
	return func(it *Item) bool { return it.Severity.Rank() >= rank }
}

// blasts is the blast-radius table, first match wins; anything else is 1.
var blasts = []blast{
	{titleHas("is the login for"), 3, "one account opens the money and cloud accounts that sign in with it"},
	{anyOf(keyHas("check:org-2fa-not-required"), keyHas("check:org-members-without-2fa"), keyHas("check:org-outside-collaborators-without-2fa")), 3,
		"one stolen password opens every repository of those orgs"},
	{anyOf(refHas("macos_setting", "backup-none"), titleHas("no time machine backup")), 2.5, "a lost, stolen or encrypted Mac takes every file with it"},
	{allOf(keyHas("google-personal|oauth_grant"), severityAtLeast(3)), 2.5, "apps that can read or change the account's mail and files"},
	{refHas("macos_setting", "brave-remote-debugging"), 2, "any local program can drive the browser with your sessions"},
	{refHas("data_dump", ""), 2, "other people's data, with breach duties"},
	{anyOf(titleHas("can delete your repositories"), titleHas("read and write all your repositories")), 1.5, "write access to every repository you own"},
	{keyHas("check:org-default-repository-permission"), 1.5, "every member can change every repository"},
	{refHas("x_app", ""), 0.6, "old consumer apps; at worst they post as you"},
	{anyOf(refHas("azure_budget", ""), keyHas("|project|"), keyHas("|organization|")), 0.7, "money, bounded by the card on file"},
	{refHas("endpoint_agent", ""), 0.5, "leftovers, nothing running"},
}

// efforts is the effort table, first match wins; anything else is one change.
var efforts = []struct {
	match func(it *Item) bool
	value func(it *Item) float64
	why   func(it *Item) string
}{
	{func(it *Item) bool {
		return it.Kind == KindRotate && it.Next != nil && strings.HasPrefix(it.Next.Command, "segurata rotations replace")
	},
		fixed(1), says("rotate at the provider; segurata puts the new value in place")},
	{func(it *Item) bool { return it.Kind == KindRotate }, fixed(1.5), says("rotate at the provider and update its users by hand")},
	{refHas("data_dump", ""), fixed(3), says("a history rewrite and a force-push")},
	// A review list takes longer the more entries it has: 1 for a few, 3 at most.
	{func(it *Item) bool { return it.Kind == KindReview },
		func(it *Item) float64 { return math.Min(3, 1+float64(len(it.Findings))/20) },
		func(it *Item) string { return textfmt.Count(len(it.Findings), "entry", "entries") + " to go through" }},
}

func fixed(v float64) func(*Item) float64 { return func(*Item) float64 { return v } }
func says(s string) func(*Item) string    { return func(*Item) string { return s } }

// quickWinMin is how many findings one fix must close to count as a quick win.
const quickWinMin = 3

// Score rates an item for "Do next" (see the tables above). A decision is rated by what it
// unblocks: half the worth of those items, as a quick win.
func (t *Tracker) Score(it *Item, now time.Time) Score {
	if it.Kind == KindDecide {
		return t.decisionScore(it, now)
	}
	p := it.EffectivePriority()
	fs := []Factor{{"impact", impactOf(p), prioLabel(p)}}
	b := Factor{"blast", 1, ""}
	for _, row := range blasts {
		if row.match(it) {
			b.Value, b.Why = row.factor, row.why
			break
		}
	}
	fs = append(fs, b)
	if it.Kind == KindRotate {
		fs = append(fs, exposureFactor(it), livenessFactor(it))
	}
	fs = append(fs, confidenceFactor(it), t.effortFactor(it, now))
	return newScore(append(fs, quickWin(it))...)
}

func impactOf(p secretrisk.Priority) float64 {
	if v, ok := impacts[p]; ok {
		return v
	}
	return 0.5
}

func prioLabel(p secretrisk.Priority) string {
	if p == "" {
		return "no priority"
	}
	return string(p)
}

func exposureFactor(it *Item) Factor {
	switch w := it.worst(); w.Level {
	case secretrisk.Remote:
		return Factor{"exposure", 1.5, w.Label}
	case secretrisk.Local:
		return Factor{"exposure", 0.7, w.Label}
	}
	return Factor{"exposure", 1, ""}
}

func livenessFactor(it *Item) Factor {
	switch {
	case it.LiveAndLeaked():
		return Factor{"liveness", 2, "a connector shows it works, and it left the machine"}
	case len(it.live()) > 0:
		return Factor{"liveness", 1.5, "a connector shows it works"}
	case it.Owner() == attribution.Mine:
		return Factor{"liveness", 1.3, "attributed to one of your accounts"}
	case it.Owner() == attribution.NotMine:
		return Factor{"liveness", 0.3, "attributed to someone else's account"}
	}
	return Factor{"liveness", 1, ""}
}

func confidenceFactor(it *Item) Factor {
	switch {
	case it.Kind == KindRotate && it.Owner() != attribution.Mine && len(it.live()) == 0:
		return Factor{"confidence", 0.8, "nothing shows it is still valid"}
	case it.Kind == KindReview:
		return Factor{"confidence", 0.8, "some entries may be fine"}
	case strings.HasPrefix(it.Title, "Possible "):
		return Factor{"confidence", 0.7, "possibly not a real dump"}
	}
	return Factor{"confidence", 1, ""}
}

func (t *Tracker) effortFactor(it *Item, now time.Time) Factor {
	f := Factor{"effort", 1, "one change"}
	for _, row := range efforts {
		if row.match(it) {
			f.Value, f.Why = row.value(it), row.why(it)
			break
		}
	}
	if d := t.BlockedBy(it, now); d != nil {
		f.Value *= 2
		f.Why += "; waits on decision " + d.ID
	}
	return f
}

func quickWin(it *Item) Factor {
	switch {
	case it.Next != nil && it.Next.Who == Segurata:
		return Factor{"quick win", 1.5, "segurata does it after your confirmation"}
	case it.Kind == KindFix && len(it.Findings) >= quickWinMin:
		return Factor{"quick win", 1.5, fmt.Sprintf("one fix closes %d findings", len(it.Findings))}
	}
	return Factor{"quick win", 1, ""}
}

// decisionScore is worth half of what answering unblocks, as a quick win.
func (t *Tracker) decisionScore(d *Item, now time.Time) Score {
	sum := 0.0
	blocked := t.Unblocks(d, now)
	for _, it := range blocked {
		sum += t.Score(it, now).Total
	}
	if len(blocked) == 0 {
		return newScore(Factor{"impact", impactOf(d.EffectivePriority()), prioLabel(d.EffectivePriority())}, Factor{"effort", 1, "one answer"})
	}
	return newScore(Factor{"leverage", math.Round(sum*5) / 10, "half the worth of the " + textfmt.Count(len(blocked), "item", "items") + " it unblocks"},
		Factor{"effort", 1, "one answer"}, Factor{"quick win", 1.5, "answering unblocks " + textfmt.Count(len(blocked), "item", "items")})
}
