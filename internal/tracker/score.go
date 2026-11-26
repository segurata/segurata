package tracker

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

// Factor is one term of a "Do next" score:
//
//	score = impact × blast × exposure × liveness × confidence ÷ effort × quick win
//
// Every factor comes from a table below and `status --explain` shows it, so the order can be argued
// with. See docs/architecture.md, "Do next".
type Factor struct {
	Name  string
	Value float64
	Why   string
}

// Score is an item's worth for "Do next".
type Score struct {
	Total   float64
	Factors []Factor
}

// explain is "27.0 = impact 6 (P1) × blast 3 (…) ÷ effort 1 (…)", without neutral factors.
func (s Score) explain() string {
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

func (s Score) factor(name string) Factor {
	for _, f := range s.Factors {
		if f.Name == name {
			return f
		}
	}
	return Factor{Name: name, Value: 1}
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

var impacts = map[secretrisk.Priority]float64{secretrisk.P0: 10, secretrisk.P1: 6, secretrisk.P2: 3, secretrisk.P3: 1}

// blasts weigh what a finding puts at stake beyond its severity; an item takes the first one its
// findings declare.
var blasts = []struct {
	blast  finding.Blast
	factor float64
	why    string
}{
	{finding.BlastLogin, 3, "one account opens the money and cloud accounts that sign in with it"},
	{finding.BlastOrgAccess, 3, "one stolen password opens every repository of those orgs"},
	{finding.BlastDevice, 2.5, "a lost, stolen or encrypted Mac takes every file with it"},
	{finding.BlastMailAndFiles, 2.5, "apps that can read or change the account's mail and files"},
	{finding.BlastBrowser, 2, "any local program can drive the browser with your sessions"},
	{finding.BlastPersonalData, 2, "other people's data, with breach duties"},
	{finding.BlastAllRepos, 1.5, "write access to every repository you own"},
	{finding.BlastOrgWrite, 1.5, "every member can change every repository"},
	{finding.BlastPosts, 0.6, "old consumer apps; at worst they post as you"},
	{finding.BlastMoney, 0.7, "money, bounded by the card on file"},
	{finding.BlastLeftovers, 0.5, "leftovers, nothing running"},
}

func refHas(typ string) func(*Item) bool {
	return func(it *Item) bool {
		return slices.ContainsFunc(it.Findings, func(r FindingRef) bool { return r.Type == typ })
	}
}

// efforts: first match wins; anything else is one change.
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
	{refHas("data_dump"), fixed(3), says("a history rewrite and a force-push")},
	{func(it *Item) bool { return it.Kind == KindReview },
		func(it *Item) float64 { return math.Min(3, 1+float64(len(it.Findings))/20) },
		func(it *Item) string { return textfmt.Count(len(it.Findings), "entry", "entries") + " to go through" }},
}

func fixed(v float64) func(*Item) float64 { return func(*Item) float64 { return v } }
func says(s string) func(*Item) string    { return func(*Item) string { return s } }

const quickWinMin = 3

func (t *Tracker) score(it *Item, now time.Time) Score {
	if it.Kind == KindDecide {
		return t.decisionScore(it, now)
	}
	p := it.EffectivePriority()
	fs := []Factor{{"impact", impactOf(p), prioLabel(p)}}
	fs = append(fs, blastFactor(it))
	if it.Kind == KindRotate {
		fs = append(fs, exposureFactor(it), livenessFactor(it))
	}
	fs = append(fs, confidenceFactor(it), t.effortFactor(it, now))
	return newScore(append(fs, quickWin(it))...)
}

func blastFactor(it *Item) Factor {
	for _, row := range blasts {
		if slices.ContainsFunc(it.Findings, func(r FindingRef) bool { return r.Blast == row.blast }) {
			return Factor{"blast", row.factor, row.why}
		}
	}
	return Factor{"blast", 1, ""}
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
	case it.liveAndLeaked():
		return Factor{"liveness", 2, "a connector or the provider shows it works, and it left the machine"}
	case it.provenLive():
		return Factor{"liveness", 1.5, "a connector or the provider shows it works"}
	case it.Owner() == attribution.Mine:
		return Factor{"liveness", 1.3, "attributed to one of your accounts"}
	case it.Owner() == attribution.NotMine:
		return Factor{"liveness", 0.3, "attributed to someone else's account"}
	}
	return Factor{"liveness", 1, ""}
}

func confidenceFactor(it *Item) Factor {
	switch {
	case it.Kind == KindRotate && it.Owner() != attribution.Mine && !it.provenLive():
		return Factor{"confidence", 0.8, "nothing shows it is still valid"}
	case it.Kind == KindReview:
		return Factor{"confidence", 0.8, "some entries may be fine"}
	case len(it.Findings) > 0 && !slices.ContainsFunc(it.Findings, func(r FindingRef) bool { return !r.Unconfirmed }):
		return Factor{"confidence", 0.7, "possibly not a real problem"}
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
	if d := t.blockedBy(it, now); d != nil {
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

// decisionScore is half the worth of what answering unblocks, as a quick win.
func (t *Tracker) decisionScore(d *Item, now time.Time) Score {
	sum := 0.0
	blocked := t.unblocks(d, now)
	for _, it := range blocked {
		sum += t.score(it, now).Total
	}
	if len(blocked) == 0 {
		return newScore(Factor{"impact", impactOf(d.EffectivePriority()), prioLabel(d.EffectivePriority())}, Factor{"effort", 1, "one answer"})
	}
	return newScore(Factor{"leverage", math.Round(sum*5) / 10, "half the worth of the " + textfmt.Count(len(blocked), "item", "items") + " it unblocks"},
		Factor{"effort", 1, "one answer"}, Factor{"quick win", 1.5, "answering unblocks " + textfmt.Count(len(blocked), "item", "items")})
}
