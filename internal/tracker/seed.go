package tracker

import (
	"cmp"
	"maps"
	"slices"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// themes are created in every tracker, in briefing order; a connector's own theme is added when a
// run declares it.
var themes = slices.Concat([]Theme{
	{ID: "rotations", Title: "Secrets to rotate", Description: "One item per secret fingerprint found by local-secrets: rotate it at the provider, then put the new value where it is used."},
	{ID: "data-dumps", Title: "Data dumps in git", Description: "Database dumps committed to repositories, one item per repository: purge them from history in one pass, rotate what they hold, check breach duties."},
	{ID: "transcripts", Title: "Trail files to redact", Description: "Agent transcripts, shell histories and logs that still hold secrets in plaintext: segurata redact cleans the local copies."},
}, finding.Themes, []Theme{
	{ID: coverageTheme, Title: "Not audited here", Description: "Areas of the plan no connector checks on this machine, with the step that would cover each: not failures."},
	{ID: "setup", Title: "Setup", Description: "What keeps segurata from seeing an account: sign-ins, missing credentials, missing scopes, connector errors."},
	{ID: "decisions", Title: "Decisions", Description: "Questions only you can answer before the related work can go ahead."},
	finding.ThemeOther,
})

const coverageTheme = "coverage"

// themeOf is the theme of a finding whose run declared the theme declared ("" for none).
func themeOf(f finding.Finding, declared string) string {
	if f.Connector == secretrisk.ConnectorName {
		if f.Resource.Type == "data_dump" {
			return "data-dumps"
		}
		return "rotations"
	}
	return cmp.Or(declared, finding.ThemeOther.ID)
}

// declareThemes adds or renames the connector themes the folded runs declare; segurata's own
// themes keep their titles.
func (t *Tracker) declareThemes(folded map[string]*run) {
	labels := slices.Sorted(maps.Keys(folded))
	for _, l := range labels {
		th := folded[l].theme
		if th.ID == "" || slices.ContainsFunc(themes, func(d Theme) bool { return d.ID == th.ID }) {
			continue
		}
		if i := slices.IndexFunc(t.Themes, func(d Theme) bool { return d.ID == th.ID }); i >= 0 {
			t.Themes[i] = th
		} else {
			t.Themes = append(t.Themes, th)
		}
	}
}

type seedDecision struct {
	slug, question string
	options        []string
	priority       secretrisk.Priority
}

// seedDecisions are questions every installation faces, created once when absent; answering or
// ignoring one keeps it from coming back.
var seedDecisions = []seedDecision{
	{"daily-schedule", "Install the daily scheduled inventory?",
		[]string{"yes: segurata schedule install --apply", "not now"}, secretrisk.P3},
}

// seed adds missing themes and seeded decisions, and renames segurata's themes to this version's
// titles.
func (t *Tracker) seed(now time.Time) {
	defined := map[string]Theme{}
	for _, th := range themes {
		defined[th.ID] = th
	}
	have := map[string]bool{}
	for i, th := range t.Themes {
		have[th.ID] = true
		if def, ok := defined[th.ID]; ok {
			t.Themes[i] = def
		}
	}
	for _, th := range themes {
		if !have[th.ID] {
			t.Themes = append(t.Themes, th)
		}
	}
	for _, d := range seedDecisions {
		if t.itemByKey("decide:"+d.slug) == nil {
			it := t.addDecision("decide:"+d.slug, d.question, d.options, now)
			it.Priority = d.priority
		}
	}
}

func (t *Tracker) addDecision(key, question string, options []string, now time.Time) *Item {
	it := t.newItem(KindDecide, key, "decisions", question, now)
	it.Decision = &Decision{Question: question, Options: options}
	it.Priority, it.Severity = secretrisk.P2, "medium"
	it.Next = &Next{Who: You, Action: "Decide: " + question, Command: "segurata track decide " + it.ID + ` --answer "…"`}
	it.Log(now, EvFound, actFound, "decision to take")
	return it
}

func (t *Tracker) themeTitle(id string) string {
	for _, th := range t.Themes {
		if th.ID == id {
			return th.Title
		}
	}
	return id
}
