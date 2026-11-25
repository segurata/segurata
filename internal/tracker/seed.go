package tracker

import (
	"maps"
	"slices"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// themes are created in every tracker, in this order (the briefing follows it): the tracker's own
// around the ones connectors share. A connector's own theme is added when a run declares it
// (declareThemes).
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

// coverageTheme holds the review items for what no connector audits on this machine (coverage.go);
// status lists them apart from what is failing.
const coverageTheme = "coverage"

// connectorThemes maps a connector that does not declare its theme yet to it.
var connectorThemes = map[string]string{
	"prowler":   "cloud",
	"anthropic": "ai-spend", "openrouter": "ai-spend",
}

// themeOf is the theme of a finding whose run declared the theme declared ("" for none). The
// tracker files local-secrets findings itself: data dumps apart from the secrets to rotate.
func themeOf(f finding.Finding, declared string) string {
	if f.Connector == SecretsConnector {
		if f.Resource.Type == "data_dump" {
			return "data-dumps"
		}
		return "rotations"
	}
	if declared != "" && declared != finding.ThemeOther.ID {
		return declared
	}
	if th, ok := connectorThemes[f.Connector]; ok {
		return th
	}
	return finding.ThemeOther.ID
}

// declareThemes adds, or renames, the themes of their own that the folded runs declare. A theme
// segurata defines keeps its own title and description.
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

// seedDecision is an open question the owner already knows about.
type seedDecision struct {
	slug, question string
	options        []string
	priority       secretrisk.Priority
}

// seedDecisions are generic questions every installation faces, created once each when absent;
// answering or ignoring one keeps it from coming back. Questions about one owner's own projects
// are added with `segurata track add --kind decide` and live only in that owner's tracker.
var seedDecisions = []seedDecision{
	{"daily-schedule", "Install the daily scheduled inventory?",
		[]string{"yes: segurata schedule install --apply", "not now"}, secretrisk.P3},
}

// seed adds the themes and seeded decisions that are missing. A theme segurata defines keeps the
// title and description of this version, so renaming one here renames it in every tracker.
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
		if t.ByKey("decide:"+d.slug) == nil {
			it := t.AddDecision("decide:"+d.slug, d.question, d.options, now)
			it.Priority = d.priority
		}
	}
}

// AddDecision creates a decide item.
func (t *Tracker) AddDecision(key, question string, options []string, now time.Time) *Item {
	it := t.newItem(KindDecide, key, "decisions", question, now)
	it.Decision = &Decision{Question: question, Options: options}
	it.Priority, it.Severity = secretrisk.P2, "medium"
	it.Next = &Next{Who: You, Action: "Decide: " + question, Command: "segurata track decide " + it.ID + ` --answer "…"`}
	it.Log(now, EvFound, actFound, "decision to take")
	return it
}

// ThemeTitle is the title of a theme id, or the id itself.
func (t *Tracker) ThemeTitle(id string) string {
	for _, th := range t.Themes {
		if th.ID == id {
			return th.Title
		}
	}
	return id
}
