package tracker

import (
	"time"

	"github.com/segurata/segurata/internal/secretrisk"
)

// themes are created in every tracker, in this order (the briefing follows it).
var themes = []Theme{
	{"rotations", "Secrets to rotate", "One item per secret fingerprint found by local-secrets: rotate it at the provider, then put the new value where it is used."},
	{"data-dumps", "Data dumps in git", "Database dumps committed to repositories, one item per repository: purge them from history in one pass, rotate what they hold, check breach duties."},
	{"transcripts", "Trail files to redact", "Agent transcripts, shell histories and logs that still hold secrets in plaintext: segurata redact cleans the local copies."},
	{"mac", "This Mac", "macOS posture: backups, updates, sharing, ports, login items, endpoint agents."},
	{"browser-extensions", "Browser extensions", "Extensions that can read or drive your pages, one item per extension."},
	{"github-orgs", "GitHub", "Organizations and repositories you administer: 2FA, default permissions, Actions, secret scanning."},
	{"connected-apps", "Connected apps", "Third-party apps with access to GitHub, X, Slack, Notion, Facebook and other accounts."},
	{"google", "Google", "Apps with access to your Google accounts, and Workspace tenants."},
	{"cloud", "Cloud", "GCP, AWS, Azure, Cloudflare, Vercel and Supabase: keys, roles, budgets."},
	{"ai-spend", "AI providers", "OpenAI, Anthropic and OpenRouter keys, limits and spend."},
	{coverageTheme, "Not audited here", "Areas of the plan no connector checks on this machine, with the step that would cover each: not failures."},
	{"setup", "Setup", "What keeps segurata from seeing an account: sign-ins, missing credentials, missing scopes, connector errors."},
	{"decisions", "Decisions", "Questions only you can answer before the related work can go ahead."},
	{"other", "Other", "Findings of connectors without a theme of their own, and items added by hand."},
}

// coverageTheme holds the review items for what no connector audits on this machine (coverage.go);
// status lists them apart from what is failing.
const coverageTheme = "coverage"

// connectorThemes maps a connector to its theme; local-secrets depends on the resource type.
var connectorThemes = map[string]string{
	"macos": "mac", "browser-extensions": "browser-extensions", "github": "github-orgs",
	"connected-apps": "connected-apps", "google-personal": "google", "workspace": "google",
	"gcp": "cloud", "aws": "cloud", "azure": "cloud", "cloudflare": "cloud", "vercel": "cloud", "supabase": "cloud",
	"openai": "ai-spend", "anthropic": "ai-spend", "openrouter": "ai-spend",
}

func themeOf(connector, resourceType string) string {
	if connector == SecretsConnector {
		if resourceType == "data_dump" {
			return "data-dumps"
		}
		return "rotations"
	}
	if th, ok := connectorThemes[connector]; ok {
		return th
	}
	return "other"
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
