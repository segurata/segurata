package finding

// Theme is the part of the tracker's briefing a connector's items go to. A connector declares one
// in its description (docs/connectors.md, "Theme and grouping"); the core writes it, resolved by
// ThemeFor, into every run_end record, and the tracker files the run's items under it. A connector
// that declares none goes to "other".
type Theme struct {
	ID          string `json:"id"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
}

// The themes connectors share, in the order the briefing lists them. A connector names one of these
// by its id alone; its title and description are the ones here.
var (
	ThemeMac               = Theme{"mac", "This Mac", "macOS posture: backups, updates, sharing, ports, login items, endpoint agents."}
	ThemeBrowserExtensions = Theme{"browser-extensions", "Browser extensions", "Extensions that can read or drive your pages, one item per extension."}
	ThemeGitHub            = Theme{"github-orgs", "GitHub", "Organizations and repositories you administer: 2FA, default permissions, Actions, secret scanning."}
	ThemeConnectedApps     = Theme{"connected-apps", "Connected apps", "Third-party apps with access to GitHub, X, Slack, Notion, Facebook and other accounts."}
	ThemeGoogle            = Theme{"google", "Google", "Apps with access to your Google accounts, and Workspace tenants."}
	ThemeCloud             = Theme{"cloud", "Cloud", "GCP, AWS, Azure, Cloudflare, Vercel and Supabase: keys, roles, budgets."}
	ThemeAISpend           = Theme{"ai-spend", "AI providers", "OpenAI, Anthropic and OpenRouter keys, limits and spend."}
)

// Themes are the shared themes in briefing order.
var Themes = []Theme{ThemeMac, ThemeBrowserExtensions, ThemeGitHub, ThemeConnectedApps, ThemeGoogle, ThemeCloud, ThemeAISpend}

// ThemeFor is the theme a declaration stands for: a shared theme's own title and description when
// it names one by id, otherwise the declaration with its id as the title when it gives none. A
// declaration without an id is no theme.
func ThemeFor(declared Theme) Theme {
	if declared.ID == "" {
		return Theme{}
	}
	for _, th := range Themes {
		if th.ID == declared.ID {
			return th
		}
	}
	if declared.Title == "" {
		declared.Title = declared.ID
	}
	return declared
}
