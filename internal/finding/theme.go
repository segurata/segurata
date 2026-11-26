package finding

// Theme is the part of the tracker's briefing a connector's items go to (docs/connectors.md,
// "Theme and grouping").
type Theme struct {
	ID          string `json:"id"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
}

// The shared themes, which a connector names by id alone.
var (
	ThemeMac               = Theme{"mac", "This Mac", "macOS posture: backups, updates, sharing, ports, login items, endpoint agents."}
	ThemeBrowserExtensions = Theme{"browser-extensions", "Browser extensions", "Extensions that can read or drive your pages, one item per extension."}
	ThemeGitHub            = Theme{"github-orgs", "GitHub", "Organizations and repositories you administer: 2FA, default permissions, Actions, secret scanning."}
	ThemeConnectedApps     = Theme{"connected-apps", "Connected apps", "Third-party apps with access to GitHub, X, Slack, Notion, Facebook and other accounts."}
	ThemeGoogle            = Theme{"google", "Google", "Apps with access to your Google accounts, and Workspace tenants."}
	ThemeCloud             = Theme{"cloud", "Cloud", "GCP, AWS, Azure, Cloudflare, Vercel and Supabase: keys, roles, budgets."}
	ThemeAISpend           = Theme{"ai-spend", "AI providers", "OpenAI, Anthropic and OpenRouter keys, limits and spend."}
)

var ThemeOther = Theme{"other", "Other", "Findings of connectors without a theme of their own, and items added by hand."}

// Themes are in briefing order.
var Themes = []Theme{ThemeMac, ThemeBrowserExtensions, ThemeGitHub, ThemeConnectedApps, ThemeGoogle, ThemeCloud, ThemeAISpend}

// ThemeFor resolves a declaration: a shared theme by id (ThemeOther for none), else the declaration
// titled by its id when it gives no title.
func ThemeFor(declared Theme) Theme {
	if declared.ID == "" || declared.ID == ThemeOther.ID {
		return ThemeOther
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
