package connectedapps

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

// rule classifies one permission line. label completes "<App> can …".
type rule struct {
	re    *regexp.Regexp
	sev   finding.Severity
	label string
}

func rx(s string) *regexp.Regexp { return regexp.MustCompile(`(?i)` + s) }

// scopeRules per service, worst first. The worst match over all of an app's scopes wins, and
// between scopes of the same severity the earlier rule names the risk. The policy: write access, reading direct messages, deleting repositories,
// administering organizations and billing are high; broad read-only access is medium; profile
// and email are low or info.
var scopeRules = map[string][]rule{
	"github": {
		{rx(`^Delete repositories`), finding.SevHigh, "delete your repositories"},
		{rx(`^Full control of orgs and teams|admin:org|^Full control of enterprises`), finding.SevHigh, "administer your organizations and teams"},
		{rx(`billing`), finding.SevHigh, "manage your billing"},
		{rx(`^Full control of private repositories`), finding.SevHigh, "read and write all your repositories, private ones included"},
		{rx(`^Access public repositories`), finding.SevHigh, "write to your public repositories"},
		{rx(`^Update github action workflows`), finding.SevHigh, "change your GitHub Actions workflows"},
		{rx(`^(Full control|Write) .*(public keys|gpg keys|signing keys)`), finding.SevHigh, "add keys to your account"},
		{rx(`^(Full control|Write) .*hooks`), finding.SevHigh, "change your repository and organization webhooks"},
		{rx(`^Full control of codespaces`), finding.SevHigh, "create and use codespaces as you"},
		{rx(`^(Upload|Write|Delete) packages`), finding.SevHigh, "publish and delete your packages"},
		{rx(`^Update ALL user data`), finding.SevHigh, "change your profile"},
		{rx(`^(Full control|Write|Update|Delete)`), finding.SevHigh, "change things in your account"},
		{rx(`^Create gists`), finding.SevMedium, "create gists as you"},
		{rx(`^Download packages`), finding.SevMedium, "download your private packages"},
		{rx(`^Access (commit|deployment) status`), finding.SevMedium, "read and set commit or deployment statuses"},
		{rx(`^Read org|^Read .*team`), finding.SevLow, "see your organization and team membership"},
		{rx(`^Read all user profile data|^Read user`), finding.SevLow, "see your profile"},
		{rx(`email addresses`), finding.SevLow, "see your email addresses"},
		{rx(`notifications`), finding.SevLow, "see your notifications"},
	},
	"x": {
		{rx(`^dm\.read$`), finding.SevHigh, "read your direct messages"},
		{rx(`^dm\.write$`), finding.SevHigh, "send direct messages as you"},
		{rx(`billing`), finding.SevHigh, "manage your X developer billing"},
		{rx(`^ads\.write$`), finding.SevHigh, "run ads from your account"},
		{rx(`^write$|^tweet\.write$`), finding.SevHigh, "post and delete posts as you"},
		{rx(`\.write$`), finding.SevHigh, "change your X account"},
		{rx(`^read$`), finding.SevMedium, "read your account, protected posts and follows included"},
		{rx(`^(tweet|follows|like|list|bookmark|mute|block|space|ads|calls|broadcast|media)\.read$`), finding.SevMedium, "read your posts, follows and lists"},
		{rx(`^users\.email$`), finding.SevLow, "see your email address"},
		{rx(`^users\.read$|^offline\.access$`), finding.SevInfo, "see your profile"},
	},
	"notion": {
		{rx(`update|insert|delete`), finding.SevHigh, "read and change the Notion pages shared with it"},
		{rx(`read content`), finding.SevMedium, "read the Notion pages shared with it"},
		{rx(`comments`), finding.SevLow, "read comments on the pages shared with it"},
		{rx(`user information`), finding.SevLow, "see the workspace's members"},
	},
	// Dropbox scopes as scoped apps list them; private: ones are Dropbox's own and match too.
	"dropbox": {
		{rx(`files\.permanent_delete`), finding.SevHigh, "permanently delete your files"},
		{rx(`files\.content\.write`), finding.SevHigh, "read and change the files in your Dropbox"},
		{rx(`sharing\.write`), finding.SevHigh, "share your files and change who can open them"},
		{rx(`\.write$`), finding.SevHigh, "change your Dropbox account and settings"},
		{rx(`files\.content\.read`), finding.SevMedium, "read the files in your Dropbox"},
		{rx(`files\.metadata\.read|sharing\.read|file_requests\.read|contacts\.read|comments\.read|activity\.read`), finding.SevMedium, "see your file names, sharing and contacts"},
		{rx(`account_info\.read`), finding.SevLow, "see your account information"},
		{rx(`^(openid|profile|email)$`), finding.SevInfo, "sign you in with Dropbox"},
	},
	"facebook": {
		{rx(`publish|post (on|for) you|on your behalf|publicar|en tu nombre|manage .*pages|administrar .*páginas|\bads\b|anuncios`), finding.SevHigh, "post or manage pages and ads as you"},
		{rx(`messages|mensajes`), finding.SevHigh, "read your messages"},
		{rx(`friends|amigos|photos|fotos|videos|vídeos|posts|publicaciones|likes|me gusta|birthday|cumpleaños|location|ubicación|hometown|ciudad|groups|grupos|events|eventos`), finding.SevMedium, "see your friends, posts or photos"},
		{rx(`email|correo`), finding.SevLow, "see your email address"},
		{rx(`name and profile picture|nombre y foto del perfil|gender|sexo|age range|edad`), finding.SevLow, "see your name and profile picture"},
	},
}

// assess returns a grant's severity and the label that completes "<name> can …". A grant last
// used more than a year ago goes up one level. A Notion integration the owner created is low:
// it is their own API token, whose leaks local-secrets reports.
func assess(service string, g grant) (finding.Severity, string) {
	sev, label := base(service, g)
	if g.stale {
		sev = raise(sev)
	}
	if g.resType == "notion_integration" && ownIntegration(g.publisher) && sev.Rank() > finding.SevLow.Rank() {
		sev = finding.SevLow
	}
	return sev, label
}

// youRE is how Notion marks the signed-in user in an owner column.
var youRE = regexp.MustCompile(`\((You|Tú|Tu)\)`)

func ownIntegration(owner string) bool { return youRE.MatchString(owner) }

func base(service string, g grant) (finding.Severity, string) {
	switch g.resType {
	case "github_app_authorized":
		return finding.SevMedium, "act on your behalf within its GitHub App permissions"
	case "github_app_installed":
		if strings.Contains(g.note, "Suspended") {
			return finding.SevLow, "act on your repositories again if it is unsuspended"
		}
		return finding.SevMedium, "act on the repositories it is installed on (its permissions need sudo mode to read)"
	case "github_session":
		return finding.SevInfo, "use your GitHub account from a signed-in browser"
	case "github_ssh_key":
		return finding.SevLow, "push to and pull from your repositories over SSH"
	case "github_ssh_signing_key", "github_gpg_key":
		return finding.SevInfo, "sign commits as you"
	case "slack_app":
		return slackSeverity(g)
	case "dropbox_app":
		return dropboxSeverity(service, g)
	}
	if len(g.scopes) == 0 {
		switch service {
		case "github":
			return finding.SevInfo, "sign you in with GitHub"
		case "x":
			return finding.SevLow, "sign you in with X"
		case "facebook":
			return finding.SevLow, "sign you in with Facebook"
		}
		return finding.SevMedium, "access your " + service + " account"
	}
	return worstScope(service, g.scopes)
}

// worstScope is the severity and label of the worst of a non-empty list of scopes.
func worstScope(service string, scopes []string) (finding.Severity, string) {
	worst, wi := classify(service, scopes[0])
	for _, s := range scopes[1:] {
		r, i := classify(service, s)
		if r.sev.Rank() > worst.sev.Rank() || r.sev == worst.sev && i < wi {
			worst, wi = r, i
		}
	}
	return worst.sev, worst.label
}

// classify finds the first rule of the service matching a scope, and its position. A scope no
// rule knows is data access of unknown reach: medium, after every rule.
func classify(service, scope string) (rule, int) {
	rules := scopeRules[service]
	for i, r := range rules {
		if r.re.MatchString(scope) {
			return r, i
		}
	}
	return rule{sev: finding.SevMedium, label: "access some of your " + service + " data"}, len(rules)
}

// slackSeverity works from the scope count, the only thing the workspace's app list shows.
// Fifteen or more scopes nearly always include posting and reading channel history.
func slackSeverity(g grant) (finding.Severity, string) {
	if g.extra["pending_approval"] == true {
		return finding.SevInfo, "be installed once a workspace admin approves it"
	}
	if g.count <= 0 {
		return finding.SevMedium, "act in " + g.scope
	}
	label := fmt.Sprintf("use %d permissions in %s", g.count, g.scope)
	switch {
	case g.count >= 15:
		return finding.SevHigh, label
	case g.count >= 5:
		return finding.SevMedium, label
	}
	return finding.SevLow, label
}

// raise moves a severity up one level, stopping at critical.
func raise(s finding.Severity) finding.Severity {
	switch s {
	case finding.SevInfo:
		return finding.SevLow
	case finding.SevLow:
		return finding.SevMedium
	case finding.SevMedium:
		return finding.SevHigh
	}
	return finding.SevCritical
}
