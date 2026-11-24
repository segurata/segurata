package connectedapps

import (
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		service, scope string
		want           finding.Severity
	}{
		{"github", "Delete repositories", finding.SevHigh},
		{"github", "Full control of orgs and teams, read and write org projects", finding.SevHigh},
		{"github", "Full control of private repositories", finding.SevHigh},
		{"github", "Access public repositories", finding.SevHigh},
		{"github", "Update github action workflows", finding.SevHigh},
		{"github", "Full control of user public keys", finding.SevHigh},
		{"github", "Full control of repository hooks", finding.SevHigh},
		{"github", "Full control of codespaces", finding.SevHigh},
		{"github", "Write packages to github package registry", finding.SevHigh},
		{"github", "Create gists", finding.SevMedium},
		{"github", "Download packages from github package registry", finding.SevMedium},
		{"github", "Read org and team membership, read org projects", finding.SevLow},
		{"github", "Read all user profile data", finding.SevLow},
		{"github", "Access user email addresses (read-only)", finding.SevLow},
		{"github", "Something GitHub adds next year", finding.SevMedium},
		{"x", "dm.read", finding.SevHigh},
		{"x", "dm.write", finding.SevHigh},
		{"x", "developer.billing.write", finding.SevHigh},
		{"x", "write", finding.SevHigh},
		{"x", "tweet.write", finding.SevHigh},
		{"x", "list.write", finding.SevHigh},
		{"x", "ads.write", finding.SevHigh},
		{"x", "read", finding.SevMedium},
		{"x", "tweet.read", finding.SevMedium},
		{"x", "users.email", finding.SevLow},
		{"x", "users.read", finding.SevInfo},
		{"x", "offline.access", finding.SevInfo},
		{"notion", "Read, update, and insert content and read user information", finding.SevHigh},
		{"notion", "Read content", finding.SevMedium},
		{"facebook", "Publish posts on your behalf", finding.SevHigh},
		{"facebook", "Administrar tus páginas", finding.SevHigh},
		{"facebook", "Friends list", finding.SevMedium},
		{"facebook", "Lista de amigos", finding.SevMedium},
		{"facebook", "Email address", finding.SevLow},
		{"facebook", "Nombre y foto del perfil", finding.SevLow},
		{"facebook", "Uploads", finding.SevMedium}, // unknown, and "ads" inside a word is not ads
	}
	for _, c := range cases {
		if got, _ := classify(c.service, c.scope); got.sev != c.want {
			t.Errorf("%s %q = %s, want %s", c.service, c.scope, got.sev, c.want)
		}
	}
}

func TestAssess(t *testing.T) {
	cases := []struct {
		name    string
		service string
		g       grant
		want    finding.Severity
		label   string
	}{
		{"worst scope wins", "github", grant{resType: "github_oauth_app", scopes: []string{"Read all user profile data", "Delete repositories"}}, finding.SevHigh, "delete your repositories"},
		{"between equals the earlier rule names it", "x", grant{scopes: []string{"write", "dm.read"}}, finding.SevHigh, "read your direct messages"},
		{"unknown scopes rank after known ones", "github", grant{resType: "github_oauth_app", scopes: []string{"Brand new scope", "Create gists"}}, finding.SevMedium, "create gists as you"},
		{"no scopes on GitHub", "github", grant{resType: "github_oauth_app"}, finding.SevInfo, "sign you in with GitHub"},
		{"no scopes on X", "x", grant{scopes: []string{}}, finding.SevLow, "sign you in with X"},
		{"no scopes on Facebook", "facebook", grant{}, finding.SevLow, "sign you in with Facebook"},
		{"no scopes elsewhere", "notion", grant{}, finding.SevMedium, "access your notion account"},
		{"stale low", "github", grant{resType: "github_oauth_app", scopes: []string{"Read all user profile data"}, stale: true}, finding.SevMedium, "see your profile"},
		{"stale high", "github", grant{resType: "github_oauth_app", scopes: []string{"Delete repositories"}, stale: true}, finding.SevCritical, "delete your repositories"},
		{"stale key", "github", grant{resType: "github_ssh_key", stale: true}, finding.SevMedium, "push to and pull from your repositories over SSH"},
		{"authorized app", "github", grant{resType: "github_app_authorized"}, finding.SevMedium, "act on your behalf within its GitHub App permissions"},
		{"suspended app", "github", grant{resType: "github_app_installed", note: "Suspended"}, finding.SevLow, "act on your repositories again if it is unsuspended"},
		{"signing key", "github", grant{resType: "github_gpg_key"}, finding.SevInfo, "sign commits as you"},
		{"slack 15", "slack", grant{resType: "slack_app", scope: "w.slack.com", count: 15}, finding.SevHigh, "use 15 permissions in w.slack.com"},
		{"slack 14", "slack", grant{resType: "slack_app", scope: "w.slack.com", count: 14}, finding.SevMedium, "use 14 permissions in w.slack.com"},
		{"slack 4", "slack", grant{resType: "slack_app", scope: "w.slack.com", count: 4}, finding.SevLow, "use 4 permissions in w.slack.com"},
		{"slack unknown", "slack", grant{resType: "slack_app", scope: "w.slack.com"}, finding.SevMedium, "act in w.slack.com"},
		{"slack pending", "slack", grant{resType: "slack_app", scope: "w.slack.com", count: 40, extra: map[string]any{"pending_approval": true}}, finding.SevInfo, "be installed once a workspace admin approves it"},
		// Declared scopes: graded by what they let the app do, whatever their number.
		{"slack admin scope", "slack", slackGrant([]string{"admin.users:read"}, nil), finding.SevHigh, "administer the workspace"},
		{"slack user-token history", "slack", slackGrant(nil, []string{"im:history"}), finding.SevHigh, "read messages as the person who installed it, direct messages included"},
		{"slack user-token search", "slack", slackGrant(nil, []string{"search:read.private", "users:read"}), finding.SevHigh, "read messages as the person who installed it, direct messages included"},
		{"slack post and history", "slack", slackGrant([]string{"chat:write", "channels:history", "users:read"}, nil), finding.SevHigh, "post as a bot and read the history of the conversations it is in"},
		{"slack post as user and bot history", "slack", slackGrant([]string{"groups:history"}, []string{"chat:write"}), finding.SevHigh, "post as the person who installed it and read the history of the conversations it is in"},
		{"slack post only", "slack", slackGrant([]string{"chat:write", "chat:write.public", "chat:write.customize", "commands"}, nil), finding.SevMedium,
			"post as a bot, post in public channels it was not added to and post under any name and icon"},
		{"slack history only", "slack", slackGrant([]string{"channels:history"}, nil), finding.SevMedium, "read the history of the conversations it is in"},
		{"slack files", "slack", slackGrant([]string{"files:read", "files:write"}, nil), finding.SevMedium, "read and upload files"},
		{"slack emails", "slack", slackGrant([]string{"users:read", "users:read.email"}, nil), finding.SevLow, "see members' email addresses"},
		{"slack webhook", "slack", slackGrant([]string{"incoming-webhook"}, nil), finding.SevLow, "post to a channel through an incoming webhook"},
		{"slack metadata", "slack", slackGrant([]string{"channels:read", "team:read", "reactions:read"}, nil), finding.SevLow, "see the workspace's channels and members"},
		{"slack no scopes", "slack", slackGrant([]string{}, []string{}), finding.SevLow, "see the workspace's channels and members"},
		// A user-token chat:write without history is posting only.
		{"slack user post only", "slack", slackGrant(nil, []string{"chat:write", "users:read"}), finding.SevMedium, "post as the person who installed it"},
		// Many scopes of metadata are still low: the count no longer decides.
		{"slack many metadata scopes", "slack", slackGrant([]string{"channels:read", "groups:read", "im:read", "mpim:read", "team:read", "users:read",
			"emoji:read", "reactions:read", "pins:read", "bookmarks:read", "links:read", "usergroups:read", "dnd:read", "calls:read", "commands", "app_mentions:read"}, nil),
			finding.SevLow, "see the workspace's channels and members"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := assess(c.service, c.g)
			if r.sev != c.want || r.label != c.label {
				t.Fatalf("got %s %q, want %s %q", r.sev, r.label, c.want, c.label)
			}
		})
	}
}

// A grant declares what it puts at stake beyond its severity: write access to every repository
// for GitHub scopes that give it, posting as you for any X app.
func TestAssessBlast(t *testing.T) {
	cases := []struct {
		service string
		g       grant
		want    finding.Blast
	}{
		{"github", grant{resType: "github_oauth_app", scopes: []string{"Read all user profile data", "Delete repositories"}}, finding.BlastAllRepos},
		{"github", grant{resType: "github_oauth_app", scopes: []string{"Full control of private repositories"}, stale: true}, finding.BlastAllRepos},
		{"github", grant{resType: "github_oauth_app", scopes: []string{"Read all user profile data"}}, ""},
		{"x", grant{resType: "x_app", scopes: []string{"users.read"}}, finding.BlastPosts},
		{"x", grant{resType: "x_app", scopes: []string{"write"}}, finding.BlastPosts},
		{"dropbox", grant{resType: "dropbox_app", scopes: []string{"files.content.write"}}, ""},
	}
	for _, c := range cases {
		if got := assess(c.service, c.g).blast; got != c.want {
			t.Errorf("%s %v: blast %q, want %q", c.service, c.g.scopes, got, c.want)
		}
	}
}

// slackGrant is a Slack app the workspace's app list declares these bot and user scopes for.
func slackGrant(bot, user []string) grant {
	if bot == nil && user != nil {
		bot = []string{}
	}
	return grant{resType: "slack_app", scope: "w.slack.com", scopes: bot, userScopes: user, count: len(bot) + len(user)}
}

func TestReportMarksStaleDates(t *testing.T) {
	rec := &recorder{}
	e := &env{service: "github", emit: rec, now: now, seen: map[string]int{}}
	recent, old := now.AddDate(0, -6, 0), now.AddDate(-2, 0, 0)
	e.report(grant{resType: "github_ssh_key", name: "recent", lastUsed: &recent})
	e.report(grant{resType: "github_ssh_key", name: "old", lastUsed: &old})
	if rec.findings[0].Severity != finding.SevLow || rec.findings[1].Severity != finding.SevMedium {
		t.Fatalf("severities %s %s", rec.findings[0].Severity, rec.findings[1].Severity)
	}
}

func TestStableIDsIgnoreURLsAndAccounts(t *testing.T) {
	emit := func(who, url string) string {
		rec := &recorder{}
		e := &env{service: "slack", emit: rec, now: now, seen: map[string]int{}}
		e.report(grant{who: who, scope: "w.slack.com", resType: "slack_app", name: "Bot", url: url})
		return rec.findings[0].ID
	}
	if emit("w.slack.com", "https://a/1") != emit("w.slack.com", "https://b/2") {
		t.Error("a different link changed the id")
	}
	other := &env{service: "slack", emit: &recorder{}, now: now, seen: map[string]int{}}
	other.report(grant{scope: "v.slack.com", resType: "slack_app", name: "Bot"})
	if other.emit.(*recorder).findings[0].ID == emit("w.slack.com", "") {
		t.Error("the same app in two workspaces needs two ids")
	}
}

func TestRaise(t *testing.T) {
	for in, want := range map[finding.Severity]finding.Severity{
		finding.SevInfo: finding.SevLow, finding.SevLow: finding.SevMedium, finding.SevMedium: finding.SevHigh,
		finding.SevHigh: finding.SevCritical, finding.SevCritical: finding.SevCritical,
	} {
		if got := raise(in); got != want {
			t.Errorf("raise(%s) = %s", in, got)
		}
	}
}
