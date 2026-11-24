package connectedapps

import (
	"fmt"
	"regexp"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/textfmt"
)

// A Slack app's capabilities, read from the scopes a workspace's app list declares for it: the
// bot's, and the user token's (which acts as the person who installed the app). Scope names:
// https://docs.slack.dev/reference/scopes.
type slackCap string

const (
	capAdmin      slackCap = "admin"           // admin.* scopes
	capReadAsUser slackCap = "read_as_user"    // history or search with a user token
	capPostAsUser slackCap = "post_as_user"    // chat:write with a user token
	capPost       slackCap = "post"            // chat:write as the bot
	capPostPublic slackCap = "post_public"     // chat:write.public: channels it was not invited to
	capCustomize  slackCap = "post_customized" // chat:write.customize: any name and icon
	capHistory    slackCap = "read_history"    // history or search as the bot
	capFiles      slackCap = "files"           // files and remote files
	capEmails     slackCap = "emails"          // users:read.email
	capWebhook    slackCap = "webhook"         // incoming-webhook: posts to one channel
)

// slackScopeCaps map a scope, written "bot:<scope>" or "user:<scope>", to the capability it gives.
// Every rule that matches counts.
var slackScopeCaps = []struct {
	re  *regexp.Regexp
	cap slackCap
}{
	{regexp.MustCompile(`^(bot|user):admin(\.|$)`), capAdmin},
	{regexp.MustCompile(`^user:((channels|groups|im|mpim):history|search:read(\.\w+)?)$`), capReadAsUser},
	{regexp.MustCompile(`^user:chat:write(:user)?$`), capPostAsUser},
	{regexp.MustCompile(`^bot:chat:write(:bot)?$`), capPost},
	{regexp.MustCompile(`^bot:chat:write\.public$`), capPostPublic},
	{regexp.MustCompile(`^bot:chat:write\.customize$`), capCustomize},
	{regexp.MustCompile(`^bot:((channels|groups|im|mpim):history|search:read(\.\w+)?)$`), capHistory},
	{regexp.MustCompile(`^(bot|user):(remote_)?files:(read|write)(:user)?$`), capFiles},
	{regexp.MustCompile(`^(bot|user):users:read\.email$`), capEmails},
	{regexp.MustCompile(`^bot:incoming-webhook$`), capWebhook},
}

// slackCapLabel is a capability and the words for it.
type slackCapLabel struct {
	cap   slackCap
	label string
}

// slackCapLabels complete "<App> can …", in the order a title lists them.
var slackCapLabels = []slackCapLabel{
	{capAdmin, "administer the workspace"},
	{capReadAsUser, "read messages as the person who installed it, direct messages included"},
	{capPostAsUser, "post as the person who installed it"},
	{capPost, "post as a bot"},
	{capPostPublic, "post in public channels it was not added to"},
	{capCustomize, "post under any name and icon"},
	{capHistory, "read the history of the conversations it is in"},
	{capFiles, "read and upload files"},
	{capEmails, "see members' email addresses"},
	{capWebhook, "post to a channel through an incoming webhook"},
}

// slackSeverityRules grade an app by its capabilities, worst first: a rule applies when every one
// of its groups has a capability the app has. Administering the workspace or reading messages as a
// person is high, and so is posting together with reading history (an app that can read a
// conversation and answer in it can be steered by anyone who writes there); posting, reading
// history or files alone is medium; emails and an incoming webhook are low.
var slackSeverityRules = []struct {
	need [][]slackCap
	sev  finding.Severity
}{
	{[][]slackCap{{capAdmin}}, finding.SevHigh},
	{[][]slackCap{{capReadAsUser}}, finding.SevHigh},
	{[][]slackCap{{capPost, capPostAsUser, capPostPublic, capCustomize}, {capHistory}}, finding.SevHigh},
	{[][]slackCap{{capPost, capPostAsUser, capPostPublic, capCustomize, capHistory, capFiles}}, finding.SevMedium},
	{[][]slackCap{{capEmails, capWebhook}}, finding.SevLow},
}

// slackCaps are the capabilities of an app's bot and user scopes.
func slackCaps(bot, user []string) map[slackCap]bool {
	caps := map[slackCap]bool{}
	scopes := make([]string, 0, len(bot)+len(user))
	for _, s := range bot {
		scopes = append(scopes, "bot:"+s)
	}
	for _, s := range user {
		scopes = append(scopes, "user:"+s)
	}
	for _, s := range scopes {
		for _, r := range slackScopeCaps {
			if r.re.MatchString(s) {
				caps[r.cap] = true
			}
		}
	}
	return caps
}

// slackGrade is the severity and label of an app with these capabilities. An app with none of
// them reads workspace metadata (channel names, members, reactions) or adds commands: low.
func slackGrade(caps map[slackCap]bool) (finding.Severity, string) {
	sev := slackCapSeverity(caps)
	var labels []string
	for _, l := range present(caps) {
		labels = append(labels, l.label)
	}
	if len(labels) == 0 {
		return sev, "see the workspace's channels and members"
	}
	return sev, textfmt.JoinAnd(labels)
}

// slackCapSeverity is the severity of the first rule whose every group the capabilities meet, or
// low when none applies.
func slackCapSeverity(caps map[slackCap]bool) finding.Severity {
	for _, r := range slackSeverityRules {
		if meetsAll(caps, r.need) {
			return r.sev
		}
	}
	return finding.SevLow
}

// present are the labels of the capabilities an app has, in title order.
func present(caps map[slackCap]bool) []slackCapLabel {
	var out []slackCapLabel
	for _, l := range slackCapLabels {
		if caps[l.cap] {
			out = append(out, l)
		}
	}
	return out
}

// slackCapList names the capabilities in title order, for evidence.
func slackCapList(caps map[slackCap]bool) []string {
	out := []string{}
	for _, l := range present(caps) {
		out = append(out, string(l.cap))
	}
	return out
}

// meetsAll reports whether caps has a capability of every group.
func meetsAll(caps map[slackCap]bool, groups [][]slackCap) bool {
	for _, g := range groups {
		if !anyCap(caps, g) {
			return false
		}
	}
	return true
}

func anyCap(caps map[slackCap]bool, of []slackCap) bool {
	for _, c := range of {
		if caps[c] {
			return true
		}
	}
	return false
}

// slackSeverity grades a Slack app. One the workspace's app list declares scopes for is graded by
// what they let it do; one only the page's rows show (waiting for approval, or the list did not
// load) by its scope count: fifteen or more nearly always include posting and reading history.
func slackSeverity(g grant) (finding.Severity, string) {
	if g.extra["pending_approval"] == true {
		return finding.SevInfo, "be installed once a workspace admin approves it"
	}
	if g.scopes != nil || g.userScopes != nil {
		return slackGrade(slackCaps(g.scopes, g.userScopes))
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
