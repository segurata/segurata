package connectedapps

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/textfmt"
)

// A Slack app's capabilities, from the scopes declared for its bot and its user token (which acts
// as the person who installed it). Scopes: https://docs.slack.dev/reference/scopes.
type slackCap string

const (
	capAdmin      slackCap = "admin"
	capReadAsUser slackCap = "read_as_user"
	capPostAsUser slackCap = "post_as_user"
	capPost       slackCap = "post"
	capPostPublic slackCap = "post_public"
	capCustomize  slackCap = "post_customized"
	capHistory    slackCap = "read_history"
	capFiles      slackCap = "files"
	capEmails     slackCap = "emails"
	capWebhook    slackCap = "webhook"
)

// slackScopeCaps match "bot:<scope>" or "user:<scope>"; every match counts.
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

// slackCapLabels complete "<App> can …", in title order.
var slackCapLabels = []struct {
	cap   slackCap
	label string
}{
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

// slackSeverityRules apply, worst first, when the app has a capability of every group. Posting
// together with reading history is high: anyone who writes in the conversation can steer it.
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

func slackCaps(bot, user []string) map[slackCap]bool {
	caps := map[slackCap]bool{}
	for prefix, scopes := range map[string][]string{"bot:": bot, "user:": user} {
		for _, s := range scopes {
			for _, r := range slackScopeCaps {
				if r.re.MatchString(prefix + s) {
					caps[r.cap] = true
				}
			}
		}
	}
	return caps
}

// slackGrade: an app with no listed capability reads workspace metadata or adds commands.
func slackGrade(caps map[slackCap]bool) (finding.Severity, string) {
	has := func(c slackCap) bool { return caps[c] }
	lacks := func(group []slackCap) bool { return !slices.ContainsFunc(group, has) }
	sev := finding.SevLow
	for _, r := range slackSeverityRules {
		if !slices.ContainsFunc(r.need, lacks) {
			sev = r.sev
			break
		}
	}
	var labels []string
	for _, l := range slackCapLabels {
		if caps[l.cap] {
			labels = append(labels, l.label)
		}
	}
	if len(labels) == 0 {
		return sev, "see the workspace's channels and members"
	}
	return sev, textfmt.JoinAnd(labels)
}

func slackCapList(caps map[slackCap]bool) []string {
	out := []string{}
	for _, l := range slackCapLabels {
		if caps[l.cap] {
			out = append(out, string(l.cap))
		}
	}
	return out
}

// slackSeverity grades an app by its declared scopes or, when only the page's rows show it, by
// its scope count: fifteen or more nearly always include posting and reading history.
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
