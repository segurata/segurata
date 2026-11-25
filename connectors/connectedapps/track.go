package connectedapps

import (
	"strings"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/textfmt"
)

// appNouns name what a resource type is, one and several.
var appNouns = map[string][2]string{
	"x_app":                 {"X app", "X apps"},
	"github_oauth_app":      {"GitHub OAuth app", "GitHub OAuth apps"},
	"github_app_installed":  {"GitHub App", "GitHub Apps"},
	"github_app_authorized": {"authorized GitHub App", "authorized GitHub Apps"},
	"github_ssh_key":        {"GitHub SSH key", "GitHub SSH keys"},
	"notion_integration":    {"Notion integration", "Notion integrations"},
	"facebook_app":          {"Facebook app", "Facebook apps"},
	"dropbox_app":           {"Dropbox app", "Dropbox apps"},
	"microsoft_work_app":    {"work account app", "work account apps"},
}

// Track makes review items: a Slack workspace's apps by how broad their permissions are ("Review
// 3 Slack apps with broad permissions in acme"), and the apps of any other account that can do
// the same thing as one item, the count and noun in front of what they can do ("7 Notion
// integrations can read and change the Notion pages shared with them (your own integrations)").
func (c *Connector) Track(f finding.Finding) *finding.Track {
	if f.Resource.Type == "slack_app" {
		return &finding.Track{Group: finding.GroupAccountSeverity, Kind: finding.TrackReview, Noun: "Slack app", Nouns: "Slack apps",
			Title: "Review {count} with " + f.Severity.Pick("broad", "several", "few") + " permissions in " + strings.TrimPrefix(f.Account, "slack:")}
	}
	noun, ok := appNouns[f.Resource.Type]
	if !ok {
		noun = [2]string{"app", "apps"}
	}
	rest := f.Title
	if n := f.Resource.Name; n != "" && strings.HasPrefix(rest, n+" ") {
		rest = rest[len(n)+1:]
	}
	rest = textfmt.PluralPredicate(2, rest)
	one, many := lastWord(noun[0]), lastWord(noun[1])
	rest = strings.ReplaceAll(rest, "(your own "+one+")", "(your own "+many+")")
	return &finding.Track{Group: finding.GroupFamily, Kind: finding.TrackReview, Noun: noun[0], Nouns: noun[1],
		Title: "{count} " + rest, TitleOne: f.Title}
}

// lastWord is the head noun of an app noun: "integration" for "Notion integration".
func lastWord(s string) string {
	f := strings.Fields(s)
	return f[len(f)-1]
}
