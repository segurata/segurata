package tracker

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

// Grouping turns findings into items: one item per thing a person would do. Five GitHub orgs that
// do not require 2FA are one item (one settings page, five times); each data dump is its own item;
// thirty X apps that can post as you are one review. Info findings never make an item. Secrets are
// grouped by fingerprint elsewhere (secret.go); connector statuses become setup items (sync.go).

type groupBy int

const (
	perFinding         groupBy = iota // one item per finding
	perCheck                          // one item per check (resource id) across accounts
	perAccount                        // one item per account
	perAccountSeverity                // one item per account and severity
	perProject                        // one item per evidence.project
	perFamily                         // one item per account and title family (the title without the resource's name)
)

// rule maps findings of a connector and resource type (and, optionally, some resource ids) to how
// they group, the kind of item and its title. First match wins.
type rule struct {
	connectors []string // empty: any
	resource   string   // empty: any
	by         groupBy
	kind       Kind
	title      func(p *proposal) string // nil: the finding's title, or the family with a count
}

var rules = []rule{
	{connectors: []string{SecretsConnector}, resource: "data_dump", by: perFinding, kind: KindFix},
	{connectors: []string{"github"}, resource: "github_org_setting", by: perCheck, kind: KindFix, title: githubCheckTitle},
	{connectors: []string{"github"}, resource: "github_repo_setting", by: perCheck, kind: KindFix, title: githubCheckTitle},
	{connectors: []string{"github"}, resource: "github_repo", by: perAccount, kind: KindFix, title: func(p *proposal) string {
		return fmt.Sprintf("Repository security settings off in %s of %s", count(len(p.findings), "repository", "repositories"), p.account)
	}},
	{connectors: []string{"connected-apps"}, resource: "slack_app", by: perAccountSeverity, kind: KindReview, title: func(p *proposal) string {
		return fmt.Sprintf("Review %s with %s permissions in %s", count(len(p.findings), "Slack app", "Slack apps"),
			breadth(p.worst().Severity, "broad", "several", "few"), strings.TrimPrefix(p.account, "slack:"))
	}},
	{connectors: []string{"connected-apps"}, by: perFamily, kind: KindReview, title: appsTitle},
	{connectors: []string{"google-personal"}, resource: "oauth_grant", by: perAccountSeverity, kind: KindReview, title: func(p *proposal) string {
		return fmt.Sprintf("Review %s with %s access to %s", count(len(p.findings), "app", "apps"),
			breadth(p.worst().Severity, "high-risk", "broad", "limited"), p.account)
	}},
	{connectors: []string{"gcp"}, resource: "api_key", by: perProject, kind: KindFix, title: func(p *proposal) string {
		return fmt.Sprintf("Restrict %s in GCP project %s", count(len(p.findings), "API key", "API keys"), p.project)
	}},
	{connectors: []string{"gcp"}, resource: "service_account_key", by: perProject, kind: KindFix, title: func(p *proposal) string {
		return fmt.Sprintf("Rotate or delete %s in GCP project %s", count(len(p.findings), "user-managed service-account key", "user-managed service-account keys"), p.project)
	}},
	{connectors: []string{"gcp"}, resource: "service_account_role", by: perProject, kind: KindFix, title: func(p *proposal) string {
		return fmt.Sprintf("Narrow the roles of %s in GCP project %s", count(len(p.findings), "service account", "service accounts"), p.project)
	}},
	{connectors: []string{"openai", "anthropic", "openrouter"}, resource: "api_key", by: perAccountSeverity, kind: KindFix, title: func(p *proposal) string {
		s := fmt.Sprintf("Revoke or limit %s", count(len(p.findings), providerName(p.connector)+" API key", providerName(p.connector)+" API keys"))
		if p.instance != "" {
			s += " (" + p.instance + ")"
		}
		return s
	}},
	{connectors: []string{"macos", "aws"}, by: perFinding, kind: KindFix},
	{connectors: []string{"browser-extensions"}, by: perFinding, kind: KindReview},
	{by: perFamily, kind: KindFix},
}

// breadth words a group's worst severity: high and critical, medium, or lower.
func breadth(s finding.Severity, high, medium, low string) string {
	switch {
	case s.Rank() >= finding.SevHigh.Rank():
		return high
	case s == finding.SevMedium:
		return medium
	}
	return low
}

func providerName(connector string) string {
	return map[string]string{"openai": "OpenAI", "anthropic": "Anthropic", "openrouter": "OpenRouter"}[connector]
}

// githubChecks phrase each organization-level check the github connector reports.
var githubChecks = map[string]string{
	"org-2fa-not-required":                          "Two-factor authentication not required",
	"org-members-without-2fa":                       "Members without two-factor authentication",
	"org-outside-collaborators-without-2fa":         "Outside collaborators without two-factor authentication",
	"org-default-repository-permission":             "Every member can write to every repository",
	"org-default-workflow-permissions-write":        "Workflows get a read and write GITHUB_TOKEN by default",
	"org-all-actions-allowed":                       "Workflows may use any action from any author",
	"org-actions-can-approve-pull-requests":         "Workflows can create and approve pull requests",
	"org-members-can-create-public-repos":           "Members can create public repositories",
	"org-new-public-repos-without-secret-scanning":  "New public repositories get no secret scanning or push protection",
	"org-new-private-repos-without-secret-scanning": "New private repositories get no secret scanning or push protection",
	"dependabot-security-updates-disabled":          "Repositories without Dependabot security updates",
	"fork-secret-scanning-disabled":                 "Forks without secret scanning or push protection",
	"fork-workflow-write":                           "Forks whose workflows get a read and write GITHUB_TOKEN",
	"private-secret-scanning-disabled":              "Private repositories without secret scanning or push protection",
}

func githubCheckTitle(p *proposal) string {
	phrase, ok := githubChecks[p.check]
	if !ok {
		phrase = strings.ReplaceAll(strings.TrimPrefix(p.check, "org-"), "-", " ")
	}
	return phrase + " in " + count(len(p.accounts()), "GitHub org", "GitHub orgs")
}

// appNouns name what a connected-apps resource type is.
var appNouns = map[string][2]string{
	"x_app":                {"X app", "X apps"},
	"github_oauth_app":     {"GitHub OAuth app", "GitHub OAuth apps"},
	"github_app_installed": {"GitHub App", "GitHub Apps"},
	"github_ssh_key":       {"GitHub SSH key", "GitHub SSH keys"},
	"notion_integration":   {"Notion integration", "Notion integrations"},
	"facebook_app":         {"Facebook app", "Facebook apps"},
}

func appsTitle(p *proposal) string {
	if len(p.findings) == 1 {
		return p.findings[0].Title
	}
	noun, ok := appNouns[p.resource]
	if !ok {
		noun = [2]string{"app", "apps"}
	}
	return count(len(p.findings), noun[0], noun[1]) + " " + stripName(p.findings[0])
}

var (
	quoted = regexp.MustCompile(`"[^"]*"`)
	digits = regexp.MustCompile(`[0-9]+`)
)

// stripName is a finding's title without the resource's name in front: "Flickr can post and
// delete posts as you" becomes "can post and delete posts as you".
func stripName(f finding.Finding) string {
	if n := f.Resource.Name; n != "" && strings.HasPrefix(f.Title, n+" ") {
		return f.Title[len(n)+1:]
	}
	return f.Title
}

// family is what findings of one kind share in their titles: the name left out, quoted names and
// numbers blanked.
func family(f finding.Finding) string {
	return digits.ReplaceAllString(quoted.ReplaceAllString(stripName(f), `"…"`), "N")
}

func (r rule) matches(f finding.Finding) bool {
	if r.resource != "" && r.resource != f.Resource.Type {
		return false
	}
	return len(r.connectors) == 0 || slices.Contains(r.connectors, f.Connector)
}

func ruleFor(f finding.Finding) *rule {
	for i := range rules {
		if rules[i].matches(f) {
			return &rules[i]
		}
	}
	return &rules[len(rules)-1]
}

// proposal is what one sync says an item should hold.
type proposal struct {
	key, theme, connector, instance, resource string
	account, project, check                   string
	kind                                      Kind
	rule                                      *rule
	findings                                  []finding.Finding
	refs                                      []FindingRef
	maxSeverity                               finding.Severity // "" for no cap
	title                                     string           // set for proposals not made of findings by a rule
	next                                      *Next
}

// groupKey is the item key of a finding under its rule.
func groupKey(f finding.Finding, r *rule) (key string, p proposal) {
	lbl := label(f.Connector, f.Instance)
	p = proposal{theme: themeOf(f.Connector, f.Resource.Type), connector: f.Connector, instance: f.Instance,
		resource: f.Resource.Type, account: f.Account, kind: r.kind, rule: r}
	base := "group:" + lbl + "|" + f.Resource.Type
	switch r.by {
	case perCheck:
		p.check = f.Resource.ID
		key = base + "|check:" + p.check
	case perAccount:
		key = base + "|account:" + f.Account
	case perAccountSeverity:
		key = base + "|account:" + f.Account + "|severity:" + string(f.Severity)
	case perProject:
		p.project, _ = f.Evidence["project"].(string)
		if p.project == "" {
			p.project = f.Account
		}
		key = base + "|project:" + p.project
	case perFamily:
		key = base + "|account:" + f.Account + "|family:" + family(f)
	default:
		key = pinnedKey(f.ID)
	}
	return key, p
}

func (p *proposal) add(f finding.Finding) {
	p.findings = append(p.findings, f)
	p.refs = append(p.refs, refOf(f))
}

func refOf(f finding.Finding) FindingRef {
	return FindingRef{ID: f.ID, Connector: f.Connector, Instance: f.Instance, Account: f.Account, Title: f.Title,
		Severity: f.Severity, LastSeen: f.ObservedAt.UTC()}
}

// worst is the most severe finding (the first one on a tie).
func (p *proposal) worst() finding.Finding {
	w := p.findings[0]
	for _, f := range p.findings[1:] {
		if f.Severity.Rank() > w.Severity.Rank() {
			w = f
		}
	}
	return w
}

func (p *proposal) accounts() []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range p.findings {
		if !seen[f.Account] {
			seen[f.Account] = true
			out = append(out, f.Account)
		}
	}
	sort.Strings(out)
	return out
}

// severity is the worst severity of the refs, capped.
func (p *proposal) severity() finding.Severity {
	var s finding.Severity
	for _, r := range p.refs {
		if r.Severity.Rank() > s.Rank() || s == "" {
			s = r.Severity
		}
	}
	if p.maxSeverity != "" && s.Rank() > p.maxSeverity.Rank() {
		s = p.maxSeverity
	}
	return s
}

// finish sets the title and next step of a proposal made of findings by a rule.
func (p *proposal) finish(itemID string) {
	if p.rule == nil {
		return
	}
	switch {
	case p.rule.title != nil:
		p.title = p.rule.title(p)
	case len(p.findings) == 1:
		p.title = p.findings[0].Title
	default:
		p.title = fmt.Sprintf("%s (%d)", family(p.findings[0]), len(p.findings))
	}
	w := p.worst()
	n := &Next{Who: You, Action: w.Remediation.Summary, URL: w.Remediation.URL}
	if n.Action == "" {
		n.Action = "Review the linked findings."
	}
	if len(p.findings) == 1 && w.Remediation.Automatable {
		n.Who, n.Command = Segurata, "segurata remediate "+w.ID
	} else {
		n.Command = "segurata track show " + itemID
	}
	p.next = n
}
