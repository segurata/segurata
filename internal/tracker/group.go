package tracker

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
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
	perRepo                           // one item per evidence.repo
)

// rule maps findings of a connector and resource type (and, optionally, some resource ids) to how
// they group, the kind of item and its title. First match wins.
type rule struct {
	connectors []string // empty: any
	resource   string   // empty: any
	by         groupBy
	kind       Kind
	title      func(p *proposal) string // nil: the finding's title, or the family with a count
	next       func(p *proposal) *Next  // nil: the worst finding's remediation
}

var rules = []rule{
	{connectors: []string{SecretsConnector}, resource: "data_dump", by: perRepo, kind: KindFix, title: dumpsTitle, next: dumpsNext},
	{connectors: []string{"github"}, resource: "github_org_setting", by: perCheck, kind: KindFix, title: githubCheckTitle},
	{connectors: []string{"github"}, resource: "github_repo_setting", by: perCheck, kind: KindFix, title: githubCheckTitle},
	{connectors: []string{"github"}, resource: "github_repo", by: perAccount, kind: KindFix, title: func(p *proposal) string {
		return fmt.Sprintf("Repository security settings off in %s of %s", textfmt.Count(len(p.findings), "repository", "repositories"), p.account)
	}},
	{connectors: []string{"connected-apps"}, resource: "slack_app", by: perAccountSeverity, kind: KindReview, title: func(p *proposal) string {
		return fmt.Sprintf("Review %s with %s permissions in %s", textfmt.Count(len(p.findings), "Slack app", "Slack apps"),
			breadth(p.worst().Severity, "broad", "several", "few"), strings.TrimPrefix(p.account, "slack:"))
	}},
	{connectors: []string{"connected-apps"}, by: perFamily, kind: KindReview, title: appsTitle},
	{connectors: []string{"google-personal"}, resource: "oauth_grant", by: perAccountSeverity, kind: KindReview, title: func(p *proposal) string {
		return fmt.Sprintf("Review %s with %s access to %s", textfmt.Count(len(p.findings), "app", "apps"),
			breadth(p.worst().Severity, "high-risk", "broad", "limited"), p.account)
	}},
	{connectors: []string{"gcp"}, resource: "api_key", by: perProject, kind: KindFix, title: func(p *proposal) string {
		return fmt.Sprintf("Restrict %s in GCP project %s", textfmt.Count(len(p.findings), "API key", "API keys"), p.project)
	}},
	{connectors: []string{"gcp"}, resource: "service_account_key", by: perProject, kind: KindFix, title: func(p *proposal) string {
		return fmt.Sprintf("Rotate or delete %s in GCP project %s", textfmt.Count(len(p.findings), "user-managed service-account key", "user-managed service-account keys"), p.project)
	}},
	{connectors: []string{"gcp"}, resource: "service_account_role", by: perProject, kind: KindFix, title: func(p *proposal) string {
		return fmt.Sprintf("Narrow the roles of %s in GCP project %s", textfmt.Count(len(p.findings), "service account", "service accounts"), p.project)
	}},
	{connectors: []string{"openai", "anthropic", "openrouter"}, resource: "api_key", by: perAccountSeverity, kind: KindFix, title: func(p *proposal) string {
		s := fmt.Sprintf("Revoke or limit %s", textfmt.Count(len(p.findings), providerName(p.connector)+" API key", providerName(p.connector)+" API keys"))
		if p.instance != "" {
			s += " (" + p.instance + ")"
		}
		return s
	}},
	{connectors: []string{"macos", "aws"}, by: perFinding, kind: KindFix},
	{connectors: []string{"browser-extensions"}, by: perFinding, kind: KindReview},
	{by: perFamily, kind: KindFix},
}

// dumpsTitle names a repository's dumps by number and total size: "3 database dumps in the git
// history of ~/src/api (11 MB)".
func dumpsTitle(p *proposal) string {
	var total int64
	for _, f := range p.findings {
		n, _ := f.Evidence["size_bytes"].(float64)
		total += int64(n)
	}
	return fmt.Sprintf("%s in the git history of %s (%s)", textfmt.Count(len(p.findings), "database dump", "database dumps"), p.repo, secretrisk.HumanSize(total))
}

// dumpsNext purges every dump of the repository in one history rewrite, lists the files with their
// size, and leaves the breach-notification duty as the secondary step. Its page is the guide in
// docs/secrets.md.
func dumpsNext(p *proposal) *Next {
	fs := slices.Clone(p.findings)
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity.Rank() > fs[j].Severity.Rank() })
	var paths, files []string
	pushed := false
	for _, f := range fs {
		str := func(k string) string { s, _ := f.Evidence[k].(string); return s }
		paths = append(paths, "--path '"+strings.ReplaceAll(str("path"), "'", `'\''`)+"'")
		state := "local"
		if remote, _ := f.Evidence["remote"].(bool); remote {
			state, pushed = "pushed", true
		}
		files = append(files, fmt.Sprintf("%s (%s, %s)", str("path"), str("size"), state))
	}
	var b strings.Builder
	if pushed {
		b.WriteString("Treat the data as exposed to everyone who could clone the repository. ")
	}
	fmt.Fprintf(&b, "Rotate every credential the dumps hold, then purge %s from history in one pass: `git filter-repo --invert-paths %s`",
		textfmt.Plural(len(fs), "it", "them"), strings.Join(paths, " "))
	if pushed {
		b.WriteString(" and force-push every branch and tag; collaborators must re-clone")
	}
	b.WriteString(". segurata never rewrites history or pushes.\nFiles: " + strings.Join(files, "; ") + ".\n")
	fmt.Fprintf(&b, "If they hold personal data of customers or staff, check the GDPR breach notification duty (72 hours): %s, %s.",
		secretrisk.URLAEPDBreaches, secretrisk.URLEDPBBreaches)
	return &Next{Who: You, Action: b.String(), URL: secretrisk.DumpFixDoc}
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
	return phrase + " in " + textfmt.Count(len(p.accounts()), "GitHub org", "GitHub orgs")
}

// appNouns name what a connected-apps resource type is.
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

// appsTitle puts the count and noun in front of what the findings' titles say about one app, with
// the predicate made plural: "7 Notion integrations can read and change the Notion pages shared
// with them (your own integrations)".
func appsTitle(p *proposal) string {
	if len(p.findings) == 1 {
		return p.findings[0].Title
	}
	noun, ok := appNouns[p.resource]
	if !ok {
		noun = [2]string{"app", "apps"}
	}
	n := len(p.findings)
	rest := textfmt.PluralPredicate(n, stripName(p.findings[0]))
	one, many := lastWord(noun[0]), lastWord(noun[1])
	rest = strings.ReplaceAll(rest, "(your own "+one+")", "(your own "+many+")")
	return textfmt.Count(n, noun[0], noun[1]) + " " + rest
}

// lastWord is the head noun of an app noun: "integration" for "Notion integration".
func lastWord(s string) string {
	f := strings.Fields(s)
	return f[len(f)-1]
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
	account, project, check, repo             string
	kind                                      Kind
	rule                                      *rule
	findings                                  []finding.Finding
	refs                                      []FindingRef
	maxSeverity                               finding.Severity // "" for no cap
	title                                     string           // set for proposals not made of findings by a rule
	next                                      *Next
	statuses                                  []finding.Status // setup proposals: one per ref
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
	case perRepo:
		p.repo, _ = f.Evidence["repo"].(string)
		key = base + "|repo:" + p.repo
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
	r := FindingRef{ID: f.ID, Connector: f.Connector, Instance: f.Instance, Account: f.Account, Scope: finding.ScopeOf(f), Title: f.Title,
		Severity: f.Severity, LastSeen: f.ObservedAt.UTC(), Type: f.Resource.Type, Resource: f.Resource.ID}
	str := func(k string) string { s, _ := f.Evidence[k].(string); return s }
	for _, p := range []string{str("repo"), str("path")} {
		if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "/") {
			r.Path = p
			break
		}
	}
	if f.Connector == "github" && strings.Count(f.Resource.Name, "/") == 1 {
		r.Repo = f.Resource.Name
	}
	if f.Connector == "gcp" {
		r.Project = str("project")
	}
	return r
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
		// A group no rule names: the worst finding's own title, and how many more are like it.
		p.title = fmt.Sprintf("%s, and %d more like it", p.worst().Title, len(p.findings)-1)
	}
	if p.rule.next != nil {
		p.next = p.rule.next(p)
		p.next.Command = "segurata track show " + itemID
		return
	}
	w := p.worst()
	n := &Next{Who: You, Action: w.Remediation.Summary, URL: w.Remediation.URL}
	if n.Action == "" {
		n.Action = "Review the linked findings."
	}
	// A hardening action (Remediation.Severity set) is a side step, not the fix of the item.
	if len(p.findings) == 1 && w.Remediation.Automatable && w.Remediation.Severity == "" {
		n.Who, n.Command = Segurata, "segurata remediate "+w.ID
	} else {
		n.Command = "segurata track show " + itemID
	}
	p.next = n
}
