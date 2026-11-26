package tracker

import (
	"cmp"
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
// do not require 2FA are one item (one settings page, five times); a repository's data dumps are
// one item; thirty X apps that can post as you are one review. Each connector declares how its
// findings group (finding.Track); the tracker applies it, and groups the findings of a connector
// that declares nothing by title family. Info findings never make an item. Secrets are grouped by
// fingerprint elsewhere (secret.go); connector statuses become setup items (sync.go).

type groupBy int

const (
	perFinding         groupBy = iota // one item per finding
	perCheck                          // one item per check (declared key, or resource id) across accounts
	perAccount                        // one item per account
	perAccountSeverity                // one item per account and severity
	perProject                        // one item per project (declared key, or account)
	perFamily                         // one item per account and title family (the title without the resource's name)
	perRepo                           // one item per evidence.repo
)

// groupsBy maps a finding.Track group to how it groups.
var groupsBy = map[string]groupBy{
	finding.GroupFinding: perFinding, finding.GroupCheck: perCheck, finding.GroupAccount: perAccount,
	finding.GroupAccountSeverity: perAccountSeverity, finding.GroupProject: perProject, finding.GroupFamily: perFamily,
}

// grouping says how findings group, the kind of item and its title: what a finding declares
// (finding.Track), or the tracker's own grouping for local-secrets' data dumps. Not to be confused
// with Rule, a decision about items (rules.go).
type grouping struct {
	by        groupBy
	kind      Kind
	title     func(p *proposal) string // nil: the finding's title, or the worst finding's with a count
	next      func(p *proposal) *Next  // nil: the worst finding's remediation
	keepTitle bool                     // keep the item's title (a run from before declarations)
}

// dumpsGrouping makes one item of a repository's data dumps, purged in one history rewrite.
var dumpsGrouping = &grouping{by: perRepo, kind: KindFix, title: dumpsTitle, next: dumpsNext}

// defaultGrouping groups a finding that declares nothing.
var defaultGrouping = &grouping{by: perFamily, kind: KindFix}

// declared is the grouping a finding's Track declares.
func declared(tr *finding.Track) *grouping {
	r := *defaultGrouping
	if by, ok := groupsBy[tr.Group]; ok {
		r.by = by
	}
	if tr.Kind == finding.TrackReview {
		r.kind = KindReview
	}
	if tr.Title != "" {
		r.title = declaredTitle
	}
	return &r
}

// declaredTitle is the title the group's first finding declares, with the count in it.
func declaredTitle(p *proposal) string {
	tr := p.findings[0].Track
	n := len(p.findings)
	switch tr.Count {
	case finding.CountAccounts:
		n = len(p.accounts())
	case finding.CountScopes:
		n = len(p.scopes())
	}
	if n == 1 && tr.TitleOne != "" {
		return tr.TitleOne
	}
	noun, nouns := cmp.Or(tr.Noun, "finding"), cmp.Or(tr.Nouns, "findings")
	return strings.ReplaceAll(tr.Title, "{count}", textfmt.Count(n, noun, nouns))
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

// groupingFor is the grouping a finding follows.
func groupingFor(f finding.Finding) *grouping {
	switch {
	case f.Connector == SecretsConnector && f.Resource.Type == "data_dump":
		return dumpsGrouping
	case f.Track != nil:
		return declared(f.Track)
	}
	return defaultGrouping
}

// proposal is what one sync says an item should hold.
type proposal struct {
	key, theme, connector, instance, account string
	repo                                     string // perRepo: the repository the dumps are in
	kind                                     Kind
	grouping                                 *grouping
	findings                                 []finding.Finding
	refs                                     []FindingRef
	maxSeverity                              finding.Severity // "" for no cap
	title                                    string           // set for proposals not made of findings by a rule
	next                                     *Next
	statuses                                 []finding.Status // setup proposals: one per ref
}

// groupKey is the item key of a finding under its grouping.
func groupKey(f finding.Finding, r *grouping, theme string) (key string, p proposal) {
	lbl := finding.Label(f.Connector, f.Instance)
	p = proposal{theme: theme, connector: f.Connector, instance: f.Instance, account: f.Account, kind: r.kind, grouping: r}
	base := "group:" + lbl + "|" + f.Resource.Type
	var declaredKey string
	if f.Track != nil {
		declaredKey = f.Track.Key
	}
	switch r.by {
	case perCheck:
		key = base + "|check:" + cmp.Or(declaredKey, f.Resource.ID)
	case perAccount:
		key = base + "|account:" + f.Account
	case perAccountSeverity:
		key = base + "|account:" + f.Account + "|severity:" + string(f.Severity)
	case perProject:
		key = base + "|project:" + cmp.Or(declaredKey, f.Account)
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
		Severity: f.Severity, LastSeen: f.ObservedAt.UTC(), Type: f.Resource.Type, Resource: f.Resource.ID, Blast: f.Blast, Unconfirmed: f.Unconfirmed,
		Path: finding.PathOf(f)}
	if tr := f.Track; tr != nil {
		r.Repo, r.Project = tr.Repo, tr.Project
	}
	return r
}

// keepWhere gives the last ref added the repository and project its item's ref of the same
// finding says, which only a declared Track carries.
func (p *proposal) keepWhere(held *Item) {
	r := &p.refs[len(p.refs)-1]
	for _, old := range held.Findings {
		if old.ID == r.ID {
			r.Repo, r.Project = cmp.Or(r.Repo, old.Repo), cmp.Or(r.Project, old.Project)
		}
	}
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

// scopes are the distinct scopes of the findings (finding.ScopeOf).
func (p *proposal) scopes() map[string]bool {
	out := map[string]bool{}
	for _, f := range p.findings {
		out[finding.ScopeOf(f)] = true
	}
	return out
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
	if p.grouping == nil {
		return
	}
	switch {
	case p.grouping.keepTitle:
	case p.grouping.title != nil:
		p.title = p.grouping.title(p)
	case len(p.findings) == 1:
		p.title = p.findings[0].Title
	default:
		// A group no rule names: the worst finding's own title, and how many more are like it.
		p.title = fmt.Sprintf("%s, and %d more like it", p.worst().Title, len(p.findings)-1)
	}
	if p.title != "" {
		p.title += p.severitySplit()
	}
	if p.grouping.next != nil {
		p.next = p.grouping.next(p)
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

// severitySplit is, for a group whose scopes (projects, orgs, accounts) sit at different severities,
// how many sit at each, worst first: " (1 medium, 2 low)"; "" otherwise. The item's priority is its
// worst scope's, since that scope needs the fix at that urgency; the split keeps the count in the
// title from reading as that much work at that priority, as when a project's activity profile
// lowered a hygiene check everywhere but in one production project.
func (p *proposal) severitySplit() string {
	worst := map[string]finding.Severity{}
	for _, f := range p.findings {
		if s, ok := worst[finding.ScopeOf(f)]; !ok || f.Severity.Rank() > s.Rank() {
			worst[finding.ScopeOf(f)] = f.Severity
		}
	}
	count := map[finding.Severity]int{}
	for _, s := range worst {
		count[s]++
	}
	if len(count) < 2 {
		return ""
	}
	var parts []string
	for _, s := range []finding.Severity{finding.SevCritical, finding.SevHigh, finding.SevMedium, finding.SevLow} {
		if count[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", count[s], s))
		}
	}
	return " (" + strings.Join(parts, ", ") + ")"
}
