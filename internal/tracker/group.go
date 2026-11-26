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

// groupBy says which findings make one item: one per thing a person would do, as five GitHub orgs
// that do not require 2FA are one settings page, five times.
type groupBy int

const (
	perFinding groupBy = iota // one item per finding
	perCheck                  // per check (declared key, or resource id), across accounts
	perAccount
	perAccountSeverity
	perProject // declared key, or account
	perFamily  // per account and title family
	perRepo    // per evidence.repo
)

var groupsBy = map[string]groupBy{
	finding.GroupFinding: perFinding, finding.GroupCheck: perCheck, finding.GroupAccount: perAccount,
	finding.GroupAccountSeverity: perAccountSeverity, finding.GroupProject: perProject, finding.GroupFamily: perFamily,
}

// grouping is how findings group into an item, from finding.Track or the tracker's own for data
// dumps.
type grouping struct {
	by        groupBy
	kind      Kind
	title     func(p *proposal) string // nil: the finding's title, or the worst finding's with a count
	next      func(p *proposal) *Next  // nil: the worst finding's remediation
	keepTitle bool                     // a legacy run keeps the item's title
}

// dumpsGrouping makes one item of a repository's data dumps: one history rewrite purges them.
var dumpsGrouping = &grouping{by: perRepo, kind: KindFix, title: dumpsTitle, next: dumpsNext}

var defaultGrouping = &grouping{by: perFamily, kind: KindFix}

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

// dumpsTitle is "3 database dumps in the git history of ~/src/api (11 MB)".
func dumpsTitle(p *proposal) string {
	var total int64
	for _, f := range p.findings {
		n, _ := f.Evidence["size_bytes"].(float64)
		total += int64(n)
	}
	return fmt.Sprintf("%s in the git history of %s (%s)", textfmt.Count(len(p.findings), "database dump", "database dumps"), p.repo, secretrisk.HumanSize(total))
}

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

// stripName drops the resource's name in front of the title.
func stripName(f finding.Finding) string {
	if n := f.Resource.Name; n != "" && strings.HasPrefix(f.Title, n+" ") {
		return f.Title[len(n)+1:]
	}
	return f.Title
}

// family is the title without the name, quoted names and numbers blanked.
func family(f finding.Finding) string {
	return digits.ReplaceAllString(quoted.ReplaceAllString(stripName(f), `"…"`), "N")
}

func groupingFor(f finding.Finding) *grouping {
	switch {
	case f.Connector == SecretsConnector && f.Resource.Type == "data_dump":
		return dumpsGrouping
	case f.Track != nil:
		return declared(f.Track)
	}
	return defaultGrouping
}

type proposal struct {
	key, theme, connector, instance, account string
	repo                                     string // perRepo: the repository the dumps are in
	kind                                     Kind
	grouping                                 *grouping
	findings                                 []finding.Finding
	refs                                     []FindingRef
	maxSeverity                              finding.Severity // "" for no cap
	title                                    string
	next                                     *Next
	statuses                                 []finding.Status // setup proposals: one per ref
}

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

// keepWhere carries the repository and project, which only a declared Track gives, over from the
// item's ref of the last finding added.
func (p *proposal) keepWhere(held *Item) {
	r := &p.refs[len(p.refs)-1]
	for _, old := range held.Findings {
		if old.ID == r.ID {
			r.Repo, r.Project = cmp.Or(r.Repo, old.Repo), cmp.Or(r.Project, old.Project)
		}
	}
}

// worst is the most severe finding, the first on a tie.
func (p *proposal) worst() finding.Finding {
	w := p.findings[0]
	for _, f := range p.findings[1:] {
		if f.Severity.Rank() > w.Severity.Rank() {
			w = f
		}
	}
	return w
}

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
	// A hardening action (Remediation.Severity set) is a side step, not the item's fix.
	if len(p.findings) == 1 && w.Remediation.Automatable && w.Remediation.Severity == "" {
		n.Who, n.Command = Segurata, "segurata remediate "+w.ID
	} else {
		n.Command = "segurata track show " + itemID
	}
	p.next = n
}

// severitySplit is " (1 medium, 2 low)" for a group whose scopes sit at different severities: the
// item takes its worst scope's priority, and the split keeps the count from reading as that much
// work at it.
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
