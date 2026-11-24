// Package attribution decides, offline, whose a leaked secret is: the owner's ("mine"), provably
// someone else's ("not-mine"), or "unknown". It never uses a secret against a provider. The
// evidence is what the value itself carries (the AWS account encoded in an access key id, the
// Slack workspace in a webhook URL, the GCP project number in an OAuth client id), what the file
// around it says (project_id in a credentials file), compared with the accounts, projects and
// workspaces the owner is known to hold (config `owned` plus what the aws, gcp, connected-apps and
// github connectors report). Who committed it and whose repository holds it are hints, never
// proof. See docs/architecture.md, "Attribution".
package attribution

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/proc"
)

// Claims are the account identifiers one sighting of a secret names. local-secrets fills them at
// scan time, where the raw value is at hand, and stores only these derived identifiers: never the
// key id or the value.
type Claims struct {
	AWSAccount  string `json:"aws_account,omitempty"`  // decoded from an access key id
	SlackTeam   string `json:"slack_team,omitempty"`   // T… from a webhook URL
	GCPProject  string `json:"gcp_project,omitempty"`  // project id or number
	AuthorEmail string `json:"author_email,omitempty"` // git history: the commit's author
}

// Owner is the verdict.
type Owner string

const (
	Mine    Owner = "mine"
	NotMine Owner = "not-mine"
	Unknown Owner = "unknown"
)

// Owners are the verdicts, in the order listings use.
var Owners = []Owner{Mine, NotMine, Unknown}

// ParseOwners reads a comma-separated list of verdicts.
func ParseOwners(s string) ([]Owner, error) {
	var out []Owner
	for _, p := range strings.Split(s, ",") {
		o := Owner(lower(p))
		if o == "" {
			continue
		}
		if !slices.Contains(Owners, o) {
			return nil, fmt.Errorf("owner %q: use mine, not-mine or unknown", p)
		}
		if !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no owner in %q: use mine, not-mine or unknown", s)
	}
	return out, nil
}

// Confidence of a verdict.
const (
	High   = "high"   // one of the owner's accounts
	Medium = "medium" // an account that is none of the owner's known ones
	Low    = "low"    // no account named: hints only
)

// Owned are the owner's accounts, projects, workspaces, GitHub owners and emails. Config `owned`
// gives some; Discover finds the rest in the connectors' runs.
type Owned struct {
	AWSAccounts []string `json:"aws_accounts,omitempty"`
	GCPProjects []string `json:"gcp_projects,omitempty"` // ids and numbers
	SlackTeams  []string `json:"slack_teams,omitempty"`
	GitHub      []string `json:"github,omitempty"` // users and organizations
	Emails      []string `json:"emails,omitempty"`
}

// Merge is the union of both, each list sorted, without duplicates (GitHub owners and emails
// compared without case).
func (o Owned) Merge(p Owned) Owned {
	return Owned{AWSAccounts: union(o.AWSAccounts, p.AWSAccounts, false), GCPProjects: union(o.GCPProjects, p.GCPProjects, false),
		SlackTeams: union(o.SlackTeams, p.SlackTeams, false), GitHub: union(o.GitHub, p.GitHub, true), Emails: union(o.Emails, p.Emails, true)}
}

func union(a, b []string, fold bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range append(append([]string{}, a...), b...) {
		v = strings.TrimSpace(v)
		k := v
		if fold {
			k = strings.ToLower(v)
		}
		if v == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Facts are every claim a secret's sightings made, plus the GitHub owners of the repositories that
// hold it.
type Facts struct {
	AWSAccounts  []string `json:"aws_accounts,omitempty"`
	GCPProjects  []string `json:"gcp_projects,omitempty"`
	SlackTeams   []string `json:"slack_teams,omitempty"`
	AuthorEmails []string `json:"author_emails,omitempty"`
	RepoOwners   []string `json:"repo_owners,omitempty"`
}

// Add folds one sighting's claims in.
func (f *Facts) Add(c Claims) {
	add := func(list *[]string, v string) {
		if v != "" && !slices.Contains(*list, v) {
			*list = append(*list, v)
			sort.Strings(*list)
		}
	}
	add(&f.AWSAccounts, c.AWSAccount)
	add(&f.GCPProjects, c.GCPProject)
	add(&f.SlackTeams, c.SlackTeam)
	add(&f.AuthorEmails, lower(c.AuthorEmail))
}

// AddRepoOwner records the GitHub owner of a repository that holds the secret.
func (f *Facts) AddRepoOwner(owner string) {
	if owner = strings.TrimSpace(owner); owner != "" && !slices.ContainsFunc(f.RepoOwners, func(o string) bool { return strings.EqualFold(o, owner) }) {
		f.RepoOwners = append(f.RepoOwners, owner)
		sort.Strings(f.RepoOwners)
	}
}

// Result is a verdict with its confidence, the reasons behind it and the facts it read.
type Result struct {
	Owner      Owner    `json:"owner"`
	Confidence string   `json:"confidence"`
	Reasons    []string `json:"reasons"`
	Facts      Facts    `json:"facts"`
}

// account is one kind of account a secret can name.
type account struct {
	label, key string // "AWS account", "aws_accounts"
	named      []string
	owned      []string
	fold       bool
}

// Attribute combines the facts with what the owner holds. A secret is mine when it names one of the
// owner's accounts, projects or workspaces; not-mine when it names only ones that are none of the
// owner's (and at least one of the owner's of that kind is known, so the comparison means
// something); unknown otherwise. Commit authorship and repository ownership are reported as
// hints and never decide.
func Attribute(f Facts, o Owned) Result {
	kinds := []account{
		{"AWS account", "aws_accounts", f.AWSAccounts, o.AWSAccounts, false},
		{"GCP project", "gcp_projects", f.GCPProjects, o.GCPProjects, false},
		{"Slack workspace", "slack_teams", f.SlackTeams, o.SlackTeams, false},
	}
	var mine, foreign, blind []string
	for _, k := range kinds {
		for _, v := range k.named {
			switch {
			case contains(k.owned, v, k.fold):
				mine = append(mine, fmt.Sprintf("%s %s is yours", k.label, v))
			case len(k.owned) > 0:
				foreign = append(foreign, fmt.Sprintf("%s %s is none of your %d known (owned.%s)", k.label, v, len(k.owned), k.key))
			default:
				blind = append(blind, fmt.Sprintf("%s %s: none of yours is known (run its connector or set owned.%s)", k.label, v, k.key))
			}
		}
	}
	r := Result{Facts: f}
	switch {
	case len(mine) > 0:
		r.Owner, r.Confidence = Mine, High
		if len(foreign) > 0 {
			r.Confidence = Medium // a file naming two accounts: one of them is the owner's
		}
	case len(foreign) > 0 && len(blind) == 0:
		r.Owner, r.Confidence = NotMine, Medium
	default:
		r.Owner, r.Confidence = Unknown, Low
	}
	r.Reasons = append(append(append(r.Reasons, mine...), foreign...), blind...)
	if len(mine)+len(foreign)+len(blind) == 0 {
		r.Reasons = append(r.Reasons, "the secret names no account, project or workspace that can be read offline")
	}
	r.Reasons = append(r.Reasons, hints(f, o)...)
	return r
}

// hints are what authorship and repository ownership suggest.
func hints(f Facts, o Owned) []string {
	var out []string
	var by, others []string
	for _, e := range f.AuthorEmails {
		if contains(o.Emails, e, true) {
			by = append(by, e)
		} else {
			others = append(others, e)
		}
	}
	switch {
	case len(by) > 0:
		out = append(out, "hint: committed by you ("+strings.Join(by, ", ")+")")
	case len(others) > 0 && len(o.Emails) > 0:
		out = append(out, "hint: committed by someone else ("+strings.Join(others, ", ")+")")
	}
	var yours, theirs []string
	for _, r := range f.RepoOwners {
		if contains(o.GitHub, r, true) {
			yours = append(yours, r)
		} else {
			theirs = append(theirs, r)
		}
	}
	if len(yours) > 0 {
		out = append(out, "hint: in a repository you own ("+strings.Join(yours, ", ")+")")
	}
	if len(theirs) > 0 && len(o.GitHub) > 0 {
		out = append(out, "hint: in a repository of "+strings.Join(theirs, ", ")+", none of your GitHub accounts or organizations")
	}
	return out
}

func contains(list []string, v string, fold bool) bool {
	return slices.ContainsFunc(list, func(x string) bool { return x == v || fold && strings.EqualFold(x, v) })
}

// GitEmail is the email `git config user.email` gives (global or system), or "" when git or the
// setting is missing: the owner's commit email by default.
func GitEmail() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := proc.Command(ctx, "git", "config", "--get", "user.email").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
