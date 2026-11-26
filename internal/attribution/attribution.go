// Package attribution decides offline, never using a secret against a provider, whose a leaked
// secret is: the accounts its value and the file around it name, compared with the accounts the
// owner holds. Who committed it and whose repository holds it are hints, never proof. See
// docs/architecture.md, "Attribution".
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

// Claims are the account identifiers one sighting of a secret names, derived at scan time: never
// the key id or the value.
type Claims struct {
	AWSAccount  string `json:"aws_account,omitempty"`  // decoded from an access key id
	SlackTeam   string `json:"slack_team,omitempty"`   // T… from a webhook URL
	GCPProject  string `json:"gcp_project,omitempty"`  // project id or number
	GitHubLogin string `json:"github_login,omitempty"` // the login a token signs in as (liveness check)
	AuthorEmail string `json:"author_email,omitempty"` // git history: the commit's author
}

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

const (
	High   = "high"   // one of the owner's accounts
	Medium = "medium" // an account that is none of the owner's known ones
	Low    = "low"    // no account named: hints only
)

// Owned is what the owner holds: config `owned` plus what Discover finds in connector runs.
type Owned struct {
	AWSAccounts []string `json:"aws_accounts,omitempty"`
	GCPProjects []string `json:"gcp_projects,omitempty"` // ids and numbers
	SlackTeams  []string `json:"slack_teams,omitempty"`
	GitHub      []string `json:"github,omitempty"` // users and organizations
	Emails      []string `json:"emails,omitempty"`
}

// Merge is the sorted union of both; GitHub owners and emails compare without case.
func (o Owned) Merge(p Owned) Owned {
	return Owned{AWSAccounts: union(o.AWSAccounts, p.AWSAccounts, false), GCPProjects: union(o.GCPProjects, p.GCPProjects, false),
		SlackTeams: union(o.SlackTeams, p.SlackTeams, false), GitHub: union(o.GitHub, p.GitHub, true), Emails: union(o.Emails, p.Emails, true)}
}

func union(a, b []string, fold bool) []string {
	var out []string
	for _, v := range slices.Concat(a, b) {
		insert(&out, strings.TrimSpace(v), fold)
	}
	return out
}

// insert adds v to the sorted list unless it is empty or already there.
func insert(list *[]string, v string, fold bool) {
	if v != "" && !contains(*list, v, fold) {
		*list = append(*list, v)
		sort.Strings(*list)
	}
}

// Facts are every claim a secret's sightings made, plus the GitHub owners of the repositories
// holding it.
type Facts struct {
	AWSAccounts  []string `json:"aws_accounts,omitempty"`
	GCPProjects  []string `json:"gcp_projects,omitempty"`
	SlackTeams   []string `json:"slack_teams,omitempty"`
	GitHubLogins []string `json:"github_logins,omitempty"`
	AuthorEmails []string `json:"author_emails,omitempty"`
	RepoOwners   []string `json:"repo_owners,omitempty"`
}

func (f *Facts) Add(c Claims) {
	insert(&f.AWSAccounts, c.AWSAccount, false)
	insert(&f.GCPProjects, c.GCPProject, false)
	insert(&f.SlackTeams, c.SlackTeam, false)
	insert(&f.GitHubLogins, c.GitHubLogin, true)
	insert(&f.AuthorEmails, lower(c.AuthorEmail), false)
}

// Clone is a deep copy.
func (f Facts) Clone() Facts {
	return Facts{AWSAccounts: slices.Clone(f.AWSAccounts), GCPProjects: slices.Clone(f.GCPProjects), SlackTeams: slices.Clone(f.SlackTeams),
		GitHubLogins: slices.Clone(f.GitHubLogins), AuthorEmails: slices.Clone(f.AuthorEmails), RepoOwners: slices.Clone(f.RepoOwners)}
}

func (f *Facts) AddRepoOwner(owner string) { insert(&f.RepoOwners, strings.TrimSpace(owner), true) }

type Result struct {
	Owner      Owner    `json:"owner"`
	Confidence string   `json:"confidence"`
	Reasons    []string `json:"reasons"`
	Facts      Facts    `json:"facts"`
}

type account struct {
	label, key string // "AWS account", "aws_accounts"
	named      []string
	owned      []string
	fold       bool
}

// Attribute is mine when the facts name one of the owner's accounts; not-mine when they name only
// accounts of kinds the owner holds some of, none of them the owner's; unknown otherwise.
func Attribute(f Facts, o Owned) Result {
	kinds := []account{
		{"AWS account", "aws_accounts", f.AWSAccounts, o.AWSAccounts, false},
		{"GCP project", "gcp_projects", f.GCPProjects, o.GCPProjects, false},
		{"Slack workspace", "slack_teams", f.SlackTeams, o.SlackTeams, false},
		{"GitHub account", "github", f.GitHubLogins, o.GitHub, true},
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

// Known is what the tracker knew when a scan started: the owner's accounts and, by fingerprint,
// the facts earlier syncs gathered.
type Known struct {
	Owned Owned
	Facts map[string]Facts
}

// Of is the verdict on the secret with fingerprint fp, adding this scan's claims; Unknown on a nil
// Known.
func (k *Known) Of(fp string, claims []Claims) Owner {
	if k == nil {
		return Unknown
	}
	f := k.Facts[fp].Clone()
	for _, c := range claims {
		f.Add(c)
	}
	return Attribute(f, k.Owned).Owner
}

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

// GitEmail is `git config user.email`, the owner's commit email by default; "" without one.
func GitEmail() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := proc.Command(ctx, "git", "config", "--get", "user.email").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
