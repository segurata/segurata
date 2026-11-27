// Package attribution decides offline, never using a secret against a provider, whose a leaked
// secret is: the accounts its value and the file around it name, the repositories it is committed
// in, who committed it and the owner's own config files that hold it, compared with what the owner
// holds. The owner's own word (Override) wins over all of them. See docs/architecture.md,
// "Attribution".
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
	// SSHKey is where the public half of a private key was found among the owner's keys:
	// "github:<login>" or "file:~/.ssh/<name>.pub"; SSHKeyUnreadable when it could not be read.
	SSHKey string `json:"ssh_key,omitempty"`
}

// SSHKeyUnreadable is the SSHKey claim of a private key whose public half could not be read.
const SSHKeyUnreadable = "unreadable"

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

// Facts are every claim a secret's sightings made, plus what its locations say: the GitHub owners
// of the repositories it is committed in, the repositories without one, and the owner's own config
// files holding it. Override is the owner's own verdict.
type Facts struct {
	AWSAccounts  []string  `json:"aws_accounts,omitempty"`
	GCPProjects  []string  `json:"gcp_projects,omitempty"`
	SlackTeams   []string  `json:"slack_teams,omitempty"`
	GitHubLogins []string  `json:"github_logins,omitempty"`
	SSHKeys      []string  `json:"ssh_keys,omitempty"`
	AuthorEmails []string  `json:"author_emails,omitempty"`
	RepoOwners   []string  `json:"repo_owners,omitempty"`
	UnownedRepos []string  `json:"repos_without_owner,omitempty"`
	OwnConfig    []string  `json:"own_config,omitempty"`
	Override     *Override `json:"override,omitempty"`
}

// Override is the verdict the owner set by hand (segurata rotations owner).
type Override struct {
	Owner  Owner     `json:"owner"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

func (f *Facts) Add(c Claims) {
	insert(&f.AWSAccounts, c.AWSAccount, false)
	insert(&f.GCPProjects, c.GCPProject, false)
	insert(&f.SlackTeams, c.SlackTeam, false)
	insert(&f.GitHubLogins, c.GitHubLogin, true)
	insert(&f.SSHKeys, c.SSHKey, false)
	insert(&f.AuthorEmails, lower(c.AuthorEmail), false)
}

// Clone is a deep copy.
func (f Facts) Clone() Facts {
	c := Facts{AWSAccounts: slices.Clone(f.AWSAccounts), GCPProjects: slices.Clone(f.GCPProjects), SlackTeams: slices.Clone(f.SlackTeams),
		GitHubLogins: slices.Clone(f.GitHubLogins), SSHKeys: slices.Clone(f.SSHKeys), AuthorEmails: slices.Clone(f.AuthorEmails),
		RepoOwners: slices.Clone(f.RepoOwners), UnownedRepos: slices.Clone(f.UnownedRepos), OwnConfig: slices.Clone(f.OwnConfig)}
	if f.Override != nil {
		o := *f.Override
		c.Override = &o
	}
	return c
}

// Accounts keeps the claims that name an account, and the override: what ties a value to the
// owner wherever it sits, unlike the repository, author or file of one copy.
func (f Facts) Accounts() Facts {
	c := f.Clone()
	c.AuthorEmails, c.RepoOwners, c.UnownedRepos, c.OwnConfig = nil, nil, nil, nil
	return c
}

func (f *Facts) AddRepoOwner(owner string) { insert(&f.RepoOwners, strings.TrimSpace(owner), true) }

func (f *Facts) AddUnownedRepo(repo string) { insert(&f.UnownedRepos, repo, false) }

func (f *Facts) AddOwnConfig(path string) { insert(&f.OwnConfig, path, false) }

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

// evidence is one tier's: the accounts and keys a secret names (strong), or the repositories,
// authors and config files of its copies (weak).
type evidence struct{ mine, foreign, blind []string }

// Attribute is the override when the owner set one. Otherwise it is mine when anything ties the
// secret to the owner: an account it names, a repository of theirs it is committed in, a commit of
// theirs, a config file of theirs or their key list holding its public half; not-mine when it
// names only accounts, or sits committed only in repositories, of kinds the owner holds some of,
// none of them the owner's; unknown otherwise. An account named outranks a copy's repository,
// author or file: someone else's AWS key the owner committed stays someone else's, so it is never
// tried against its provider.
func Attribute(f Facts, o Owned) Result {
	if ov := f.Override; ov != nil && ov.Owner != Unknown {
		auto := f.Clone()
		auto.Override = nil
		a := Attribute(auto, o)
		return Result{Owner: ov.Owner, Confidence: High, Facts: f,
			Reasons: append([]string{"set by you: " + ov.Reason, fmt.Sprintf("without it: %s (%s confidence)", a.Owner, a.Confidence)}, a.Reasons...)}
	}
	var strong, weak evidence
	for _, k := range []account{
		{"AWS account", "aws_accounts", f.AWSAccounts, o.AWSAccounts, false},
		{"GCP project", "gcp_projects", f.GCPProjects, o.GCPProjects, false},
		{"Slack workspace", "slack_teams", f.SlackTeams, o.SlackTeams, false},
		{"GitHub account", "github", f.GitHubLogins, o.GitHub, true},
	} {
		for _, n := range k.named {
			switch {
			case contains(k.owned, n, k.fold):
				strong.mine = append(strong.mine, fmt.Sprintf("%s %s is yours", k.label, n))
			case len(k.owned) > 0:
				strong.foreign = append(strong.foreign, fmt.Sprintf("%s %s is none of your %d known (owned.%s)", k.label, n, len(k.owned), k.key))
			default:
				strong.blind = append(strong.blind, fmt.Sprintf("%s %s: none of yours is known (run its connector or set owned.%s)", k.label, n, k.key))
			}
		}
	}
	strong.sshKeys(f.SSHKeys, o)
	for _, r := range f.RepoOwners {
		switch {
		case contains(o.GitHub, r, true):
			weak.mine = append(weak.mine, "committed in a repository you own ("+r+")")
		case len(o.GitHub) > 0:
			weak.foreign = append(weak.foreign, fmt.Sprintf("committed in a repository of %s, none of your %d GitHub accounts or organizations (owned.github)", r, len(o.GitHub)))
		default:
			weak.blind = append(weak.blind, "committed in a repository of "+r+": none of your GitHub accounts or organizations is known (run the github connector or set owned.github)")
		}
	}
	for _, r := range f.UnownedRepos {
		weak.blind = append(weak.blind, "committed to a git repository with no GitHub remote, so whose it is is unknown ("+r+")")
	}
	var others []string
	for _, e := range f.AuthorEmails {
		if contains(o.Emails, e, true) {
			weak.mine = append(weak.mine, "committed by you ("+e+")")
		} else {
			others = append(others, e)
		}
	}
	for _, p := range f.OwnConfig {
		if strings.HasPrefix(p, "~") {
			weak.mine = append(weak.mine, "kept in your own config file "+p)
		} else {
			weak.mine = append(weak.mine, "kept in your own user environment "+p)
		}
	}
	r := Result{Facts: f}
	switch {
	case len(strong.mine) > 0:
		r.Owner, r.Confidence = Mine, High
		if len(strong.foreign)+len(weak.foreign) > 0 {
			r.Confidence = Medium // a file naming two accounts, or a copy in someone else's repository
		}
	case len(strong.foreign) > 0:
		r.Owner, r.Confidence = NotMine, Medium
		if len(strong.blind) > 0 {
			r.Owner, r.Confidence = Unknown, Low
		}
	case len(weak.mine) > 0:
		r.Owner, r.Confidence = Mine, Medium
	case len(weak.foreign) > 0 && len(strong.blind)+len(weak.blind) == 0:
		r.Owner, r.Confidence = NotMine, Medium
	default:
		r.Owner, r.Confidence = Unknown, Low
	}
	r.Reasons = slices.Concat(strong.mine, weak.mine, strong.foreign, weak.foreign, strong.blind, weak.blind)
	if len(r.Reasons) == 0 {
		r.Reasons = append(r.Reasons, "the secret names no account, project or workspace that can be read offline")
	}
	if len(others) > 0 && len(o.Emails) > 0 {
		r.Reasons = append(r.Reasons, "hint: committed by someone else ("+strings.Join(others, ", ")+")")
	}
	if slices.Equal(f.SSHKeys, []string{SSHKeyUnreadable}) {
		r.Reasons = append(r.Reasons, "hint: the public key of this private key could not be read (a passphrase or an unsupported format), so it was not compared with your keys")
	}
	return r
}

// sshKeys is mine for a private key whose public half the owner holds; a key found nowhere is no
// evidence either way: the owner's keys are not all listed anywhere.
func (v *evidence) sshKeys(keys []string, o Owned) {
	for _, k := range keys {
		switch kind, where, _ := strings.Cut(k, ":"); {
		case kind == "file":
			v.mine = append(v.mine, "the public key of this private key matches "+where)
		case kind == "github" && contains(o.GitHub, where, true):
			v.mine = append(v.mine, "the public key of this private key is on your GitHub account "+where)
		case kind == "github":
			v.blind = append(v.blind, "the public key of this private key is on GitHub account "+where+", none of your known ones (owned.github)")
		}
	}
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
