package github

import (
	"context"
	"fmt"
	"strings"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/textfmt"
)

type membership struct {
	Role         string `json:"role"` // admin (owner), member, billing_manager
	Organization struct {
		Login string `json:"login"`
	} `json:"organization"`
}

// memberships lists the organizations the user is an active member of, with the role in each.
// It returns false when they could not be listed; the status says why.
func (r *run) memberships(ctx context.Context, login string) ([]membership, bool) {
	if !r.scopes.has("read:org") {
		r.scopedStatus(account(login), orgScope("*"), finding.StateNoScope, "organizations not inspected: gh's token lacks read:org; run: %s", refresh("read:org"))
		return nil, false
	}
	ms, err := list[membership](ctx, r, "/user/memberships/orgs?state=active&per_page=100")
	if err != nil {
		r.scopedStatus(account(login), orgScope("*"), stateOrNoScope(err), "%s", describe(err, "organizations not inspected; to grant access run: "+refresh("read:org")))
		return nil, false
	}
	return ms, true
}

// stateOrNoScope reads a refusal of the token as a missing scope.
func stateOrNoScope(err error) finding.State {
	if denied(err) {
		return finding.StateNoScope
	}
	return stateOf(err)
}

func ownsAny(ms []membership) bool {
	for _, m := range ms {
		if m.Role == "admin" {
			return true
		}
	}
	return false
}

func (r *run) orgs(ctx context.Context, ms []membership) {
	for _, m := range ms {
		org := m.Organization.Login
		if m.Role != "admin" {
			r.status(account(org), finding.StateOK, "%s, not owner: organization settings are visible only to owners", strings.ReplaceAll(m.Role, "_", " "))
			continue
		}
		r.org(ctx, org)
	}
}

type orgDetails struct {
	TwoFactorRequired      *bool   `json:"two_factor_requirement_enabled"`
	DefaultPermission      *string `json:"default_repository_permission"`
	MembersCanCreatePublic *bool   `json:"members_can_create_public_repositories"`
	Plan                   *struct {
		Name string `json:"name"`
	} `json:"plan"`
}

type login struct {
	Login string `json:"login"`
}

type defaultConfig struct {
	For    string `json:"default_for_new_repos"` // public, private_and_internal, all
	Config struct {
		Name           string `json:"name"`
		SecretScanning string `json:"secret_scanning"`                 // enabled, disabled, not_set
		PushProtection string `json:"secret_scanning_push_protection"` // enabled, disabled, not_set
	} `json:"configuration"`
}

type actionsPermissions struct {
	EnabledRepositories string `json:"enabled_repositories"` // all, none, selected
	AllowedActions      string `json:"allowed_actions"`      // all, local_only, selected
}

type workflowPermissions struct {
	Default       string `json:"default_workflow_permissions"` // read, write
	CanApprovePRs bool   `json:"can_approve_pull_request_reviews"`
}

// orgReport gathers one organization's findings and notes before they are emitted.
type orgReport struct {
	org, settings string
	found         []orgCheck
	notes         []string
	incomplete    bool
}

type orgCheck struct {
	check           check
	title, fix, url string
	evidence        map[string]any
}

func (o *orgReport) add(c check, title, fix, url string, ev map[string]any) {
	o.found = append(o.found, orgCheck{check: c, title: title, fix: fix, url: url, evidence: ev})
}

func (o *orgReport) note(format string, args ...any) {
	o.notes = append(o.notes, fmt.Sprintf(format, args...))
}

func (o *orgReport) fail(what string, err error) {
	o.incomplete = true
	o.notes = append(o.notes, describe(err, what+" not read"))
}

// Account-level checks have scopes of their own, so a missing token scope for one of them does not
// leave the account's repositories (also under github:<login>) uninspected: "user:<login>" for the
// signed-in user's own settings, "org:<org>" for an organization's settings.
func userScope(login string) string { return "user:" + login }
func orgScope(org string) string    { return "org:" + org }

// org reads one organization the user owns and reports what falls short.
func (r *run) org(ctx context.Context, org string) {
	acct := account(org)
	if !r.scopes.has("admin:org") {
		r.scopedStatus(acct, orgScope(org), finding.StateNoScope, "owner, but organization settings need admin:org; run: %s", refresh("admin:org"))
		return
	}
	var d orgDetails
	if err := r.get(ctx, "/orgs/"+org, &d); err != nil {
		r.scopedStatus(acct, orgScope(org), stateOrNoScope(err), "%s", describe(err, "organization settings not read"))
		return
	}
	if d.TwoFactorRequired == nil {
		r.scopedStatus(acct, orgScope(org), finding.StateNoScope, "GitHub returned the organization without its owner-only settings; run: %s", refresh("admin:org"))
		return
	}

	o := &orgReport{org: org, settings: "https://github.com/organizations/" + org + "/settings"}
	if !*d.TwoFactorRequired {
		o.add(orgNo2FARequirement, org+" does not require two-factor authentication",
			"Turn on \"Require two-factor authentication\" under Authentication security. Members without it are removed from the organization, so ask them to enable it first.",
			o.settings+"/security", nil)
	}
	r.orgPeople(ctx, o)
	if p := deref(d.DefaultPermission); p == "write" || p == "admin" {
		o.add(orgDefaultPermission, fmt.Sprintf("Every member of %s has %s access to every repository", org, p),
			"Set the base permission under Member privileges to Read or No permission, and grant more per team or repository.",
			o.settings+"/member_privileges", map[string]any{"default_repository_permission": p})
	}
	if d.MembersCanCreatePublic != nil && *d.MembersCanCreatePublic {
		o.add(orgPublicRepoCreation, "Members of "+org+" can create public repositories",
			"Under Member privileges, allow members to create only private repositories, so code cannot be published by mistake.",
			o.settings+"/member_privileges", nil)
	}
	plan := ""
	if d.Plan != nil {
		plan = d.Plan.Name
	}
	r.orgScanning(ctx, o, plan)
	r.orgActions(ctx, o)

	for _, f := range o.found {
		r.emit.Finding(finding.Finding{
			Account:     acct,
			Scope:       orgScope(org),
			Resource:    finding.Resource{Type: "github_org_setting", ID: string(f.check), Name: org},
			Kind:        finding.KindSetting,
			Severity:    severities[f.check],
			Title:       f.title,
			Evidence:    withCheck(f.evidence, f.check),
			Remediation: remedy(f.fix, f.url, org, f.check),
		})
	}
	state := finding.StateOK
	if o.incomplete {
		state = finding.StateError
	}
	r.scopedStatus(acct, orgScope(org), state, "owner; %d findings; %s", len(o.found), strings.Join(o.notes, "; "))
}

// orgPeople reports members and outside collaborators without two-factor authentication.
// GitHub lets only owners use the 2fa_disabled filter.
func (r *run) orgPeople(ctx context.Context, o *orgReport) {
	if ms, err := list[login](ctx, r, "/orgs/"+o.org+"/members?filter=2fa_disabled&per_page=100"); err != nil {
		o.fail("members without 2FA", err)
	} else if len(ms) > 0 {
		o.add(orgMembersNo2FA, fmt.Sprintf("%d %s of %s %s no two-factor authentication", len(ms), textfmt.Plural(len(ms), "member", "members"), o.org, textfmt.Plural(len(ms), "has", "have")),
			"Ask them to enable two-factor authentication, then require it for the organization.",
			"https://github.com/orgs/"+o.org+"/people", map[string]any{"count": len(ms), "logins": logins(ms)})
	}
	all, err := list[login](ctx, r, "/orgs/"+o.org+"/outside_collaborators?per_page=100")
	if err != nil {
		o.fail("outside collaborators", err)
		return
	}
	o.note("%d outside collaborators", len(all))
	if len(all) == 0 {
		return
	}
	cs, err := list[login](ctx, r, "/orgs/"+o.org+"/outside_collaborators?filter=2fa_disabled&per_page=100")
	if err != nil {
		o.fail("outside collaborators without 2FA", err)
	} else if len(cs) > 0 {
		o.add(orgCollaboratorsNo2FA, fmt.Sprintf("%d outside %s of %s %s no two-factor authentication", len(cs), textfmt.Plural(len(cs), "collaborator", "collaborators"), o.org, textfmt.Plural(len(cs), "has", "have")),
			"Ask them to enable two-factor authentication, or remove their access, then require it for the organization.",
			"https://github.com/orgs/"+o.org+"/outside-collaborators", map[string]any{"count": len(cs), "logins": logins(cs)})
	}
}

// orgScanning compares the code security configurations applied to new repositories with secret
// scanning and push protection. The organization's own *_enabled_for_new_repositories fields are
// deprecated in favour of these configurations, so they are not read.
func (r *run) orgScanning(ctx context.Context, o *orgReport, plan string) {
	var defaults []defaultConfig
	if err := r.get(ctx, "/orgs/"+o.org+"/code-security/configurations/defaults", &defaults); err != nil {
		o.fail("code security defaults", err)
		return
	}
	public, private := scanningDefaults(defaults)
	const fix = "Under Code security, Configurations, apply a configuration with secret scanning and push protection enabled (\"GitHub recommended\" has both) and make it the default for new %s repositories."
	url := o.settings + "/security_analysis"
	if !public.ok {
		o.add(orgNoPublicScanning, "New public repositories in "+o.org+" do not get secret scanning and push protection by default",
			fmt.Sprintf(fix, "public"), url, map[string]any{"default_configuration": public.name})
	}
	switch {
	case private.ok:
	case plan == "free":
		// Secret scanning on private repositories needs GitHub Secret Protection, which the Free
		// plan cannot buy: nothing the owner can turn on.
		o.note("secret scanning for private repositories is not available on the Free plan")
	default:
		o.add(orgNoPrivateScanning, "New private repositories in "+o.org+" do not get secret scanning and push protection by default",
			fmt.Sprintf(fix, "private and internal"), url, map[string]any{"default_configuration": private.name, "plan": plan})
	}
}

type scanning struct {
	ok   bool   // secret scanning and push protection both enabled
	name string // configuration applied by default, if any
}

// scanningDefaults reads which default configuration covers new public and new private repos.
func scanningDefaults(defaults []defaultConfig) (public, private scanning) {
	for _, d := range defaults {
		s := scanning{ok: d.Config.SecretScanning == "enabled" && d.Config.PushProtection == "enabled", name: d.Config.Name}
		if d.For == "public" || d.For == "all" {
			public = s
		}
		if d.For == "private_and_internal" || d.For == "all" {
			private = s
		}
	}
	return public, private
}

func (r *run) orgActions(ctx context.Context, o *orgReport) {
	url := o.settings + "/actions"
	var ap actionsPermissions
	if err := r.get(ctx, "/orgs/"+o.org+"/actions/permissions", &ap); err != nil {
		o.fail("Actions permissions", err)
		return
	}
	if ap.EnabledRepositories == "none" {
		o.note("Actions disabled")
		return
	}
	if ap.AllowedActions == "all" {
		o.add(orgAllActions, "Workflows in "+o.org+" may use any action from any author",
			"Under Actions, General, allow only actions from GitHub, verified creators or a list you choose, so a compromised third-party action cannot run.",
			url, map[string]any{"allowed_actions": ap.AllowedActions, "enabled_repositories": ap.EnabledRepositories})
	}
	var wp workflowPermissions
	if err := r.get(ctx, "/orgs/"+o.org+"/actions/permissions/workflow", &wp); err != nil {
		o.fail("default workflow permissions", err)
		return
	}
	if wp.Default == "write" {
		o.add(orgWorkflowWrite, "Workflows in "+o.org+" get a read and write GITHUB_TOKEN by default",
			"Under Actions, General, Workflow permissions, choose \"Read repository contents and packages permissions\"; workflows that need more ask for it with `permissions:`.",
			url, map[string]any{"default_workflow_permissions": wp.Default})
	}
	if wp.CanApprovePRs {
		o.add(orgActionsApprovePRs, "Workflows in "+o.org+" can create and approve pull requests",
			"Under Actions, General, Workflow permissions, untick \"Allow GitHub Actions to create and approve pull requests\", so a workflow cannot approve its own changes.",
			url, nil)
	}
}

func withCheck(ev map[string]any, c check) map[string]any {
	out := map[string]any{"check": string(c)}
	for k, v := range ev {
		out[k] = v
	}
	return out
}

// maxLogins caps the logins listed in one finding's evidence.
const maxLogins = 50

func logins(ls []login) []string {
	out := make([]string, 0, min(len(ls), maxLogins))
	for _, l := range ls[:min(len(ls), maxLogins)] {
		out = append(out, l.Login)
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
