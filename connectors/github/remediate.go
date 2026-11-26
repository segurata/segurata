package github

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/fanout"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/textfmt"
)

// Each action groups the findings of one GitHub owner, so one plan covers all its repositories.
const (
	// ActionSecretScanning enables secret scanning and push protection on public repositories.
	ActionSecretScanning = "github.secret-scanning.enable"
	// ActionWorkflowRead makes the default GITHUB_TOKEN read-only in organizations and repositories.
	ActionWorkflowRead = "github.workflow-token.read"
)

// checkActions: a repository finding with both checks offers secret scanning first, and the
// workflow action once the next run finds only that issue left.
var checkActions = map[check]string{
	repoNoSecretScanning:     ActionSecretScanning,
	repoNoPushProtection:     ActionSecretScanning,
	repoForkNoSecretScanning: ActionSecretScanning,
	repoWorkflowWrite:        ActionWorkflowRead,
	repoForkWorkflowWrite:    ActionWorkflowRead,
	orgWorkflowWrite:         ActionWorkflowRead,
}

func remedy(summary, url, owner string, checks ...check) finding.Remediation {
	r := finding.Remediation{Summary: summary, URL: url}
	for _, want := range []string{ActionSecretScanning, ActionWorkflowRead} {
		for _, c := range checks {
			if checkActions[c] == want {
				r.Action, r.Group = want, owner
				return r
			}
		}
	}
	return r
}

func ghStep(args ...string) connector.Step {
	return connector.Step{Argv: append([]string{"gh", "api"}, args...)}
}

func scanningStep(full, status string, features []string) connector.Step {
	args := []string{"--method", "PATCH", "--silent", "/repos/" + full}
	for _, f := range features {
		args = append(args, "-f", "security_and_analysis["+f+"][status]="+status)
	}
	return ghStep(args...)
}

func workflowStep(base, perm string, canApprove bool) connector.Step {
	return ghStep("--method", "PUT", "--silent", base+"/actions/permissions/workflow",
		"-f", "default_workflow_permissions="+perm, "-F", "can_approve_pull_request_reviews="+strconv.FormatBool(canApprove))
}

const (
	featureScanning = "secret_scanning"
	featurePush     = "secret_scanning_push_protection"
)

var scanningFeatureSets = [][]string{{featureScanning, featurePush}, {featureScanning}, {featurePush}}

// target is one repository or organization named by a group's findings, as read now.
type target struct {
	base       string // /repos/<owner>/<name> or /orgs/<org>, from GitHub's answer
	name       string
	eligible   bool
	why        string   // why it is left out when not eligible
	features   []string // secret scanning features off now
	canApprove bool
}

// names also counts the repositories a capped roll-up list left out.
func names(fs []finding.Finding) (repos, orgs []string, unlisted int) {
	seen := map[string]bool{}
	add := func(list *[]string, n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			*list = append(*list, n)
		}
	}
	for _, f := range fs {
		switch f.Resource.Type {
		case "github_repo":
			n, _ := f.Evidence["repository"].(string)
			add(&repos, n)
		case "github_repo_setting":
			listed, _ := f.Evidence["repositories"].([]any)
			for _, v := range listed {
				n, _ := v.(string)
				add(&repos, n)
			}
			if n, ok := f.Evidence["count"].(float64); ok && int(n) > len(listed) {
				unlisted += int(n) - len(listed)
			}
		case "github_org_setting":
			add(&orgs, f.Resource.Name)
		}
	}
	sort.Strings(repos)
	sort.Strings(orgs)
	return repos, orgs, unlisted
}

func (c *Connector) get(ctx context.Context, path string, out any) error {
	raw, err := ghGet(ctx, c.Run, "", path)
	if err != nil {
		return err
	}
	return decodeJSON(path, raw, out)
}

func readEach(ctx context.Context, items []string, read func(context.Context, string) (target, error)) ([]target, error) {
	out := make([]target, len(items))
	errs := make([]error, len(items))
	fanout.Each(len(items), concurrency, func(i int) { out[i], errs[i] = read(ctx, items[i]) })
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// readRepo says whether an action may change the repository: administered and not archived.
func (c *Connector) readRepo(ctx context.Context, full string) (repo, target, bool, error) {
	var rp repo
	if err := c.get(ctx, "/repos/"+full, &rp); err != nil {
		if notFound(err) {
			return rp, target{name: full, why: "not found (renamed, deleted or no longer visible to you)"}, false, nil
		}
		return rp, target{}, false, err
	}
	t := target{base: "/repos/" + rp.FullName, name: rp.FullName}
	switch {
	case !rp.Permissions.Admin:
		t.why = "you no longer administer it"
	case rp.Archived:
		t.why = "archived, so read-only"
	default:
		return rp, t, true, nil
	}
	return rp, t, false, nil
}

func (c *Connector) readScanning(ctx context.Context, full string) (target, error) {
	rp, t, ok, err := c.readRepo(ctx, full)
	if err != nil || !ok {
		return t, err
	}
	sa := rp.SecurityAndAnalysis
	switch {
	case rp.Visibility != "public":
		t.why = rp.Visibility + ": secret scanning there needs GitHub Secret Protection, a paid add-on billed per committer; turn it on by hand if you have it"
		return t, nil
	case sa == nil:
		t.why = "GitHub does not offer secret scanning on it"
		return t, nil
	}
	if sa.SecretScanning.disabled() {
		t.features = append(t.features, featureScanning)
	}
	if sa.PushProtection.disabled() {
		t.features = append(t.features, featurePush)
	}
	if len(t.features) == 0 {
		t.why = "secret scanning and push protection are already on"
		return t, nil
	}
	t.eligible = true
	return t, nil
}

func (c *Connector) readRepoWorkflow(ctx context.Context, full string) (target, error) {
	_, t, ok, err := c.readRepo(ctx, full)
	if err != nil || !ok {
		return t, err
	}
	return c.readWorkflow(ctx, t)
}

func (c *Connector) readOrgWorkflow(ctx context.Context, org string) (target, error) {
	return c.readWorkflow(ctx, target{base: "/orgs/" + org, name: org})
}

func (c *Connector) readWorkflow(ctx context.Context, t target) (target, error) {
	var wp workflowPermissions
	if err := c.get(ctx, t.base+"/actions/permissions/workflow", &wp); err != nil {
		if denied(err) {
			t.why = "its workflow permissions are not readable with gh's token (owner rights and admin:org for an organization)"
			return t, nil
		}
		return t, err
	}
	if wp.Default != "write" {
		t.why = "the default workflow token is already " + wp.Default
		return t, nil
	}
	t.eligible, t.canApprove = true, wp.CanApprovePRs
	return t, nil
}

type state struct {
	action   string
	owner    string
	targets  []target
	unlisted int
}

func (c *Connector) read(ctx context.Context, fs []finding.Finding) (state, error) {
	if len(fs) == 0 {
		return state{}, fmt.Errorf("no finding to plan")
	}
	st := state{action: fs[0].Remediation.Action, owner: fs[0].Remediation.Group}
	repos, orgs, unlisted := names(fs)
	st.unlisted = unlisted
	var err error
	var got []target
	switch st.action {
	case ActionSecretScanning:
		got, err = readEach(ctx, repos, c.readScanning)
	case ActionWorkflowRead:
		var ot, rt []target
		if ot, err = readEach(ctx, orgs, c.readOrgWorkflow); err == nil {
			rt, err = readEach(ctx, repos, c.readRepoWorkflow)
		}
		got = append(ot, rt...) // the organization's default bounds its repositories'
	default:
		return state{}, fmt.Errorf("github has no remediation %q", st.action)
	}
	if err != nil {
		return state{}, err
	}
	st.targets = got
	return st, nil
}

func (st state) plan() (connector.Plan, error) {
	p := connector.Plan{Action: st.action}
	var left []string
	n := 0
	for _, t := range st.targets {
		if !t.eligible {
			left = append(left, fmt.Sprintf("Left out: %s (%s).", t.name, t.why))
			continue
		}
		n++
		switch st.action {
		case ActionSecretScanning:
			p.Commands = append(p.Commands, scanningStep(t.name, "enabled", t.features))
			p.Undo = append(p.Undo, scanningStep(t.name, "disabled", t.features))
		case ActionWorkflowRead:
			p.Commands = append(p.Commands, workflowStep(t.base, "read", t.canApprove))
			p.Undo = append(p.Undo, workflowStep(t.base, "write", t.canApprove))
		}
	}
	if n == 0 {
		return connector.Plan{}, fmt.Errorf("nothing to do for %s on %s: %d checked now, none still needs it; run the inventory again", st.action, st.owner, len(st.targets))
	}
	switch st.action {
	case ActionSecretScanning:
		p.Summary = fmt.Sprintf("Turn on secret scanning and push protection in %d public %s of %s.", n, textfmt.Plural(n, "repository", "repositories"), st.owner)
		p.SideEffects = []string{
			"GitHub scans each repository's whole git history and opens a secret scanning alert for every credential it recognises; the alerts are visible to the repository's admins (and, for an organization, its security managers).",
			"Push protection blocks pushes that contain a recognised credential, for everyone who pushes to these repositories; a pusher can bypass a block by giving a reason, which GitHub records.",
			"Free on public repositories: no billing change.",
		}
	case ActionWorkflowRead:
		p.Summary = fmt.Sprintf("Make the default GITHUB_TOKEN of workflows read-only in %d %s of %s.", n, textfmt.Plural(n, "place", "places"), st.owner)
		p.SideEffects = []string{
			"A workflow that writes with GITHUB_TOKEN (pushes, comments, labels, releases, packages, deployments) and does not declare `permissions:` fails with HTTP 403 until it declares what it needs.",
			"Whether workflows may create and approve pull requests stays as it is in each place.",
			"An organization's setting needs gh's admin:org scope; without it that step fails and the rest does not run.",
		}
	}
	p.SideEffects = append(p.SideEffects, left...)
	if st.unlisted > 0 {
		p.SideEffects = append(p.SideEffects, fmt.Sprintf("%d more repositories are beyond the %d a finding lists, so not in this plan: apply, then run the inventory and this action again.", st.unlisted, maxListed))
	}
	return p, nil
}

// allowlist is built from what GitHub says is eligible now, never from names in a finding.
func (st state) allowlist() connector.Allowlist {
	allow := connector.Allowlist{}
	for _, t := range st.targets {
		if !t.eligible {
			continue
		}
		switch st.action {
		case ActionSecretScanning:
			for _, fs := range scanningFeatureSets {
				allow[st.action] = append(allow[st.action], scanningStep(t.name, "enabled", fs))
			}
		case ActionWorkflowRead:
			for _, approve := range []bool{false, true} {
				allow[st.action] = append(allow[st.action], workflowStep(t.base, "read", approve))
			}
		}
	}
	return allow
}

func (c *Connector) Plan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	return c.PlanGroup(ctx, []finding.Finding{f})
}

func (c *Connector) Apply(ctx context.Context, f finding.Finding, p connector.Plan, io connector.IO) error {
	return c.ApplyGroup(ctx, []finding.Finding{f}, p, io)
}

func (c *Connector) PlanGroup(ctx context.Context, fs []finding.Finding) (connector.Plan, error) {
	st, err := c.read(ctx, fs)
	if err != nil {
		return connector.Plan{}, err
	}
	return st.plan()
}

func (c *Connector) ApplyGroup(ctx context.Context, fs []finding.Finding, p connector.Plan, io connector.IO) error {
	st, err := c.read(ctx, fs)
	if err != nil {
		return err
	}
	return st.allowlist().Run(ctx, p, c.Exec, io)
}
