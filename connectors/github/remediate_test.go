package github

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/connector/connectortest"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
)

type recordingExec struct{ ran []string }

func (r *recordingExec) Run(_ context.Context, s connector.Step, _ connector.IO) error {
	r.ran = append(r.ran, s.String())
	return nil
}

// roundTrip gives findings the shape remediate reads back from a run file.
func roundTrip(t *testing.T, fs []finding.Finding) []finding.Finding {
	t.Helper()
	raw, err := json.Marshal(fs)
	if err != nil {
		t.Fatal(err)
	}
	var out []finding.Finding
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// groupOf runs the inventory of the synthetic world and returns the group remediate would gather
// for the action and owner.
func groupOf(t *testing.T, action, owner string) []finding.Finding {
	t.Helper()
	rec := inventory(t, world(), nil)
	all := roundTrip(t, rec.Findings)
	for i := range all {
		all[i].Connector = "github"
		all[i].Fill(all[i].ObservedAt)
	}
	for _, f := range all {
		if f.Remediation.Action == action && f.Remediation.Group == owner {
			return remediate.Members(all, f)
		}
	}
	t.Fatalf("no finding offers %s for %s", action, owner)
	return nil
}

func TestInventoryOffersActionsGroupedByOwner(t *testing.T) {
	rec := inventory(t, world(), nil)
	got := map[string]string{}
	for _, f := range rec.Findings {
		if f.Remediation.Action != "" {
			got[f.Resource.Type+" "+f.Resource.ID] = f.Remediation.Action + " " + f.Remediation.Group
		}
	}
	want := map[string]string{
		// secret scanning comes first; the workflow issue of the same repository waits for it
		"github_repo 101": ActionSecretScanning + " octo-tester",
		"github_repo_setting " + string(repoForkNoSecretScanning): ActionSecretScanning + " octo-tester",
		"github_repo_setting " + string(repoForkWorkflowWrite):    ActionWorkflowRead + " octo-tester",
		"github_org_setting " + string(orgWorkflowWrite):          ActionWorkflowRead + " acme-corp",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("actions\n got %v\nwant %v", got, want)
	}
}

func TestSecretScanningPlanReadsEachRepositoryNow(t *testing.T) {
	group := groupOf(t, ActionSecretScanning, "octo-tester")
	private := finding.Finding{ID: "p", Connector: "github", Resource: finding.Resource{Type: "github_repo"},
		Evidence: map[string]any{"repository": "acme-corp/api"}, Remediation: group[0].Remediation}
	gone := finding.Finding{ID: "g", Connector: "github", Resource: finding.Resource{Type: "github_repo"},
		Evidence: map[string]any{"repository": "octo-tester/deleted"}, Remediation: group[0].Remediation}
	c := &Connector{Run: world()}
	p, err := c.PlanGroup(context.Background(), append(group, private, gone))
	if err != nil {
		t.Fatal(err)
	}
	if p.Summary != "Turn on secret scanning and push protection in 2 public repositories of octo-tester." {
		t.Errorf("summary: %s", p.Summary)
	}
	want := []string{
		"gh api --method PATCH --silent /repos/octo-tester/forked -f 'security_and_analysis[secret_scanning][status]=enabled' -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'",
		"gh api --method PATCH --silent /repos/octo-tester/site -f 'security_and_analysis[secret_scanning][status]=enabled' -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'",
	}
	if got := strs(p.Commands); !reflect.DeepEqual(got, want) {
		t.Errorf("commands\n got %v\nwant %v", got, want)
	}
	if got := strs(p.Undo); len(got) != 2 || !strings.Contains(got[1], "/repos/octo-tester/site -f 'security_and_analysis[secret_scanning][status]=disabled'") {
		t.Errorf("undo: %v", got)
	}
	effects := strings.Join(p.SideEffects, "\n")
	for _, w := range []string{"Left out: acme-corp/api (private: secret scanning there needs GitHub Secret Protection",
		"Left out: octo-tester/deleted (not found", "whole git history", "bypass"} {
		if !strings.Contains(effects, w) {
			t.Errorf("side effects lack %q:\n%s", w, effects)
		}
	}
}

func TestWorkflowPlanCoversTheOrganizationFirstAndKeepsTheApproveFlag(t *testing.T) {
	org := groupOf(t, ActionWorkflowRead, "acme-corp")
	c := &Connector{Run: world()}
	p, err := c.PlanGroup(context.Background(), org)
	if err != nil {
		t.Fatal(err)
	}
	if got := strs(p.Commands); !reflect.DeepEqual(got, []string{
		"gh api --method PUT --silent /orgs/acme-corp/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=true",
	}) {
		t.Errorf("organization plan: %v", got)
	}
	if got := strs(p.Undo); got[0] != "gh api --method PUT --silent /orgs/acme-corp/actions/permissions/workflow -f default_workflow_permissions=write -F can_approve_pull_request_reviews=true" {
		t.Errorf("undo: %v", got)
	}

	forks := groupOf(t, ActionWorkflowRead, "octo-tester")
	// The site's workflow issue once secret scanning is on: same repository finding, next action.
	site := finding.Finding{ID: "site", Connector: "github", Resource: finding.Resource{Type: "github_repo"},
		Evidence: map[string]any{"repository": "octo-tester/site"}, Remediation: forks[0].Remediation}
	p, err = c.PlanGroup(context.Background(), append(forks, site))
	if err != nil {
		t.Fatal(err)
	}
	if got := strs(p.Commands); !reflect.DeepEqual(got, []string{
		"gh api --method PUT --silent /repos/octo-tester/forked-ci/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false",
		"gh api --method PUT --silent /repos/octo-tester/site/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false",
	}) {
		t.Errorf("repository plan: %v", got)
	}
}

func TestWorkflowPlanLeavesOutWhatNoLongerApplies(t *testing.T) {
	gh := world()
	gh.replies["/repos/acme-corp/old"] = repoJSON(103, "acme-corp/old", "public", true, true)
	gh.replies["/repos/other-org/shared"] = repoJSON(104, "other-org/shared", "private", false, false)
	gh.errs["/orgs/tidy-free/actions/permissions/workflow"] = httpErr("Must have admin rights to Repository.", 403)
	rem := finding.Remediation{Action: ActionWorkflowRead, Group: "octo-tester"}
	group := []finding.Finding{{ID: "o", Resource: finding.Resource{Type: "github_org_setting", Name: "tidy-free"}, Remediation: rem}}
	for _, full := range []string{"octo-tester/forked-ci", "acme-corp/old", "other-org/shared", "tidy-free/web"} {
		group = append(group, finding.Finding{ID: full, Resource: finding.Resource{Type: "github_repo"},
			Evidence: map[string]any{"repository": full}, Remediation: rem})
	}
	c := &Connector{Run: gh}
	p, err := c.PlanGroup(context.Background(), group)
	if err != nil {
		t.Fatal(err)
	}
	if got := strs(p.Commands); len(got) != 1 || !strings.Contains(got[0], "/repos/octo-tester/forked-ci/") {
		t.Errorf("commands: %v", got)
	}
	effects := strings.Join(p.SideEffects, "\n")
	for _, w := range []string{"Left out: tidy-free (its workflow permissions are not readable",
		"Left out: acme-corp/old (archived", "Left out: other-org/shared (you no longer administer it)",
		"Left out: tidy-free/web (the default workflow token is already read)"} {
		if !strings.Contains(effects, w) {
			t.Errorf("side effects lack %q:\n%s", w, effects)
		}
	}
	gh.errs["/repos/octo-tester/forked-ci"] = httpErr("Server Error", 500)
	if _, err := c.PlanGroup(context.Background(), group); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("a failed read must stop the plan: %v", err)
	}
}

func TestApplyRunsExactlyThePlanThroughALiveAllowlist(t *testing.T) {
	group := groupOf(t, ActionSecretScanning, "octo-tester")
	ex := &recordingExec{}
	c := &Connector{Run: world(), Exec: ex}
	p, err := c.PlanGroup(context.Background(), group)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ApplyGroup(context.Background(), group, p, connectortest.QuietIO()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ex.ran, strs(p.Commands)) {
		t.Fatalf("ran %v, want the plan %v", ex.ran, strs(p.Commands))
	}

	altered := p
	altered.Commands = append([]connector.Step{scanningStep("acme-corp/api", "enabled", []string{featureScanning})}, p.Commands...)
	ex.ran = nil
	if err := c.ApplyGroup(context.Background(), group, altered, connectortest.QuietIO()); err == nil || len(ex.ran) != 0 {
		t.Fatalf("an altered plan must be refused before running: %v ran=%v", err, ex.ran)
	}

	st, err := c.read(context.Background(), group)
	if err != nil {
		t.Fatal(err)
	}
	allow := st.allowlist()
	for _, s := range []connector.Step{
		scanningStep("acme-corp/api", "enabled", []string{featureScanning, featurePush}), // not in the group
		scanningStep("octo-tester/site", "disabled", []string{featureScanning}),          // the undo is not an action
		ghStep("--method", "DELETE", "/repos/octo-tester/site"),
		{Argv: scanningStep("octo-tester/site", "enabled", []string{featurePush}).Argv, Sudo: true},
	} {
		if err := allow.Check(ActionSecretScanning, s); !errors.Is(err, connector.ErrRefused) {
			t.Errorf("%s: want refusal, got %v", s, err)
		}
	}
	if err := allow.Check(ActionWorkflowRead, p.Commands[0]); !errors.Is(err, connector.ErrRefused) {
		t.Error("a step allowed for one action must not run for another")
	}
}

func TestNothingLeftToDoIsAnError(t *testing.T) {
	gh := world()
	gh.replies["/repos/octo-tester/site"] = withSA(repoJSON(101, "octo-tester/site", "public", false, true),
		`{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}`)
	site := finding.Finding{ID: "site", Connector: "github", Resource: finding.Resource{Type: "github_repo"},
		Evidence: map[string]any{"repository": "octo-tester/site"}, Remediation: finding.Remediation{Action: ActionSecretScanning, Group: "octo-tester"}}
	if _, err := (&Connector{Run: gh}).Plan(context.Background(), site); err == nil || !strings.Contains(err.Error(), "nothing to do") {
		t.Fatalf("want nothing to do, got %v", err)
	}
}

func TestRolledUpListBeyondTheCapIsNamedInThePlan(t *testing.T) {
	forks := groupOf(t, ActionSecretScanning, "octo-tester")
	for i := range forks {
		if forks[i].Resource.Type == "github_repo_setting" {
			forks[i].Evidence["count"] = float64(250)
		}
	}
	p, err := (&Connector{Run: world()}).PlanGroup(context.Background(), forks)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.SideEffects, "\n"), "249 more repositories are beyond the 200") {
		t.Fatalf("side effects: %v", p.SideEffects)
	}
}

func strs(steps []connector.Step) []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.String()
	}
	return out
}
