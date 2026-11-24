package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// hookToken is a synthetic credential inside a webhook URL; it must never reach a record.
const hookToken = "hooktoken-TEST-not-a-real-secret"

// fakeGH answers `gh api --method GET [flag] <path>` by path, through the real read-only guard's
// shape, and records every path asked for.
type fakeGH struct {
	mu      sync.Mutex
	scopes  string // X-OAuth-Scopes; "-" leaves the header out
	remain  int
	replies map[string]string
	errs    map[string]error
	calls   []string
}

func (f *fakeGH) Run(_ context.Context, args ...string) ([]byte, error) {
	if !allowed(args) {
		return nil, fmt.Errorf("test runner got a command the guard should have refused: %v", args)
	}
	path := args[len(args)-1]
	f.mu.Lock()
	f.calls = append(f.calls, path)
	f.mu.Unlock()
	if err, ok := f.errs[path]; ok {
		return nil, err
	}
	if path == "/rate_limit" {
		head := "HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n"
		if f.scopes != "-" {
			head += "X-Oauth-Scopes: " + f.scopes + "\r\n"
		}
		return []byte(head + "\r\n" + fmt.Sprintf(`{"resources":{"core":{"limit":5000,"remaining":%d,"reset":1795484099}}}`, f.remain)), nil
	}
	if out, ok := f.replies[path]; ok {
		return []byte(out), nil
	}
	return nil, httpErr("Not Found", 404)
}

func (f *fakeGH) called(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == path {
			return true
		}
	}
	return false
}

func httpErr(msg string, code int) error {
	return &cli.Error{Cmd: "gh api", Stderr: fmt.Sprintf("{\"message\":%q}\ngh: %s (HTTP %d)\n", msg, msg, code), Err: errors.New("exit status 1")}
}

const allScopes = "admin:org, admin:public_key, gist, read:user, repo, workflow"

// account is a synthetic GitHub world: one user owning acme-corp (Team plan, weak settings) and
// tidy-free (Free plan, good settings), member of other-org, with four repositories.
func world() *fakeGH {
	return &fakeGH{scopes: allScopes, remain: 5000, replies: map[string]string{
		"/user": `{"login":"octo-tester","two_factor_authentication":false}`,
		"/user/memberships/orgs?state=active&per_page=100": `[{"role":"admin","organization":{"login":"acme-corp"}},{"role":"admin","organization":{"login":"tidy-free"}}]` +
			`[{"role":"member","organization":{"login":"other-org"}}]`,

		"/orgs/acme-corp": `{"login":"acme-corp","two_factor_requirement_enabled":false,"default_repository_permission":"write","members_can_create_public_repositories":true,"plan":{"name":"team"}}`,
		"/orgs/acme-corp/members?filter=2fa_disabled&per_page=100":               `[{"login":"alice-example"},{"login":"bob-example"}]`,
		"/orgs/acme-corp/outside_collaborators?per_page=100":                     `[{"login":"carol-example"}]`,
		"/orgs/acme-corp/outside_collaborators?filter=2fa_disabled&per_page=100": `[{"login":"carol-example"}]`,
		"/orgs/acme-corp/code-security/configurations/defaults":                  `[]`,
		"/orgs/acme-corp/actions/permissions":                                    `{"enabled_repositories":"all","allowed_actions":"all"}`,
		"/orgs/acme-corp/actions/permissions/workflow":                           `{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}`,

		"/orgs/tidy-free": `{"login":"tidy-free","two_factor_requirement_enabled":true,"default_repository_permission":"read","members_can_create_public_repositories":false,"plan":{"name":"free"}}`,
		"/orgs/tidy-free/members?filter=2fa_disabled&per_page=100": `[]`,
		"/orgs/tidy-free/outside_collaborators?per_page=100":       `[]`,
		"/orgs/tidy-free/code-security/configurations/defaults":    `[{"default_for_new_repos":"public","configuration":{"name":"GitHub recommended","secret_scanning":"enabled","secret_scanning_push_protection":"enabled"}}]`,
		"/orgs/tidy-free/actions/permissions":                      `{"enabled_repositories":"all","allowed_actions":"selected"}`,
		"/orgs/tidy-free/actions/permissions/workflow":             `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`,

		"/user/repos?affiliation=owner,organization_member&per_page=100": `[` +
			repoJSON(101, "octo-tester/site", "public", false, true) + `,` +
			repoJSON(102, "acme-corp/api", "private", false, true) + `,` +
			repoJSON(103, "acme-corp/old", "public", true, true) + `]` +
			`[` + repoJSON(104, "other-org/shared", "private", false, false) + `,` +
			repoJSON(105, "tidy-free/web", "public", false, true) + `,` +
			fork(106, "octo-tester/forked") + `,` + fork(107, "octo-tester/forked-ci") + `]`,

		"/repos/octo-tester/site": withSA(repoJSON(101, "octo-tester/site", "public", false, true),
			`{"secret_scanning":{"status":"disabled"},"secret_scanning_push_protection":{"status":"disabled"},"dependabot_security_updates":{"status":"disabled"}}`),
		"/repos/octo-tester/site/hooks?per_page=100": `[{"id":7,"active":true,"config":{"url":"http://hooks.example.com/in?token=` + hookToken + `","insecure_ssl":"0"}},` +
			`{"id":8,"active":false,"config":{"url":"https://ci.example.com/hook","insecure_ssl":1}},` +
			`{"id":9,"active":true,"config":{"url":"https://ok.example.com/hook","insecure_ssl":"0"}}]`,
		"/repos/octo-tester/site/keys?per_page=100": `[{"id":11,"title":"deploy-bot","read_only":false,"created_at":"2021-01-01T00:00:00Z","last_used":null,"key":"ssh-ed25519 AAAASYNTHETIC"},` +
			`{"id":12,"title":"reader","read_only":true,"created_at":"2021-01-01T00:00:00Z","key":"ssh-ed25519 AAAASYNTHETIC2"}]`,
		"/repos/octo-tester/site/actions/permissions":          `{"enabled":true,"allowed_actions":"all"}`,
		"/repos/octo-tester/site/actions/permissions/workflow": `{"default_workflow_permissions":"write","can_approve_pull_request_reviews":false}`,

		"/repos/octo-tester/forked": withSA(strings.Replace(repoJSON(106, "octo-tester/forked", "public", false, true), `"archived"`, `"fork":true,"archived"`, 1),
			`{"secret_scanning":{"status":"disabled"},"secret_scanning_push_protection":{"status":"disabled"},"dependabot_security_updates":{"status":"enabled"}}`),
		"/repos/octo-tester/forked/hooks?per_page=100":               `[]`,
		"/repos/octo-tester/forked/keys?per_page=100":                `[]`,
		"/repos/octo-tester/forked/actions/permissions":              `{"enabled":false}`,
		"/repos/octo-tester/forked/rules/branches/main?per_page=100": `[{"type":"deletion"}]`,

		"/repos/octo-tester/forked-ci":                                  fork(107, "octo-tester/forked-ci"),
		"/repos/octo-tester/forked-ci/hooks?per_page=100":               `[]`,
		"/repos/octo-tester/forked-ci/keys?per_page=100":                `[]`,
		"/repos/octo-tester/forked-ci/actions/permissions":              `{"enabled":true}`,
		"/repos/octo-tester/forked-ci/actions/permissions/workflow":     `{"default_workflow_permissions":"write","can_approve_pull_request_reviews":false}`,
		"/repos/octo-tester/forked-ci/rules/branches/main?per_page=100": `[{"type":"deletion"}]`,

		"/repos/acme-corp/api": withSA(repoJSON(102, "acme-corp/api", "private", false, true),
			`{"secret_scanning":{"status":"disabled"},"secret_scanning_push_protection":{"status":"disabled"}}`),
		"/repos/acme-corp/api/hooks?per_page=100": `[]`,
		"/repos/acme-corp/api/keys?per_page=100":  `[]`,

		"/repos/tidy-free/web": withSA(repoJSON(105, "tidy-free/web", "public", false, true),
			`{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"},"dependabot_security_updates":{"status":"disabled"}}`),
		"/repos/tidy-free/web/hooks?per_page=100":                  `[]`,
		"/repos/tidy-free/web/keys?per_page=100":                   `[]`,
		"/repos/tidy-free/web/actions/permissions":                 `{"enabled":true,"allowed_actions":"selected"}`,
		"/repos/tidy-free/web/actions/permissions/workflow":        `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`,
		"/repos/tidy-free/web/branches/main/protection":            `{"url":"x"}`,
		"/repos/octo-tester/site/rules/branches/main?per_page=100": `[]`,
	}, errs: map[string]error{
		"/repos/octo-tester/site/branches/main/protection":      httpErr("Branch not protected", 404),
		"/repos/octo-tester/forked/branches/main/protection":    httpErr("Branch not protected", 404),
		"/repos/octo-tester/forked-ci/branches/main/protection": httpErr("Branch not protected", 404),
	}}
}

func repoJSON(id int, full, vis string, archived, admin bool) string {
	owner, _, _ := strings.Cut(full, "/")
	return fmt.Sprintf(`{"id":%d,"full_name":%q,"visibility":%q,"archived":%t,"default_branch":"main","owner":{"login":%q},"permissions":{"admin":%t}}`,
		id, full, vis, archived, owner, admin)
}

func fork(id int, full string) string {
	return strings.Replace(repoJSON(id, full, "public", false, true), `"archived"`, `"fork":true,"archived"`, 1)
}

func withSA(repo, sa string) string {
	return strings.TrimSuffix(repo, "}") + `,"security_and_analysis":` + sa + `}`
}

func inventory(t *testing.T, gh *fakeGH, cfg map[string]any) *httpxtest.Recorder {
	t.Helper()
	rec := &httpxtest.Recorder{}
	c := &Connector{Run: gh}
	if err := c.Inventory(context.Background(), connector.Request{Config: cfg}, rec); err != nil {
		t.Fatal(err)
	}
	rec.AssertNoSecret(t, hookToken)
	rec.AssertNoSecret(t, "AAAASYNTHETIC")
	return rec
}

func statusOf(t *testing.T, rec *httpxtest.Recorder, acct string) finding.Status {
	t.Helper()
	for _, s := range rec.Statuses {
		if s.Account == acct {
			return s
		}
	}
	t.Fatalf("no status for %s: %+v", acct, rec.Statuses)
	return finding.Status{}
}

func statusesOf(rec *httpxtest.Recorder, acct string) []finding.Status {
	var out []finding.Status
	for _, s := range rec.Statuses {
		if s.Account == acct {
			out = append(out, s)
		}
	}
	return out
}

func TestInventoryAccountAndOrganizations(t *testing.T) {
	rec := inventory(t, world(), nil)

	acct := rec.ByResource(t, "github_account", "two-factor-authentication")
	if acct.Severity != finding.SevCritical || acct.Account != "github:octo-tester" || acct.Kind != finding.KindSetting {
		t.Errorf("account 2FA: %+v", acct)
	}

	want := map[check]finding.Severity{
		orgNo2FARequirement:   finding.SevHigh,
		orgMembersNo2FA:       finding.SevHigh,
		orgCollaboratorsNo2FA: finding.SevHigh,
		orgDefaultPermission:  finding.SevMedium,
		orgPublicRepoCreation: finding.SevLow,
		orgWorkflowWrite:      finding.SevMedium,
		orgActionsApprovePRs:  finding.SevLow,
		orgAllActions:         finding.SevLow,
		orgNoPrivateScanning:  finding.SevMedium,
		orgNoPublicScanning:   finding.SevLow,
	}
	got := map[check]finding.Severity{}
	for _, f := range rec.Findings {
		if f.Resource.Type != "github_org_setting" {
			continue
		}
		if f.Account != "github:acme-corp" {
			t.Errorf("finding for a well-configured or member organization: %s %q", f.Account, f.Title)
			continue
		}
		got[check(f.Resource.ID)] = f.Severity
		if f.Remediation.Summary == "" || !strings.HasPrefix(f.Remediation.URL, "https://github.com/") {
			t.Errorf("%s: remediation %+v", f.Resource.ID, f.Remediation)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("org findings\n got %v\nwant %v", got, want)
	}
	members := rec.ByResource(t, "github_org_setting", string(orgMembersNo2FA))
	if members.Title != "2 members of acme-corp have no two-factor authentication" ||
		!reflect.DeepEqual(members.Evidence["logins"], []string{"alice-example", "bob-example"}) {
		t.Errorf("members without 2FA: %q %v", members.Title, members.Evidence)
	}

	if s := statusOf(t, rec, "github:other-org"); s.State != finding.StateOK || !strings.Contains(s.Detail, "not owner") {
		t.Errorf("member organization: %+v", s)
	}
	if s := statusOf(t, rec, "github:tidy-free"); s.State != finding.StateOK || !strings.Contains(s.Detail, "not available on the Free plan") {
		t.Errorf("free organization: %+v", s)
	}
	if s := statusOf(t, rec, "github:acme-corp"); s.State != finding.StateOK || !strings.Contains(s.Detail, "1 outside collaborators") {
		t.Errorf("acme status: %+v", s)
	}
}

func TestInventoryRepositories(t *testing.T) {
	gh := world()
	rec := inventory(t, gh, nil)

	site := rec.ByResource(t, "github_repo", "101")
	if site.Severity != finding.SevHigh || site.Account != "github:octo-tester" || site.Resource.Name != "octo-tester/site" || site.Scope != "repo:octo-tester/site" {
		t.Errorf("site: %+v", site)
	}
	for _, part := range []string{"active webhook 7 to http://hooks.example.com delivers over plain HTTP",
		"inactive webhook 8 to https://ci.example.com skips SSL certificate verification",
		`deploy key "deploy-bot" (id 11) can push, never used`, "secret scanning is off",
		"workflows get a read and write GITHUB_TOKEN by default"} {
		if !strings.Contains(site.Title, part) {
			t.Errorf("site title lacks %q: %s", part, site.Title)
		}
	}
	if strings.HasPrefix(site.Title, "octo-tester/site: active webhook") == false {
		t.Errorf("worst issue must come first: %s", site.Title)
	}
	if strings.Contains(site.Title, "push protection") || strings.Contains(site.Title, "reader") || strings.Contains(site.Title, "webhook 9") {
		t.Errorf("site title reports something fine or implied: %s", site.Title)
	}
	if site.Remediation.URL != "https://github.com/octo-tester/site/settings/hooks/7" {
		t.Errorf("remediation URL is the worst issue's page: %s", site.Remediation.URL)
	}
	raw, _ := json.Marshal(site.Evidence)
	if !strings.Contains(string(raw), `"check":"insecure-webhook"`) {
		t.Errorf("evidence lacks the issue checks: %s", raw)
	}

	dep := rec.ByResource(t, "github_repo_setting", string(repoNoDependabotUpdates))
	if dep.Account != "github:octo-tester" || dep.Severity != finding.SevLow || dep.Scope != "repo:octo-tester" {
		t.Errorf("dependabot roll-up: %+v", dep)
	}
	var rolled []string
	for _, f := range rec.Findings {
		if f.Resource.Type == "github_repo_setting" {
			rolled = append(rolled, f.Account+" "+f.Title)
		}
	}
	sort.Strings(rolled)
	wantRolled := []string{
		"github:acme-corp Secret scanning or push protection is off in 1 private repository of acme-corp",
		"github:octo-tester Dependabot security updates are off in 1 repository of octo-tester",
		"github:octo-tester Secret scanning or push protection is off in 1 forked repository of octo-tester",
		"github:octo-tester Workflows get a read and write GITHUB_TOKEN by default in 1 forked repository of octo-tester",
		"github:tidy-free Dependabot security updates are off in 1 repository of tidy-free",
	}
	if !reflect.DeepEqual(rolled, wantRolled) {
		t.Errorf("rolled-up findings\n got %v\nwant %v", rolled, wantRolled)
	}

	for _, f := range rec.Findings {
		if f.Resource.Type == "github_repo" && f.Resource.ID != "101" {
			t.Errorf("finding for a clean, archived or non-admin repository: %s", f.Title)
		}
	}
	for _, skipped := range []string{"/repos/acme-corp/old", "/repos/other-org/shared", "/repos/acme-corp/api/actions/permissions",
		"/repos/octo-tester/forked/actions/permissions/workflow"} {
		if gh.called(skipped) {
			t.Errorf("requested %s: archived, non-admin, private or Actions-less repositories need no such call", skipped)
		}
	}
	if gh.called("/repos/octo-tester/site/branches/main/protection") {
		t.Error("branch protection is opt-in")
	}
	repos := statesFor(rec, "github:octo-tester")
	if !strings.Contains(repos, "ok: 5 repositories you administer inspected, 5 with issues; 1 archived skipped") {
		t.Errorf("repository status: %s", repos)
	}
	if len(rec.Scopes) != 0 {
		t.Errorf("every repository read, yet skipped scopes declared: %+v", rec.Scopes)
	}
}

// skippedScopes are the scopes a run declared skipped, sorted.
func skippedScopes(rec *httpxtest.Recorder) []string {
	var out []string
	for _, s := range rec.Scopes {
		if !s.Inspected {
			out = append(out, s.ID+" ("+s.Reason+")")
		}
	}
	sort.Strings(out)
	return out
}

func statesFor(rec *httpxtest.Recorder, acct string) string {
	var out []string
	for _, s := range statusesOf(rec, acct) {
		out = append(out, string(s.State)+": "+s.Detail)
	}
	return strings.Join(out, " | ")
}

func TestBranchProtectionOptIn(t *testing.T) {
	gh := world()
	rec := inventory(t, gh, map[string]any{"branch_protection": true})
	bp := rec.ByResource(t, "github_repo_setting", string(repoUnprotectedDefault))
	if bp.Title != "The default branch has no protection in 1 public repository of octo-tester" || bp.Severity != finding.SevLow {
		t.Errorf("branch protection: %q %s", bp.Title, bp.Severity)
	}
	if !gh.called("/repos/octo-tester/site/rules/branches/main?per_page=100") {
		t.Error("an unprotected branch must be checked for rulesets too")
	}
	if gh.called("/repos/tidy-free/web/rules/branches/main?per_page=100") {
		t.Error("a protected branch needs no ruleset lookup")
	}
	if _, ok := rec.ByResource(t, "github_repo_setting", string(repoUnprotectedDefault)).Evidence["repositories"].([]string); !ok {
		t.Error("roll-up evidence lists repositories")
	}
	if got := rec.ByResource(t, "github_repo_setting", string(repoUnprotectedDefault)).Evidence["repositories"]; !reflect.DeepEqual(got, []string{"octo-tester/site"}) {
		t.Errorf("a branch covered by a ruleset counts as protected: %v", got)
	}
}

func TestIDsAreStableAcrossRuns(t *testing.T) {
	ids := func() []string {
		var out []string
		for _, f := range inventory(t, world(), nil).Findings {
			f.Connector = "github"
			f.Fill(time.Time{})
			out = append(out, f.ID)
		}
		sort.Strings(out)
		return out
	}
	a, b := ids(), ids()
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("ids changed between runs:\n%v\n%v", a, b)
	}
	seen := map[string]bool{}
	for _, id := range a {
		if seen[id] {
			t.Fatalf("two findings share id %s", id)
		}
		seen[id] = true
	}
}

func TestMissingScopesBecomeStatuses(t *testing.T) {
	gh := world()
	gh.scopes = "gist, workflow"
	gh.replies["/user"] = `{"login":"octo-tester"}`
	rec := inventory(t, gh, nil)
	if len(rec.Findings) != 0 {
		t.Errorf("findings without scopes: %v", rec.Findings)
	}
	got := statesFor(rec, "github:octo-tester")
	for _, want := range []string{
		"noscope: two-factor authentication not checked: gh's token lacks read:user; run: gh auth refresh -h github.com -s read:user",
		"noscope: organizations not inspected: gh's token lacks read:org; run: gh auth refresh -h github.com -s read:org",
		"noscope: repositories not inspected: gh's token lacks repo; run: gh auth refresh -h github.com -s repo",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("statuses lack %q:\n%s", want, got)
		}
	}
	if gh.called("/user/memberships/orgs?state=active&per_page=100") || gh.called("/user/repos?affiliation=owner,organization_member&per_page=100") {
		t.Error("requests made for scopes the token lacks")
	}
}

func TestOwnerWithoutAdminOrgScope(t *testing.T) {
	gh := world()
	gh.scopes = "read:org, read:user, repo"
	rec := inventory(t, gh, nil)
	if s := statusOf(t, rec, "github:acme-corp"); s.State != finding.StateNoScope || !strings.Contains(s.Detail, "gh auth refresh -h github.com -s admin:org") {
		t.Errorf("owner without admin:org: %+v", s)
	}
	if gh.called("/orgs/acme-corp") {
		t.Error("organization settings requested without admin:org")
	}
}

// A fine-grained token sends no scopes header: every check is tried and refusals become statuses.
func TestUnknownScopesReadRefusals(t *testing.T) {
	gh := world()
	gh.scopes = "-"
	gh.replies["/user"] = `{"login":"octo-tester"}`
	gh.errs["/user/memberships/orgs?state=active&per_page=100"] = httpErr("Resource not accessible by personal access token", 403)
	gh.errs["/orgs/acme-corp/actions/permissions"] = httpErr("Resource not accessible by personal access token", 403)
	rec := inventory(t, gh, nil)
	if got := statesFor(rec, "github:octo-tester"); !strings.Contains(got, "noscope: gh api /user/memberships/orgs?state=active&per_page=100 returned HTTP 403") {
		t.Errorf("refused organizations: %s", got)
	}
	gh = world()
	gh.scopes = "-"
	gh.errs["/orgs/acme-corp/actions/permissions"] = httpErr("Resource not accessible by personal access token", 403)
	rec = inventory(t, gh, nil)
	if s := statusOf(t, rec, "github:acme-corp"); s.State != finding.StateError || !strings.Contains(s.Detail, "Actions permissions not read") {
		t.Errorf("partly read organization: %+v", s)
	}
	if _, ok := findingFor(rec, string(orgNo2FARequirement)); !ok {
		t.Error("findings read before a refusal must still be reported")
	}
}

func findingFor(rec *httpxtest.Recorder, id string) (finding.Finding, bool) {
	for _, f := range rec.Findings {
		if f.Resource.ID == id {
			return f, true
		}
	}
	return finding.Finding{}, false
}

func TestRateLimitLowStopsBeforeStarting(t *testing.T) {
	gh := world()
	gh.remain = rateReserve
	rec := inventory(t, gh, nil)
	if len(gh.calls) != 1 || len(rec.Findings) != 0 {
		t.Fatalf("calls %v findings %d", gh.calls, len(rec.Findings))
	}
	if s := statusOf(t, rec, "github"); s.State != finding.StateError || !strings.Contains(s.Detail, "rate limit low: 300 of 5000") {
		t.Errorf("status: %+v", s)
	}
}

// The budget runs out partway through the repositories: the rest are skipped, not half-read.
func TestRateLimitBudgetSkipsRemainingRepositories(t *testing.T) {
	gh := world()
	// 15 requests before the repositories (user, memberships, 12 organization reads, the
	// repository list), then one: enough to start a repository, never to finish one.
	gh.remain = rateReserve + 16
	rec := inventory(t, gh, nil)
	got := statesFor(rec, "github:octo-tester")
	if !strings.Contains(got, "error: 0 repositories you administer inspected") || !strings.Contains(got, "5 not inspected because the GitHub API rate limit ran low") {
		t.Errorf("status: %s", got)
	}
	for _, f := range rec.Findings {
		if f.Resource.Type == "github_repo" {
			t.Errorf("a half-read repository was reported: %s", f.Title)
		}
	}
	// Each unread repository is declared, with its owner's rolled-up findings, so the findings it
	// reported last time are not taken as resolved.
	got2 := strings.Join(skippedScopes(rec), "\n")
	for _, want := range []string{"repo:acme-corp/api (the GitHub API rate limit ran low)", "repo:octo-tester/site (the GitHub API rate limit ran low)",
		"repo:octo-tester (the GitHub API rate limit ran low for octo-tester/forked)"} {
		if !strings.Contains(got2, want) {
			t.Errorf("skipped scopes lack %q:\n%s", want, got2)
		}
	}
	for _, s := range statusesOf(rec, "github:octo-tester") {
		if s.State != finding.StateOK && s.Scope != "repo:octo-tester" {
			t.Errorf("the repositories summary must be scoped to them, not the whole account: %+v", s)
		}
	}
}

func TestRateLimitResponseMidRun(t *testing.T) {
	gh := world()
	gh.errs["/repos/octo-tester/site/hooks?per_page=100"] = httpErr("API rate limit exceeded for user ID 1.", 403)
	rec := inventory(t, gh, nil)
	if got := statesFor(rec, "github:octo-tester"); !strings.Contains(got, "rate limit ran low") {
		t.Errorf("status: %s", got)
	}
}

func TestMaxReposCap(t *testing.T) {
	gh := world()
	rec := inventory(t, gh, map[string]any{"max_repos": float64(1)})
	if got := statesFor(rec, "github:octo-tester"); !strings.Contains(got, "1 repositories you administer inspected") || !strings.Contains(got, "4 more not inspected: raise max_repos") {
		t.Errorf("status: %s", got)
	}
	if gh.called("/repos/tidy-free/web") {
		t.Error("inspected past max_repos")
	}
	if got := strings.Join(skippedScopes(rec), "\n"); !strings.Contains(got, "repo:tidy-free/web (beyond max_repos in the github config)") {
		t.Errorf("repositories past max_repos not declared skipped:\n%s", got)
	}
}

func TestRepositoriesNotListedLeaveEveryRepositoryUninspected(t *testing.T) {
	gh := world()
	gh.errs["/user/repos?affiliation=owner,organization_member&per_page=100"] = httpErr("Server Error", 500)
	rec := inventory(t, gh, nil)
	failed := 0
	for _, s := range statusesOf(rec, "github:octo-tester") {
		if s.State == finding.StateOK {
			continue
		}
		failed++
		if s.Scope != "repo:*" {
			t.Errorf("a failed repository listing must leave every repository scope uninspected: %+v", s)
		}
	}
	if failed != 1 {
		t.Errorf("want one status for the failed listing, got %d", failed)
	}
}

func TestBadConfig(t *testing.T) {
	for _, cfg := range []map[string]any{{"max_repos": 0.0}, {"max_repos": 2.5}, {"max_repos": "10"}, {"branch_protection": "yes"}} {
		gh := world()
		rec := inventory(t, gh, cfg)
		if s := statusOf(t, rec, "github"); s.State != finding.StateError || len(gh.calls) != 0 {
			t.Errorf("%v: %+v calls %v", cfg, s, gh.calls)
		}
	}
}

func TestGhMissingOrSignedOut(t *testing.T) {
	cases := map[finding.State]error{
		finding.StateUnsupported: fmt.Errorf("exec: %w", exec.ErrNotFound),
		finding.StateSignedOut:   &cli.Error{Cmd: "gh api", Stderr: "To get started with GitHub CLI, please run:  gh auth login\n", Err: errors.New("exit status 4")},
		finding.StateReauth:      httpErr("Bad credentials", 401),
	}
	for want, err := range cases {
		gh := world()
		gh.errs["/rate_limit"] = err
		rec := inventory(t, gh, nil)
		if s := statusOf(t, rec, "github"); s.State != want || !strings.Contains(s.Detail, "gh") {
			t.Errorf("%s: %+v", want, s)
		}
	}
}

func TestSeverityTableCoversEveryCheck(t *testing.T) {
	checks := []check{accountNo2FA, accountNo2FAOwner, orgNo2FARequirement, orgMembersNo2FA, orgCollaboratorsNo2FA,
		orgDefaultPermission, orgPublicRepoCreation, orgWorkflowWrite, orgActionsApprovePRs, orgAllActions,
		orgNoPrivateScanning, orgNoPublicScanning, repoInsecureHook, repoInsecureHookInactive, repoWriteDeployKey,
		repoWorkflowWrite, repoNoSecretScanning, repoNoPushProtection, repoForkNoSecretScanning, repoForkWorkflowWrite,
		repoPrivateNoScanning, repoNoDependabotUpdates, repoUnprotectedDefault}
	if len(checks) != len(severities) {
		t.Fatalf("%d checks, %d severities", len(checks), len(severities))
	}
	for _, c := range checks {
		if severities[c] == "" {
			t.Errorf("no severity for %s", c)
		}
	}
	for c := range rolledUp {
		if severities[c].Rank() > finding.SevMedium.Rank() {
			t.Errorf("%s is rolled up but above medium: it belongs in each repository's finding", c)
		}
	}
}

func TestReadOnlyGuard(t *testing.T) {
	for _, ok := range []string{
		"api --method GET --include /rate_limit",
		"api --method GET /user",
		"api --method GET --paginate /user/memberships/orgs?state=active&per_page=100",
		"api --method GET /orgs/acme-corp",
		"api --method GET --paginate /orgs/acme-corp/members?filter=2fa_disabled&per_page=100",
		"api --method GET /orgs/acme-corp/code-security/configurations/defaults",
		"api --method GET /repos/acme-corp/api.v2",
		"api --method GET --paginate /repos/a/b/hooks?per_page=100",
		"api --method GET /repos/a/b/branches/release%2F1.0/protection",
	} {
		if err := readOnly.Check(strings.Fields(ok)); err != nil {
			t.Errorf("refused %q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"auth token",
		"api /user",
		"api --method POST /user",
		"api --method get /user",
		"api -X GET /user",
		"api --method GET /user -f name=x",
		"api --method GET -F name=x /user",
		"api --method GET --input body.json /user",
		"api --method GET --include --paginate /user",
		"api --method GET /user/repos",
		"api --method GET /user/repos?affiliation=owner,organization_member&per_page=100&x=1",
		"api --method GET /orgs/acme-corp/members",
		"api --method GET /repos/a/b/collaborators",
		"api --method GET /repos/a/../user",
		"api --method GET /repos/a/%2e%2e/keys?per_page=100",
		"api --method GET /repos/a/b/branches/%2E%2E/protection",
		"api --method GET /orgs/a/actions/secrets",
		"api --method GET graphql",
		"repo delete a/b --yes",
	} {
		if err := readOnly.Check(strings.Fields(bad)); !errors.Is(err, cli.ErrRefused) {
			t.Errorf("allowed %q", bad)
		}
	}
}

func TestInsecureHookKeepsOnlySchemeAndHost(t *testing.T) {
	h := hook{ID: 3, Active: true}
	h.Config.URL = "http://user:pass@example.com/path?key=" + hookToken
	h.Config.InsecureSSL = json.RawMessage(`"1"`)
	is, ok := insecureHook(h, "https://github.com/a/b/settings")
	if !ok || is.Severity != finding.SevHigh || is.Detail != "active webhook 3 to http://example.com delivers over plain HTTP and skips SSL certificate verification" {
		t.Fatalf("%v %+v", ok, is)
	}
	if strings.Contains(is.Detail+is.fix+is.url, "pass") || strings.Contains(is.Detail, hookToken) {
		t.Fatal("hook credentials leaked")
	}
	h.Config.URL = "https://example.com/"
	h.Config.InsecureSSL = json.RawMessage(`0`)
	if _, ok := insecureHook(h, ""); ok {
		t.Fatal("a verified https hook is fine")
	}
}
