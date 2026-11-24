package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

type repo struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	Visibility    string `json:"visibility"` // public, private, internal
	Archived      bool   `json:"archived"`
	Fork          bool   `json:"fork"`
	DefaultBranch string `json:"default_branch"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
	Permissions struct {
		Admin bool `json:"admin"`
	} `json:"permissions"`
	// SecurityAndAnalysis is only in GET /repos/{owner}/{repo}, for admins, and only lists the
	// features the repository's plan offers: nil for a private repository without them.
	SecurityAndAnalysis *struct {
		SecretScanning            *feature `json:"secret_scanning"`
		PushProtection            *feature `json:"secret_scanning_push_protection"`
		DependabotSecurityUpdates *feature `json:"dependabot_security_updates"`
	} `json:"security_and_analysis"`
}

type feature struct {
	Status string `json:"status"` // enabled, disabled
}

func (f *feature) disabled() bool { return f != nil && f.Status == "disabled" }

type hook struct {
	ID     int64 `json:"id"`
	Active bool  `json:"active"`
	Config struct {
		URL         string          `json:"url"`
		InsecureSSL json.RawMessage `json:"insecure_ssl"` // "0" or "1", string or number
	} `json:"config"`
}

type deployKey struct {
	ID        int64      `json:"id"`
	Title     string     `json:"title"`
	ReadOnly  bool       `json:"read_only"`
	CreatedAt *time.Time `json:"created_at"`
	LastUsed  *time.Time `json:"last_used"`
}

// repoResult is what one repository's inspection found.
type repoResult struct {
	issues  []issue
	err     error // a request that failed; the repository is reported as partly unreadable
	skipped bool  // stopped by the rate limit before it was fully read
}

// repos inspects the repositories the user administers, up to max_repos, concurrency at a time.
// Archived ones are read-only on GitHub and are skipped.
func (r *run) repos(ctx context.Context, login string) {
	acct := account(login)
	if !r.scopes.has("repo") {
		r.scopedStatus(acct, allRepos, finding.StateNoScope, "repositories not inspected: gh's token lacks repo; run: %s", refresh("repo"))
		return
	}
	all, err := list[repo](ctx, r, "/user/repos?affiliation=owner,organization_member&per_page=100")
	if err != nil {
		r.scopedStatus(acct, allRepos, stateOrNoScope(err), "%s", describe(err, "repositories not listed"))
		return
	}
	var admin []repo
	archived := 0
	for _, rp := range all {
		switch {
		case !rp.Permissions.Admin:
		case rp.Archived:
			archived++
		default:
			admin = append(admin, rp)
		}
	}
	sort.Slice(admin, func(i, j int) bool { return admin[i].FullName < admin[j].FullName })
	over := 0
	if len(admin) > r.cfg.maxRepos {
		over = len(admin) - r.cfg.maxRepos
		r.skipRepos(admin[r.cfg.maxRepos:], "beyond max_repos in the github config")
		admin = admin[:r.cfg.maxRepos]
	}

	results := make([]repoResult, len(admin))
	var stop atomic.Bool
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if stop.Load() {
					results[i] = repoResult{skipped: true}
					continue
				}
				results[i] = r.inspect(ctx, admin[i])
				if results[i].skipped {
					stop.Store(true)
				}
			}
		}()
	}
	for i := range admin {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	var limited, unreadable []repo
	for i, res := range results {
		switch {
		case res.skipped:
			limited = append(limited, admin[i])
		case res.err != nil:
			unreadable = append(unreadable, admin[i])
		}
	}
	r.skipRepos(limited, "the GitHub API rate limit ran low")
	r.skipRepos(unreadable, "partly unreadable")
	r.reportRepos(admin, results)
	r.reposStatus(acct, login, len(admin), archived, over, results)
}

// Repository findings carry these scopes, so a run that leaves repositories unread says which:
// "repo:<owner>/<name>" for one repository's own finding, "repo:<owner>" for an owner's rolled-up
// findings, which depend on every repository of that owner.
const allRepos = "repo:*"

func repoScope(fullName string) string { return "repo:" + fullName }
func ownerScope(owner string) string   { return "repo:" + owner }

// maxSkippedRepos is how many repositories are declared one by one; past it every repository
// scope is declared skipped at once, which keeps run_end small.
const maxSkippedRepos = 50

// skipRepos declares repositories the run did not fully read, and their owners' rolled-up
// findings with them.
func (r *run) skipRepos(repos []repo, reason string) {
	if len(repos) > maxSkippedRepos {
		r.emit.Scope(allRepos, false, fmt.Sprintf("%d repositories: %s", len(repos), reason))
		return
	}
	for _, rp := range repos {
		r.emit.Scope(repoScope(rp.FullName), false, reason)
		r.emit.Scope(ownerScope(rp.Owner.Login), false, reason+" for "+rp.FullName)
	}
}

// reposStatus sums up the repositories of the signed-in user. It is scoped to the user's
// repositories: the account itself was inspected, and each repository left unread is declared on
// its own by skipRepos.
func (r *run) reposStatus(acct, login string, inspected, archived, over int, results []repoResult) {
	withIssues, skipped, unreadable := 0, 0, 0
	var firstErr error
	for _, res := range results {
		switch {
		case res.skipped:
			skipped++
		case res.err != nil:
			unreadable++
			if firstErr == nil {
				firstErr = res.err
			}
		}
		if !res.skipped && len(res.issues) > 0 {
			withIssues++
		}
	}
	parts := []string{fmt.Sprintf("%d repositories you administer inspected, %d with issues", inspected-skipped, withIssues)}
	state := finding.StateOK
	if archived > 0 {
		parts = append(parts, fmt.Sprintf("%d archived skipped", archived))
	}
	if over > 0 {
		parts = append(parts, fmt.Sprintf("%d more not inspected: raise max_repos in the github config", over))
	}
	if skipped > 0 {
		state = finding.StateError
		parts = append(parts, fmt.Sprintf("%d not inspected because the GitHub API rate limit ran low: run again after the hourly reset", skipped))
	}
	if unreadable > 0 {
		state = finding.StateError
		parts = append(parts, fmt.Sprintf("%d partly unreadable, first: %v", unreadable, firstErr))
	}
	r.scopedStatus(acct, ownerScope(login), state, "%s", strings.Join(parts, "; "))
}

// inspect reads one repository: its code security features, webhooks, deploy keys and, when
// public, its default workflow permissions and (opt-in) default branch protection.
func (r *run) inspect(ctx context.Context, base repo) repoResult {
	var res repoResult
	fail := func(err error) repoResult {
		if rateLimited(err) {
			return repoResult{skipped: true}
		}
		res.err = err
		return res
	}
	var rp repo
	if err := r.get(ctx, "/repos/"+base.FullName, &rp); err != nil {
		return fail(err)
	}
	settings := web + "/" + rp.FullName + "/settings"
	if sa := rp.SecurityAndAnalysis; sa != nil {
		const where = "Under Settings, Advanced Security (formerly Code security), "
		url := settings + "/security_analysis"
		switch {
		case rp.Fork && (sa.SecretScanning.disabled() || sa.PushProtection.disabled()):
			res.issues = append(res.issues, newIssue(repoForkNoSecretScanning, "secret scanning or push protection is off in a fork",
				where+"enable secret scanning and push protection.", url))
		case rp.Visibility != "public" && (sa.SecretScanning.disabled() || sa.PushProtection.disabled()):
			res.issues = append(res.issues, newIssue(repoPrivateNoScanning, "secret scanning or push protection is off in a private repository",
				where+"enable secret scanning and push protection.", url))
		case sa.SecretScanning.disabled():
			res.issues = append(res.issues, newIssue(repoNoSecretScanning, "secret scanning is off",
				where+"enable secret scanning and push protection.", url))
		case sa.PushProtection.disabled():
			res.issues = append(res.issues, newIssue(repoNoPushProtection, "push protection is off",
				where+"enable push protection, so pushes that contain a secret are blocked.", url))
		}
		if sa.DependabotSecurityUpdates.disabled() {
			res.issues = append(res.issues, newIssue(repoNoDependabotUpdates, "Dependabot security updates are off",
				where+"enable Dependabot security updates.", url))
		}
	}

	hooks, err := list[hook](ctx, r, "/repos/"+rp.FullName+"/hooks?per_page=100")
	if err != nil {
		return fail(err)
	}
	for _, h := range hooks {
		if is, ok := insecureHook(h, settings); ok {
			res.issues = append(res.issues, is)
		}
	}

	keys, err := list[deployKey](ctx, r, "/repos/"+rp.FullName+"/keys?per_page=100")
	if err != nil {
		return fail(err)
	}
	for _, k := range keys {
		if k.ReadOnly {
			continue
		}
		used := "never used"
		if k.LastUsed != nil {
			used = "last used " + k.LastUsed.Format("2006-01-02")
		}
		res.issues = append(res.issues, newIssue(repoWriteDeployKey,
			fmt.Sprintf("deploy key %q (id %d) can push, %s", k.Title, k.ID, used),
			fmt.Sprintf("Delete deploy key %q, or add it again as read-only, unless something must push with it.", k.Title), settings+"/keys"))
	}

	if rp.Visibility != "public" {
		return res
	}
	// A workflow token's default only matters where Actions run; forks start with them off.
	var ap struct {
		Enabled bool `json:"enabled"`
	}
	if err := r.get(ctx, "/repos/"+rp.FullName+"/actions/permissions", &ap); err != nil {
		return fail(err)
	}
	if ap.Enabled {
		var wp workflowPermissions
		if err := r.get(ctx, "/repos/"+rp.FullName+"/actions/permissions/workflow", &wp); err != nil {
			return fail(err)
		}
		c := repoWorkflowWrite
		if rp.Fork {
			c = repoForkWorkflowWrite
		}
		if wp.Default == "write" {
			res.issues = append(res.issues, newIssue(c, "workflows get a read and write GITHUB_TOKEN by default",
				"Under Settings, Actions, General, Workflow permissions, choose read-only; workflows that need more ask for it with `permissions:`.", settings+"/actions"))
		}
	}
	if r.cfg.branchProtection && rp.DefaultBranch != "" {
		protected, err := r.protected(ctx, rp)
		if err != nil {
			return fail(err)
		}
		if !protected {
			res.issues = append(res.issues, newIssue(repoUnprotectedDefault, "default branch "+rp.DefaultBranch+" has no branch protection or ruleset",
				"Add a branch ruleset for the default branch that blocks force pushes and deletion and requires pull requests.", settings+"/rules"))
		}
	}
	return res
}

// protected reports whether the default branch has classic protection or an active ruleset rule.
// GitHub answers 404 "Branch not protected" when classic protection is absent.
func (r *run) protected(ctx context.Context, rp repo) (bool, error) {
	b := url.PathEscape(rp.DefaultBranch)
	var protection json.RawMessage
	err := r.get(ctx, "/repos/"+rp.FullName+"/branches/"+b+"/protection", &protection)
	if err == nil {
		return true, nil
	}
	if !notFound(err) {
		return false, err
	}
	rules, err := list[json.RawMessage](ctx, r, "/repos/"+rp.FullName+"/rules/branches/"+b+"?per_page=100")
	if err != nil {
		return false, err
	}
	return len(rules) > 0, nil
}

// insecureHook reports a webhook that delivers over plain HTTP or without checking the
// certificate. Only the scheme and host are kept: a hook URL can carry a token in its path or
// query.
func insecureHook(h hook, settings string) (issue, bool) {
	u, err := url.Parse(h.Config.URL)
	if err != nil {
		return issue{}, false
	}
	var why []string
	if u.Scheme == "http" {
		why = append(why, "delivers over plain HTTP")
	}
	if strings.Trim(string(h.Config.InsecureSSL), `"`) == "1" {
		why = append(why, "skips SSL certificate verification")
	}
	if len(why) == 0 {
		return issue{}, false
	}
	c, state := repoInsecureHook, "active"
	if !h.Active {
		c, state = repoInsecureHookInactive, "inactive"
	}
	return newIssue(c, fmt.Sprintf("%s webhook %d to %s://%s %s", state, h.ID, u.Scheme, u.Host, strings.Join(why, " and ")),
		fmt.Sprintf("Edit webhook %d: use an https:// URL and turn SSL verification on, or delete it if nothing uses it.", h.ID),
		settings+"/hooks/"+strconv.FormatInt(h.ID, 10)), true
}

// rolledUp are the checks that would otherwise flag most repositories of an owner and that one
// decision fixes (buy Secret Protection, turn a feature on everywhere, prune forks): they become
// one finding per owner listing the repositories, instead of one line in every repository's
// finding.
var rolledUp = map[check]struct{ title, fix, url string }{
	repoForkNoSecretScanning: {
		title: "Secret scanning or push protection is off in %d forked %s of %s",
		fix:   "Enable secret scanning and push protection in each fork you still push to (Settings, Advanced Security), or delete forks you no longer use.",
		url:   "https://docs.github.com/en/code-security/how-tos/secure-your-secrets/detect-secret-leaks/enable-secret-scanning",
	},
	repoForkWorkflowWrite: {
		title: "Workflows get a read and write GITHUB_TOKEN by default in %d forked %s of %s",
		fix:   "In each fork whose workflows you run, choose read-only under Settings, Actions, General, Workflow permissions; delete forks you no longer use.",
		url:   "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository",
	},
	repoPrivateNoScanning: {
		title: "Secret scanning or push protection is off in %d private %s of %s",
		fix:   "Apply a code security configuration with secret scanning and push protection to these repositories. On private repositories they need GitHub Secret Protection, a paid add-on for Team and Enterprise plans.",
		url:   "https://docs.github.com/en/code-security/how-tos/secure-your-secrets/detect-secret-leaks/enable-secret-scanning",
	},
	repoNoDependabotUpdates: {
		title: "Dependabot security updates are off in %d %s of %s",
		fix:   "Enable Dependabot security updates in each repository (Settings, Advanced Security), or for an organization in a code security configuration applied to all its repositories.",
		url:   "https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/configure-security-updates",
	},
	repoUnprotectedDefault: {
		title: "The default branch has no protection in %d public %s of %s",
		fix:   "Add a branch ruleset for the default branch (block force pushes and deletion, require pull requests); an organization can apply one ruleset to all its repositories.",
		url:   "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository",
	},
}

// maxListed caps the repositories named in one rolled-up finding's evidence.
const maxListed = 200

// reportRepos emits one finding per repository with its issues, worst first in the title, and
// one finding per owner for each rolled-up check.
func (r *run) reportRepos(repos []repo, results []repoResult) {
	type key struct {
		owner string
		check check
	}
	rolled := map[key][]string{}
	for i, res := range results {
		if res.skipped {
			continue
		}
		rp := repos[i]
		var own []issue
		for _, is := range res.issues {
			if _, ok := rolledUp[is.Check]; ok {
				k := key{rp.Owner.Login, is.Check}
				rolled[k] = append(rolled[k], rp.FullName)
				continue
			}
			own = append(own, is)
		}
		if len(own) > 0 {
			r.emitRepo(rp, own)
		}
	}
	keys := make([]key, 0, len(rolled))
	for k := range rolled {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].owner != keys[j].owner {
			return keys[i].owner < keys[j].owner
		}
		return keys[i].check < keys[j].check
	})
	for _, k := range keys {
		names := rolled[k]
		listed := names[:min(len(names), maxListed)]
		ru := rolledUp[k.check]
		r.emit.Finding(finding.Finding{
			Account:     account(k.owner),
			Scope:       ownerScope(k.owner),
			Resource:    finding.Resource{Type: "github_repo_setting", ID: string(k.check), Name: k.owner},
			Kind:        finding.KindSetting,
			Severity:    severities[k.check],
			Title:       fmt.Sprintf(ru.title, len(names), plural(len(names), "repository", "repositories"), k.owner),
			Evidence:    map[string]any{"check": string(k.check), "count": len(names), "repositories": listed},
			Remediation: finding.Remediation{Summary: ru.fix, URL: ru.url},
		})
	}
}

func (r *run) emitRepo(rp repo, issues []issue) {
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].Severity.Rank() > issues[j].Severity.Rank() })
	details := make([]string, len(issues))
	fixes := make([]string, len(issues))
	for i, is := range issues {
		details[i] = is.Detail
		fixes[i] = is.fix
	}
	r.emit.Finding(finding.Finding{
		Account:  account(rp.Owner.Login),
		Scope:    repoScope(rp.FullName),
		Resource: finding.Resource{Type: "github_repo", ID: strconv.FormatInt(rp.ID, 10), Name: rp.FullName},
		Kind:     finding.KindSetting,
		Severity: issues[0].Severity,
		Title:    rp.FullName + ": " + strings.Join(details, "; "),
		Evidence: map[string]any{"repository": rp.FullName, "visibility": rp.Visibility, "issues": issues},
		Remediation: finding.Remediation{
			Summary: strings.Join(fixes, " "),
			URL:     issues[0].url,
		},
	})
}
