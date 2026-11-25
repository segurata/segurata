// Package gcp inventories Google Cloud through the installed gcloud CLI, read-only: API keys,
// service account keys and broad roles, billing budgets, and Google credentials on this machine.
// See docs/gcp-connector.md.
package gcp

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const connectorName = "gcp"

// parallel is how many projects are inspected at once; Cloud Billing answers 429 above a few.
const parallel = 4

func init() { connector.Register(New()) }

// Connector is the built-in gcp connector. Its fields are injectable for tests.
type Connector struct {
	runner  cli.Runner // nil: run the real gcloud
	getenv  func(string) string
	home    string
	now     func() time.Time
	backoff time.Duration
	timeout time.Duration
}

func New() *Connector {
	home, _ := os.UserHomeDir()
	return &Connector{getenv: os.Getenv, home: home, now: time.Now, backoff: 3 * time.Second, timeout: 90 * time.Second}
}

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     connectorName,
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "Google Cloud: API keys, service account keys and roles, billing budgets, local credentials",
		Needs:    []string{"cli:gcloud"},
		Theme:    finding.ThemeCloud,
	}
}

type settings struct {
	accounts       []string
	projects       []string
	skipProjects   []string
	billingProject string // passed as --billing-project to budgets list when set
	gcloudPath     string
}

func parseSettings(m map[string]any) (settings, error) {
	var s settings
	var err error
	if s.accounts, err = stringList(m, "accounts"); err != nil {
		return s, err
	}
	if s.projects, err = stringList(m, "projects"); err != nil {
		return s, err
	}
	if s.skipProjects, err = stringList(m, "skip_projects"); err != nil {
		return s, err
	}
	s.billingProject, _ = m["billing_project"].(string)
	s.gcloudPath, _ = m["gcloud_path"].(string)
	return s, nil
}

func stringList(m map[string]any, key string) ([]string, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("gcp config: %q must be a list of strings", key)
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		if !ok {
			return nil, fmt.Errorf("gcp config: %q must be a list of strings", key)
		}
		out = append(out, s)
	}
	return out, nil
}

// target is one project and the accounts that list it, in config or `gcloud auth list` order.
// Each project is inspected once: a check denied to the first account is retried with the next.
type target struct {
	accounts        []string
	project, number string
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	cfg, err := parseSettings(req.Config)
	if err != nil {
		return err
	}
	for _, f := range localFindings(c.getenv, c.home) {
		emit.Finding(f)
	}
	g, err := c.gcloud(cfg)
	if err != nil {
		emit.Status(finding.Status{Account: localAccount, State: finding.StateUnsupported, Detail: err.Error()})
		return nil
	}
	// Service accounts are credentials, not identities to inventory: no finding is ever scoped to
	// one, so declaring them skipped would only mark every run partial. They are left out silently
	// (list one in connectors.gcp.config.accounts to inventory with it). People's accounts the
	// config leaves out are declared skipped, so findings an earlier run made for them are not
	// taken as resolved.
	accounts, unwatched, err := c.accounts(ctx, g, cfg)
	for _, a := range unwatched {
		emit.Scope(a, false, "not in connectors.gcp.config.accounts")
	}
	if err != nil {
		_, why := classify(err)
		emit.Status(finding.Status{Account: localAccount, State: finding.StateError, Detail: "gcloud auth list: " + why})
		return nil
	}
	if len(accounts) == 0 {
		emit.Status(finding.Status{Account: localAccount, State: finding.StateMissingCredentials, Detail: "gcloud has no credentialed accounts"})
		return nil
	}

	targets, usable := c.plan(ctx, g, accounts, cfg, emit)
	bill := &billing{g: g, billingProject: cfg.billingProject, accounts: map[string]*billingState{}, ids: map[string]string{}}
	for _, t := range targets {
		if t.number != "" {
			bill.ids[t.number] = t.project
		}
	}
	for _, a := range usable {
		bill.discover(ctx, a, emit)
	}

	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c.inspect(ctx, g, t, bill, emit)
		}(t)
	}
	wg.Wait()
	bill.judge(ctx, emit)
	return nil
}

// gcloud is the guarded gcloud the connector runs: the injected runner, or the CLI found from
// gcloud_path, PATH or the SDK's install folders.
func (c *Connector) gcloud(cfg settings) (*gcloud, error) {
	r := c.runner
	if r == nil {
		path, err := cli.FindGcloud(cfg.gcloudPath, c.home, connectorName)
		if err != nil {
			return nil, err
		}
		r = cli.Exec{Path: path, Timeout: c.timeout, Env: []string{"CLOUDSDK_CORE_DISABLE_PROMPTS=1"}}
	}
	return &gcloud{run: r, backoff: c.backoff}, nil
}

// serviceAccountSuffix ends the email of every user-managed service account. gcloud lists a service
// account it activated (`gcloud auth activate-service-account`) next to people: it is a credential
// the gcp checks already report, not an identity to inventory projects with.
const serviceAccountSuffix = ".iam.gserviceaccount.com"

// accounts are the configured accounts, or every credentialed account gcloud lists except
// service accounts. With configured accounts, unwatched are the people's accounts gcloud lists
// that the config leaves out (none when gcloud cannot list them: the configured ones still run).
func (c *Connector) accounts(ctx context.Context, g *gcloud, cfg settings) (accounts, unwatched []string, err error) {
	var listed []struct {
		Account string `json:"account"`
	}
	err = g.json(ctx, &listed, "auth", "list")
	if len(cfg.accounts) > 0 {
		for _, a := range listed {
			if !strings.HasSuffix(a.Account, serviceAccountSuffix) && !slices.ContainsFunc(cfg.accounts, func(w string) bool { return strings.EqualFold(w, a.Account) }) {
				unwatched = append(unwatched, a.Account)
			}
		}
		return cfg.accounts, unwatched, nil
	}
	if err != nil {
		return nil, nil, err
	}
	for _, a := range listed {
		if !strings.HasSuffix(a.Account, serviceAccountSuffix) {
			accounts = append(accounts, a.Account)
		}
	}
	return accounts, nil, nil
}

// projectsFinding records, as an info finding, the id and number of every project an account
// sees, so attribution knows the owner's projects (an OAuth client id names the number only).
func projectsFinding(account string, projects []listedProject) finding.Finding {
	list := make([]any, 0, len(projects))
	for _, p := range projects {
		list = append(list, map[string]any{"id": p.ProjectID, "number": p.ProjectNumber})
	}
	return finding.Finding{Account: account, Resource: finding.Resource{Type: attribution.GCPProjectsType, ID: account, Name: account},
		Kind: finding.KindSetting, Severity: finding.SevInfo, Title: fmt.Sprintf("%s sees %d projects", account, len(projects)),
		Evidence: map[string]any{"projects": list}}
}

// listedProject is a project as `gcloud projects list` reports it.
type listedProject struct {
	ProjectID      string `json:"projectId"`
	ProjectNumber  string `json:"projectNumber"`
	LifecycleState string `json:"lifecycleState"`
}

// plan lists each account's projects and gives every project the accounts that see it, first
// lister first. Configured projects nobody lists go to the accounts that could list projects.
// Skipped projects and projects pending deletion are left out.
func (c *Connector) plan(ctx context.Context, g *gcloud, accounts []string, cfg settings, emit connector.Emitter) ([]target, []string) {
	var targets []target
	var usable []string
	index := map[string]int{}
	want := map[string]bool{}
	for _, p := range cfg.projects {
		want[p] = true
	}
	skip, declared := map[string]bool{}, map[string]bool{}
	for _, p := range cfg.skipProjects {
		skip[p] = true
	}
	for _, a := range accounts {
		var projects []listedProject
		if err := g.json(ctx, &projects, "projects", "list", "--account="+a); err != nil {
			state, why := classify(err)
			emit.Status(finding.Status{Account: a, State: state, Detail: "projects list: " + why})
			continue
		}
		usable = append(usable, a)
		emit.Status(finding.Status{Account: a, State: finding.StateOK, Detail: fmt.Sprintf("%d project(s) visible", len(projects))})
		emit.Finding(projectsFinding(a, projects))
		for _, p := range projects {
			if skip[p.ProjectID] && !declared[p.ProjectID] {
				declared[p.ProjectID] = true
				emit.Scope(p.ProjectID, false, "in connectors.gcp.config.skip_projects")
			}
			if skip[p.ProjectID] || (len(want) > 0 && !want[p.ProjectID]) ||
				(p.LifecycleState != "" && p.LifecycleState != "ACTIVE") {
				continue
			}
			if i, ok := index[p.ProjectID]; ok {
				targets[i].accounts = append(targets[i].accounts, a)
				continue
			}
			index[p.ProjectID] = len(targets)
			targets = append(targets, target{accounts: []string{a}, project: p.ProjectID, number: p.ProjectNumber})
		}
	}
	for _, p := range cfg.projects {
		if _, ok := index[p]; !ok && !skip[p] && len(usable) > 0 {
			index[p] = len(targets)
			targets = append(targets, target{accounts: usable, project: p})
		}
	}
	return targets, usable
}

// inspect runs the per-project checks and reports the ones that failed in one status line, on
// the project's first account. A check denied to one account is retried with the next account
// that lists the project, so a project another account can read is not reported as denied.
func (c *Connector) inspect(ctx context.Context, g *gcloud, t target, bill *billing, emit connector.Emitter) {
	proj := "--project=" + t.project
	var failed, denied []string
	worst := finding.StateOK
	fail := func(check string, err error) {
		state, why := classify(err)
		if state == finding.StateReauth || worst == finding.StateOK {
			worst = state
		}
		if strings.HasPrefix(why, deniedPrefix) {
			denied = append(denied, check) // the reason is the same for each: list the checks only
			return
		}
		failed = append(failed, check+": "+why)
	}
	// run calls fn with each account in turn until one is not denied, and returns that account.
	// Findings stay on the project's first account whichever account read them, so their ids and
	// the coverage of that account's project scope do not depend on who answered.
	run := func(check string, fn func(acct string) error) (string, bool) {
		var err error
		for _, a := range t.accounts {
			if err = fn(a); err == nil {
				return a, true
			}
			if _, why := classify(err); !strings.HasPrefix(why, deniedPrefix) {
				break
			}
		}
		fail(check, err)
		return "", false
	}
	emitAll := func(fs []finding.Finding) {
		for _, f := range fs {
			f.Scope = t.project
			emit.Finding(f)
		}
	}

	var found []finding.Finding // this project's credential findings, counted as spend risks
	var policy iamPolicy
	if _, ok := run("iam policy", func(a string) error {
		return g.json(ctx, &policy, "projects", "get-iam-policy", t.project, "--account="+a)
	}); ok {
		emitAll(iamFindings(t.accounts[0], t.project, policy))
	}

	var sas []serviceAccount
	run("service accounts", func(a string) error {
		return g.json(ctx, &sas, "iam", "service-accounts", "list", proj, "--account="+a)
	})
	for _, sa := range sas {
		var keys []saKey
		if _, ok := run("keys of "+sa.Email, func(a string) error {
			return g.json(ctx, &keys, "iam", "service-accounts", "keys", "list", "--iam-account="+sa.Email, "--managed-by=user", proj, "--account="+a)
		}); ok {
			fs := saKeyFindings(t.accounts[0], t.project, sa, keys, c.now())
			found = append(found, fs...)
			emitAll(fs)
		}
	}

	var keys []apiKey
	if _, ok := run("api keys", func(a string) error {
		return g.json(ctx, &keys, "services", "api-keys", "list", proj, "--account="+a)
	}); ok {
		fs := apiKeyFindings(t.accounts[0], t.project, keys)
		found = append(found, fs...)
		emitAll(fs)
	}

	var info billingInfo
	if a, ok := run("billing", func(a string) error {
		return g.json(ctx, &info, "billing", "projects", "describe", t.project, "--account="+a)
	}); ok && info.BillingEnabled && info.BillingAccountName != "" {
		bill.link(a, linkedProject{id: t.project, number: t.number, risks: projectRisks(t.project, found)},
			strings.TrimPrefix(info.BillingAccountName, "billingAccounts/"))
	}

	if len(denied) > 0 {
		msg := "permission denied for " + strings.Join(denied, ", ")
		if len(t.accounts) > 1 {
			msg += " (to every account that lists it: " + strings.Join(t.accounts, ", ") + ")"
		}
		failed = append([]string{msg}, failed...)
	}
	if len(failed) > 0 {
		// Scoped to the project: the account's other projects were read. Only checks denied to
		// every account that lists the project get here.
		emit.Status(finding.Status{Account: t.accounts[0], Scope: t.project, State: worst, Detail: "project " + t.project + ": " + strings.Join(failed, "; ")})
	}
}

// billing collects billing accounts seen through accounts and projects, then judges each once.
type billing struct {
	g              *gcloud
	billingProject string
	mu             sync.Mutex
	accounts       map[string]*billingState
	ids            map[string]string // project number to id, for budget filters
}

type billingState struct {
	account  string // gcloud account used to read it
	open     *bool
	currency string // the account's currency, for budgets whose amount leaves it out
	linked   []linkedProject
}

func (b *billing) state(id, account string) *billingState {
	st, ok := b.accounts[id]
	if !ok {
		st = &billingState{account: account}
		b.accounts[id] = st
	}
	return st
}

func (b *billing) discover(ctx context.Context, account string, emit connector.Emitter) {
	var list []billingAccount
	if err := b.g.json(ctx, &list, "billing", "accounts", "list", "--account="+account); err != nil {
		state, why := classify(err)
		// Budgets are judged per billing account; without the list any of them may be missed.
		emit.Status(finding.Status{Account: account, Scope: billingScope("*"), State: state, Detail: "billing accounts list: " + why})
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ba := range list {
		open := ba.Open
		st := b.state(strings.TrimPrefix(ba.Name, "billingAccounts/"), account)
		st.open, st.currency = &open, ba.CurrencyCode
	}
}

func (b *billing) link(account string, p linkedProject, id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.state(id, account)
	st.linked = append(st.linked, p)
}

// judge reads budgets for every billing account that is open or pays for a project we saw.
func (b *billing) judge(ctx context.Context, emit connector.Emitter) {
	for _, id := range slices.Sorted(maps.Keys(b.accounts)) {
		st := b.accounts[id]
		if len(st.linked) == 0 && (st.open == nil || !*st.open) {
			continue // closed and paying for nothing we can see: it cannot spend
		}
		args := []string{"billing", "budgets", "list", "--billing-account=" + id, "--account=" + st.account}
		if b.billingProject != "" {
			args = append(args, "--billing-project="+b.billingProject)
		}
		var budgets []gcpBudget
		if err := b.g.json(ctx, &budgets, args...); err != nil {
			state, why := classify(err)
			emit.Status(finding.Status{Account: st.account, Scope: billingScope(id), State: state,
				Detail: fmt.Sprintf("billing account %s: cannot read budgets, so spend alerts are unknown for %s: %s", id, projectList(st.linked), why)})
			continue
		}
		for _, f := range billingFindings(st.account, id, st.currency, budgets, st.linked, b.ids) {
			f.Scope = billingScope(id)
			emit.Finding(f)
		}
	}
}

// Findings and failures carry a scope narrower than the gcloud account, so one project the account
// cannot read leaves only that project's findings unresolved: the project id for project checks,
// "billing:<id>" for a billing account's budgets.
func billingScope(id string) string { return "billing:" + id }

func projectList(ps []linkedProject) string {
	if len(ps) == 0 {
		return "no visible project"
	}
	return strings.Join(projectIDs(ps), ", ")
}
