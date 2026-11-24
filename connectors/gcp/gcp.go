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
	}
}

type settings struct {
	accounts       []string
	projects       []string
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

// target is one project inspected with one account. Each project is inspected once.
type target struct {
	account, project, number string
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
	accounts, err := c.accounts(ctx, g, cfg)
	if err != nil {
		_, why := classify(err)
		emit.Status(finding.Status{Account: localAccount, State: finding.StateError, Detail: "gcloud auth list: " + why})
		return nil
	}
	if len(accounts) == 0 {
		emit.Status(finding.Status{Account: localAccount, State: finding.StateMissingCredentials, Detail: "gcloud has no credentialed accounts"})
		return nil
	}

	targets, usable := c.plan(ctx, g, accounts, cfg.projects, emit)
	bill := &billing{g: g, billingProject: cfg.billingProject, accounts: map[string]*billingState{}}
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

// accounts are the configured accounts, or every credentialed account gcloud lists.
func (c *Connector) accounts(ctx context.Context, g *gcloud, cfg settings) ([]string, error) {
	if len(cfg.accounts) > 0 {
		return cfg.accounts, nil
	}
	var listed []struct {
		Account string `json:"account"`
	}
	if err := g.json(ctx, &listed, "auth", "list"); err != nil {
		return nil, err
	}
	var out []string
	for _, a := range listed {
		out = append(out, a.Account)
	}
	return out, nil
}

// plan lists each account's projects and assigns every project to the first account that sees
// it. Configured projects nobody lists go to the first account that could list projects.
func (c *Connector) plan(ctx context.Context, g *gcloud, accounts, only []string, emit connector.Emitter) ([]target, []string) {
	var targets []target
	var usable []string
	seen := map[string]bool{}
	want := map[string]bool{}
	for _, p := range only {
		want[p] = true
	}
	for _, a := range accounts {
		var projects []struct {
			ProjectID      string `json:"projectId"`
			ProjectNumber  string `json:"projectNumber"`
			LifecycleState string `json:"lifecycleState"`
		}
		if err := g.json(ctx, &projects, "projects", "list", "--account="+a); err != nil {
			state, why := classify(err)
			emit.Status(finding.Status{Account: a, State: state, Detail: "projects list: " + why})
			continue
		}
		usable = append(usable, a)
		emit.Status(finding.Status{Account: a, State: finding.StateOK, Detail: fmt.Sprintf("%d project(s) visible", len(projects))})
		for _, p := range projects {
			if seen[p.ProjectID] || (len(only) > 0 && !want[p.ProjectID]) ||
				(p.LifecycleState != "" && p.LifecycleState != "ACTIVE") {
				continue
			}
			seen[p.ProjectID] = true
			targets = append(targets, target{account: a, project: p.ProjectID, number: p.ProjectNumber})
		}
	}
	for _, p := range only {
		if !seen[p] && len(usable) > 0 {
			seen[p] = true
			targets = append(targets, target{account: usable[0], project: p})
		}
	}
	return targets, usable
}

// inspect runs the per-project checks and reports the ones that failed in one status line.
func (c *Connector) inspect(ctx context.Context, g *gcloud, t target, bill *billing, emit connector.Emitter) {
	acct, proj := "--account="+t.account, "--project="+t.project
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
	emitAll := func(fs []finding.Finding) {
		for _, f := range fs {
			emit.Finding(f)
		}
	}

	var policy iamPolicy
	if err := g.json(ctx, &policy, "projects", "get-iam-policy", t.project, acct); err != nil {
		fail("iam policy", err)
	} else {
		emitAll(iamFindings(t.account, t.project, policy))
	}

	var sas []serviceAccount
	if err := g.json(ctx, &sas, "iam", "service-accounts", "list", proj, acct); err != nil {
		fail("service accounts", err)
	}
	for _, sa := range sas {
		var keys []saKey
		if err := g.json(ctx, &keys, "iam", "service-accounts", "keys", "list", "--iam-account="+sa.Email, "--managed-by=user", proj, acct); err != nil {
			fail("keys of "+sa.Email, err)
			continue
		}
		emitAll(saKeyFindings(t.account, t.project, sa, keys, c.now()))
	}

	var keys []apiKey
	if err := g.json(ctx, &keys, "services", "api-keys", "list", proj, acct); err != nil {
		fail("api keys", err)
	} else {
		emitAll(apiKeyFindings(t.account, t.project, keys))
	}

	var info billingInfo
	if err := g.json(ctx, &info, "billing", "projects", "describe", t.project, acct); err != nil {
		fail("billing", err)
	} else if info.BillingEnabled && info.BillingAccountName != "" {
		bill.link(t, strings.TrimPrefix(info.BillingAccountName, "billingAccounts/"))
	}

	if len(denied) > 0 {
		failed = append([]string{"permission denied for " + strings.Join(denied, ", ")}, failed...)
	}
	if len(failed) > 0 {
		emit.Status(finding.Status{Account: t.account, State: worst, Detail: "project " + t.project + ": " + strings.Join(failed, "; ")})
	}
}

// billing collects billing accounts seen through accounts and projects, then judges each once.
type billing struct {
	g              *gcloud
	billingProject string
	mu             sync.Mutex
	accounts       map[string]*billingState
}

type billingState struct {
	account string // gcloud account used to read it
	open    *bool
	linked  []linkedProject
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
		emit.Status(finding.Status{Account: account, State: state, Detail: "billing accounts list: " + why})
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ba := range list {
		open := ba.Open
		b.state(strings.TrimPrefix(ba.Name, "billingAccounts/"), account).open = &open
	}
}

func (b *billing) link(t target, id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.state(id, t.account)
	st.linked = append(st.linked, linkedProject{id: t.project, number: t.number})
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
		var budgets []budget
		if err := b.g.json(ctx, &budgets, args...); err != nil {
			state, why := classify(err)
			emit.Status(finding.Status{Account: st.account, State: state,
				Detail: fmt.Sprintf("billing account %s: cannot read budgets, so spend alerts are unknown for %s: %s", id, projectList(st.linked), why)})
			continue
		}
		for _, f := range billingFindings(st.account, id, budgets, st.linked) {
			emit.Finding(f)
		}
	}
}

func projectList(ps []linkedProject) string {
	if len(ps) == 0 {
		return "no visible project"
	}
	return strings.Join(projectIDs(ps), ", ")
}
