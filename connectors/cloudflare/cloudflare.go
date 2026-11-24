// Package cloudflare inventories a Cloudflare user through the REST API with a read-only API
// token: the user's API tokens (expiry, idleness, IP restrictions, broad edit policies), each
// account's two-factor enforcement, members and super administrators, and per zone the SSL mode,
// Always Use HTTPS, minimum TLS version and DNSSEC. GET only. Endpoints and their documentation
// are listed in docs/cloud-connectors.md.
package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const (
	name           = "cloudflare"
	secretName     = "CLOUDFLARE_API_TOKEN"
	DefaultBaseURL = "https://api.cloudflare.com/client/v4"

	// userAccount labels findings about the user rather than one Cloudflare account.
	userAccount = "user"

	defaultMaxZones = 200
	perPage         = 50 // the maximum every listing used here accepts
	maxPages        = 1000
	workers         = 4

	// DefaultInterval spaces request starts so a run stays at 1000 requests per five minutes,
	// under Cloudflare's 1200 per user (dashboard and other tokens count against the same quota).
	DefaultInterval = 300 * time.Millisecond
)

// Permissions is the minimal read-only token, as the dashboard names each permission group.
const Permissions = "User > API Tokens > Read; Account > Account Settings > Read; " +
	"Zone > Zone > Read; Zone > Zone Settings > Read; Zone > DNS > Read"

const setupHint = secretName + " is not configured. Create a user API token at " + urlTokens +
	" (Create Token > Create Custom Token) with only these permissions: " + Permissions +
	". Account Resources: Include > All accounts; Zone Resources: Include > All zones. Set an expiry" +
	" (TTL) and, if you can, Client IP Address Filtering. Store it with" +
	` security add-generic-password -s segurata-cloudflare -a "$USER" -w` +
	` and reference it in ~/.config/segurata/config.json as` +
	` {"connectors": {"cloudflare": {"secrets": {"` + secretName + `": "keychain:segurata-cloudflare"}}}}` +
	` (one instance per login: "cloudflare:<label>" with keychain:segurata-cloudflare-<label>).` +
	" See docs/cloud-connectors.md."

// Connector is the built-in Cloudflare connector. Zero values use the real API, clock and pacing.
type Connector struct {
	BaseURL  string
	Now      func() time.Time
	Interval time.Duration // minimum gap between request starts; zero means DefaultInterval, negative none
}

func init() { connector.Register(&Connector{}) }

// SetupHint says how to create and store the secret the connector needs (connector.SetupHinter).
func (c *Connector) SetupHint(secret string) string {
	if secret != secretName {
		return ""
	}
	return setupHint
}

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     name,
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "API tokens (expiry, idle, IP restriction, broad edit policies), account 2FA enforcement and super admins, zone SSL/TLS settings and DNSSEC",
		Needs:    []string{"secret:" + secretName},
	}
}

type settings struct{ maxZones int }

func parseSettings(m map[string]any) (settings, error) {
	s := settings{maxZones: defaultMaxZones}
	if v, ok := m["max_zones"]; ok && v != nil {
		n, ok := v.(float64)
		if !ok || n < 1 || n != float64(int(n)) {
			return s, errors.New(`cloudflare config: "max_zones" must be a whole number above 0`)
		}
		s.maxZones = int(n)
	}
	return s, nil
}

// pacer hands out request start times at least every apart, across goroutines.
type pacer struct {
	mu    sync.Mutex
	next  time.Time
	every time.Duration
}

func (p *pacer) wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil || p.every <= 0 {
		return err
	}
	p.mu.Lock()
	now := time.Now()
	at := p.next
	if at.Before(now) {
		at = now
	}
	p.next = at.Add(p.every)
	p.mu.Unlock()
	t := time.NewTimer(time.Until(at))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

var errRateLimited = errors.New("Cloudflare answered HTTP 429: the per-user API quota (1200 requests per 5 minutes) is spent and every call is blocked for 5 minutes; the rest of this run was skipped, run it again later")

// client is the paced, GET-only API access one run shares across goroutines.
type client struct {
	api     *httpx.Client
	pace    *pacer
	limited atomic.Bool
}

func (c *Connector) client(tok string) *client {
	base, every := c.BaseURL, c.Interval
	if base == "" {
		base = DefaultBaseURL
	}
	if every == 0 {
		every = DefaultInterval
	}
	return &client{api: httpx.New(base, http.Header{"Authorization": {"Bearer " + tok}}), pace: &pacer{every: every}}
}

// get decodes the "result" of Cloudflare's envelope into out. After a 429 it stops calling.
func (cl *client) get(ctx context.Context, path string, q url.Values, out any) (resultInfo, error) {
	if cl.limited.Load() {
		return resultInfo{}, errRateLimited
	}
	if err := cl.pace.wait(ctx); err != nil {
		return resultInfo{}, err
	}
	env := envelope{Result: out}
	err := cl.api.Get(ctx, path, q, &env)
	if httpx.IsStatus(err, http.StatusTooManyRequests) {
		cl.limited.Store(true)
		return resultInfo{}, errRateLimited
	}
	return env.ResultInfo, err
}

type envelope struct {
	Result     any        `json:"result"`
	ResultInfo resultInfo `json:"result_info"`
}

type resultInfo struct {
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
	TotalCount int `json:"total_count"`
}

// list follows page=1,2,… until a short page, the last page, or max items (0: no cap). total is
// the provider's total_count when it gave one.
func list[T any](ctx context.Context, cl *client, path string, q url.Values, max int) (items []T, total int, err error) {
	for page := 1; page <= maxPages; page++ {
		qq := url.Values{"per_page": {fmt.Sprint(perPage)}, "page": {fmt.Sprint(page)}}
		for k, v := range q {
			qq[k] = v
		}
		var batch []T
		info, err := cl.get(ctx, path, qq, &batch)
		if err != nil {
			return items, total, err
		}
		total = info.TotalCount
		items = append(items, batch...)
		if max > 0 && len(items) >= max {
			return items[:max], total, nil
		}
		if len(batch) < perPage || (info.TotalPages > 0 && page >= info.TotalPages) {
			return items, total, nil
		}
	}
	return items, total, fmt.Errorf("GET %s: pagination did not end", path)
}

// verify checks the token itself; any failure there means nothing else can run.
func verify(ctx context.Context, cl *client) (tokenStatus, error) {
	var v tokenStatus
	_, err := cl.get(ctx, "/user/tokens/verify", nil, &v)
	return v, err
}

type tokenStatus struct {
	ID        string  `json:"id"`
	Status    string  `json:"status"`
	ExpiresOn *string `json:"expires_on"`
}

// rejected reports whether err means the token itself was refused (Cloudflare answers 400 with
// "Invalid API Token" or 401/403 depending on the failure).
func rejected(err error) bool {
	return httpx.IsStatus(err, http.StatusBadRequest) || httpx.IsStatus(err, http.StatusUnauthorized) ||
		httpx.IsStatus(err, http.StatusForbidden)
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	tok := req.Secrets[secretName]
	if tok == "" {
		emit.Status(finding.Status{Account: name, State: finding.StateMissingCredentials, Detail: setupHint})
		return nil
	}
	cfg, err := parseSettings(req.Config)
	if err != nil {
		emit.Status(finding.Status{Account: name, State: finding.StateError, Detail: err.Error()})
		return nil
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	s := &scan{ctx: ctx, cl: c.client(tok), emit: emit, now: now().UTC(), cfg: cfg, failures: map[string]*failure{}}
	s.run()
	return nil
}

type scan struct {
	ctx  context.Context
	cl   *client
	emit connector.Emitter
	now  time.Time
	cfg  settings

	labels   []string            // accounts seen, in order, for one status each
	failures map[string]*failure // by account label + what failed + HTTP code
}

// failure is one kind of error on one account, counted instead of repeated for every zone.
type failure struct {
	account string
	what    string
	err     error
	count   int
}

func (s *scan) see(account string) {
	for _, l := range s.labels {
		if l == account {
			return
		}
	}
	s.labels = append(s.labels, account)
}

func (s *scan) fail(account, what string, err error) {
	s.see(account)
	code := 0
	var se *httpx.StatusError
	if errors.As(err, &se) {
		code = se.Code
	}
	key := fmt.Sprintf("%s\x00%s\x00%d", account, what, code)
	if f, ok := s.failures[key]; ok {
		f.count++
		return
	}
	s.failures[key] = &failure{account: account, what: what, err: err, count: 1}
}

func (s *scan) finding(f finding.Finding) {
	s.see(f.Account)
	s.emit.Finding(f)
}

// Account and zone findings come from the account and zone lists, so when a list fails or is
// capped, every finding it would have produced is declared unread by scope.
func accountScope(label string) string { return "account:" + label }
func zoneScope(name string) string     { return "zone:" + name }

func (s *scan) scoped(scope string, f finding.Finding) {
	f.Scope = scope
	s.finding(f)
}

func (s *scan) run() {
	v, err := verify(s.ctx, s.cl)
	switch {
	case rejected(err):
		s.emit.Status(finding.Status{Account: name, State: finding.StateReauth, Detail: err.Error() + "; create a new token: " + setupHint})
		return
	case err != nil:
		s.emit.Status(finding.Status{Account: name, State: finding.StateError, Detail: err.Error()})
		return
	case v.Status != "active":
		s.emit.Status(finding.Status{Account: name, State: finding.StateReauth, Detail: fmt.Sprintf("the token is %s; create a new one: %s", v.Status, setupHint)})
		return
	}
	s.see(userAccount)
	s.tokens(v.ID)
	s.finding(globalKeyFinding())
	s.accounts()
	s.zones()
	s.statuses()
}

func (s *scan) tokens(self string) {
	toks, _, err := list[apiToken](s.ctx, s.cl, "/user/tokens", nil, 0)
	if err != nil {
		s.fail(userAccount, "API tokens", err)
	}
	for _, t := range toks {
		s.finding(tokenFinding(t, t.ID == self, s.now))
	}
}

func (s *scan) accounts() {
	accts, _, err := list[account](s.ctx, s.cl, "/accounts", nil, 0)
	if err != nil {
		s.fail(userAccount, "accounts", err)
		s.emit.Scope(accountScope("*"), false, "accounts not listed: "+err.Error())
	}
	for _, a := range accts {
		label := a.label()
		var details account
		if _, err := s.cl.get(s.ctx, "/accounts/"+url.PathEscape(a.ID), nil, &details); err != nil {
			s.fail(label, "account settings", err)
		} else {
			s.scoped(accountScope(label), accountFinding(details, label))
		}
		members, _, err := list[member](s.ctx, s.cl, "/accounts/"+url.PathEscape(a.ID)+"/members", nil, 0)
		if err != nil {
			s.fail(label, "members", err)
			continue
		}
		enforced := details.Settings != nil && details.Settings.EnforceTwofactor
		for _, f := range memberFindings(a.ID, label, members, enforced) {
			s.scoped(accountScope(label), f)
		}
	}
}

// zoneResult is what one worker read about one zone.
type zoneResult struct {
	findings []finding.Finding
	errs     []zoneErr
}

type zoneErr struct {
	what string
	err  error
}

func (s *scan) zones() {
	zones, total, err := list[zone](s.ctx, s.cl, "/zones", nil, s.cfg.maxZones)
	if err != nil {
		s.fail(userAccount, "zones", err)
		s.emit.Scope(zoneScope("*"), false, "zones not listed: "+err.Error())
	}
	if total > len(zones) && len(zones) == s.cfg.maxZones {
		msg := fmt.Sprintf("checked the first %d of %d zones; raise max_zones in the cloudflare config to check more", len(zones), total)
		s.emit.Log(msg)
		s.emit.Scope(zoneScope("*"), false, msg) // which zones were left out is unknown
	}
	results := make([]zoneResult, len(zones))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = s.zone(zones[i])
			}
		}()
	}
	for i := range zones {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	for i, r := range results {
		label := zones[i].accountLabel()
		for _, e := range r.errs {
			s.fail(label, e.what, e.err)
		}
		for _, f := range r.findings {
			s.scoped(zoneScope(zones[i].Name), f)
		}
	}
}

// zoneSettings are the settings read one by one: the bulk "get all zone settings" endpoint is
// deprecated.
var zoneSettings = []string{"ssl", "always_use_https", "min_tls_version"}

func (s *scan) zone(z zone) zoneResult {
	var r zoneResult
	if z.Status == "moved" {
		return r
	}
	base := "/zones/" + url.PathEscape(z.ID)
	for _, id := range zoneSettings {
		var st zoneSetting
		if _, err := s.cl.get(s.ctx, base+"/settings/"+id, nil, &st); err != nil {
			r.errs = append(r.errs, zoneErr{"zone setting " + id, err})
			continue
		}
		if f, ok := settingFinding(z, id, st.value()); ok {
			r.findings = append(r.findings, f)
		}
	}
	var d dnssec
	if _, err := s.cl.get(s.ctx, base+"/dnssec", nil, &d); err != nil {
		r.errs = append(r.errs, zoneErr{"DNSSEC", err})
	} else {
		r.findings = append(r.findings, dnssecFinding(z, d.Status))
	}
	return r
}

func (s *scan) statuses() {
	byAccount := map[string][]*failure{}
	for _, f := range s.failures {
		byAccount[f.account] = append(byAccount[f.account], f)
	}
	for _, label := range s.labels {
		fs := byAccount[label]
		if len(fs) == 0 {
			s.emit.Status(finding.Status{Account: label, State: finding.StateOK})
			continue
		}
		sort.Slice(fs, func(i, j int) bool { return fs[i].what < fs[j].what })
		var parts []string
		state := finding.StateNoScope
		for _, f := range fs {
			msg := f.what + ": " + f.err.Error()
			if f.count > 1 {
				msg = fmt.Sprintf("%s (%d times)", msg, f.count)
			}
			parts = append(parts, msg)
			if !httpx.IsStatus(f.err, http.StatusForbidden) {
				state = finding.StateError
			}
		}
		detail := strings.Join(parts, "; ")
		if state == finding.StateNoScope {
			detail += "; the token lacks a permission, it needs: " + Permissions
		}
		s.emit.Status(finding.Status{Account: label, State: state, Detail: detail})
	}
}

// Doctor verifies the token and probes one page of each listing the inventory reads, so a missing
// permission shows before a run. Nothing is printed from the token.
func (c *Connector) Doctor(ctx context.Context, req connector.Request) []connector.Check {
	tok := req.Secrets[secretName]
	if tok == "" {
		return []connector.Check{{Level: connector.Warn, What: "cloudflare token", Detail: secretName + " is not configured; the connector is skipped", Fix: setupHint}}
	}
	if _, err := parseSettings(req.Config); err != nil {
		return []connector.Check{{Level: connector.Fail, What: "cloudflare config", Detail: err.Error(), Fix: `set "max_zones" to a whole number above 0`}}
	}
	cl := c.client(tok)
	v, err := verify(ctx, cl)
	switch {
	case err != nil:
		return []connector.Check{{Level: connector.Fail, What: "cloudflare token", Detail: err.Error(), Fix: setupHint}}
	case v.Status != "active":
		return []connector.Check{{Level: connector.Fail, What: "cloudflare token", Detail: "token status " + v.Status, Fix: setupHint}}
	}
	detail := "active"
	if exp := httpx.ParseTime(v.ExpiresOn); exp != nil {
		detail += ", expires " + exp.Format(time.DateOnly)
	} else {
		detail += ", no expiry"
	}
	checks := []connector.Check{{Level: connector.OK, What: "cloudflare token", Detail: detail}}
	firstPage := url.Values{"page": {"1"}, "per_page": {"5"}}
	probe := func(what, path string, q url.Values, perm string, out any) bool {
		if _, err := cl.get(ctx, path, q, out); err != nil {
			checks = append(checks, connector.Check{Level: connector.Fail, What: "cloudflare " + what, Detail: err.Error(), Fix: "add " + perm + " to the token at " + urlTokens})
			return false
		}
		checks = append(checks, connector.Check{Level: connector.OK, What: "cloudflare " + what, Detail: "readable"})
		return true
	}
	var none []struct{}
	probe("API tokens", "/user/tokens", firstPage, "User > API Tokens > Read", &none)
	probe("accounts", "/accounts", firstPage, "Account > Account Settings > Read", &none)
	var zones []zone
	if !probe("zones", "/zones", firstPage, "Zone > Zone > Read", &zones) || len(zones) == 0 {
		return checks
	}
	// Per-zone permissions can only be probed on a zone; the first one stands for all.
	base := "/zones/" + url.PathEscape(zones[0].ID)
	var st zoneSetting
	var d dnssec
	probe("zone settings ("+zones[0].Name+")", base+"/settings/ssl", nil, "Zone > Zone Settings > Read", &st)
	probe("DNSSEC ("+zones[0].Name+")", base+"/dnssec", nil, "Zone > DNS > Read", &d)
	return checks
}
