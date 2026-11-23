// Package openrouter inventories an OpenRouter account with a management key: every API key in
// every workspace with its credit limit, last use and spend, plus the credit balance.
// Endpoints and their documentation are listed in docs/ai-connectors.md.
package openrouter

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const (
	name           = "openrouter"
	secretName     = "OPENROUTER_MANAGEMENT_KEY"
	DefaultBaseURL = "https://openrouter.ai/api/v1"
	account        = "organization"
	pageSize       = 100

	keysURL       = "https://openrouter.ai/settings/keys"
	creditsURL    = "https://openrouter.ai/settings/credits"
	managementURL = "https://openrouter.ai/settings/management-keys"
)

const setupHint = "set " + secretName + ": create a read-only Management API key at " + managementURL +
	`, store it with: security add-generic-password -s securizame-openrouter-admin -a "$USER" -w` +
	` and reference it as "keychain:securizame-openrouter-admin" under connectors.openrouter.secrets in ~/.config/securizame/config.json (docs/ai-connectors.md)`

// Connector is the built-in OpenRouter connector. Zero values use the real API and clock.
type Connector struct {
	BaseURL string
	Now     func() time.Time
}

func init() { connector.Register(&Connector{}) }

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     name,
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "OpenRouter keys per workspace, credit limits, last use, spend and balance",
		Needs:    []string{"secret:" + secretName},
	}
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	key := req.Secrets[secretName]
	if key == "" {
		emit.Status(finding.Status{Account: account, State: finding.StateMissingCredentials, Detail: setupHint})
		return nil
	}
	base, now := c.BaseURL, time.Now
	if base == "" {
		base = DefaultBaseURL
	}
	if c.Now != nil {
		now = c.Now
	}
	s := &scan{
		ctx:  ctx,
		api:  httpx.New(base, http.Header{"Authorization": {"Bearer " + key}}),
		emit: emit,
		now:  now().UTC(),
	}
	s.run()
	return nil
}

type scan struct {
	ctx    context.Context
	api    *httpx.Client
	emit   connector.Emitter
	now    time.Time
	failed bool
}

func (s *scan) fail(acct string, err error) {
	s.failed = true
	s.emit.Status(finding.Status{Account: acct, State: finding.StateError, Detail: err.Error()})
}

type workspace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type apiKey struct {
	Hash             string   `json:"hash"`
	Name             string   `json:"name"`
	Label            string   `json:"label"`
	Disabled         bool     `json:"disabled"`
	Limit            *float64 `json:"limit"`
	LimitRemaining   *float64 `json:"limit_remaining"`
	LimitReset       *string  `json:"limit_reset"`
	Usage            float64  `json:"usage"`
	UsageMonthly     float64  `json:"usage_monthly"`
	BYOKUsage        float64  `json:"byok_usage"`
	BYOKUsageMonthly float64  `json:"byok_usage_monthly"`
	CreatedAt        *string  `json:"created_at"`
	ExpiresAt        *string  `json:"expires_at"`
	LastUsedAt       *string  `json:"last_used_at"`
	CreatorUserID    *string  `json:"creator_user_id"`
	WorkspaceID      string   `json:"workspace_id"`
}

// list pages an offset-paginated endpoint; a page shorter than pageSize is the last one.
func list[T any](s *scan, path string, q url.Values) ([]T, error) {
	var out []T
	for offset := 0; offset < 1_000_000; offset += pageSize {
		qq := url.Values{"offset": {strconv.Itoa(offset)}}
		for k, v := range q {
			qq[k] = v
		}
		var p struct {
			Data []T `json:"data"`
		}
		if err := s.api.Get(s.ctx, path, qq, &p); err != nil {
			return out, err
		}
		out = append(out, p.Data...)
		if len(p.Data) < pageSize {
			return out, nil
		}
	}
	return out, fmt.Errorf("GET %s: pagination did not end", path)
}

func (s *scan) run() {
	workspaces, err := list[workspace](s, "/workspaces", url.Values{"limit": {strconv.Itoa(pageSize)}})
	switch {
	case httpx.IsStatus(err, http.StatusForbidden):
		// A workspace-scoped management key cannot list workspaces; its key list is its own workspace.
		s.emit.Log("management key cannot list workspaces; inventorying its own workspace only")
		workspaces = []workspace{{}}
	case httpx.IsStatus(err, http.StatusUnauthorized):
		s.fail(account, err)
		return
	case err != nil:
		s.fail(account, err)
		workspaces = []workspace{{}}
	}
	for _, w := range workspaces {
		s.workspace(w)
	}
	s.credits()
	if !s.failed {
		s.emit.Status(finding.Status{Account: account, State: finding.StateOK})
	}
}

func (s *scan) workspace(w workspace) {
	acct, q := "default workspace", url.Values{}
	if w.ID != "" {
		acct, q = w.label(), url.Values{"workspace_id": {w.ID}}
	}
	keys, err := list[apiKey](s, "/keys", q)
	if err != nil {
		s.fail(acct, err)
		return
	}
	var monthly, byokMonthly float64
	active, uncapped := 0, 0
	for _, k := range keys {
		if k.Disabled {
			continue
		}
		active++
		monthly += k.UsageMonthly
		byokMonthly += k.BYOKUsageMonthly
		if k.Limit == nil {
			uncapped++
		}
		s.emit.Finding(keyFinding(acct, k, s.now))
	}
	id := w.ID
	if id == "" {
		id = "default"
	}
	s.emit.Finding(finding.Finding{
		Account:  acct,
		Resource: finding.Resource{Type: "workspace", ID: id, Name: acct},
		Kind:     finding.KindSpend,
		Severity: finding.SevInfo,
		Title: fmt.Sprintf("Workspace %q: %s on OpenRouter credits this month across %d keys, %d without a limit",
			acct, httpx.USD(monthly), active, uncapped),
		Evidence: map[string]any{
			"usage_month_to_date_usd":      monthly,
			"byok_usage_month_to_date_usd": byokMonthly,
			"keys":                         active,
			"keys_without_limit":           uncapped,
		},
		Remediation: finding.Remediation{Summary: "Give every key a credit limit with a reset period", URL: keysURL},
	})
}

func (w workspace) label() string {
	switch {
	case w.Name != "":
		return w.Name
	case w.Slug != "":
		return w.Slug
	}
	return w.ID
}

// credits is prepaid balance: the outer bound on what an uncapped key can burn. Only an
// organization-scoped management key may read it.
func (s *scan) credits() {
	var c struct {
		Data struct {
			TotalCredits float64 `json:"total_credits"`
			TotalUsage   float64 `json:"total_usage"`
		} `json:"data"`
	}
	err := s.api.Get(s.ctx, "/credits", nil, &c)
	if httpx.IsStatus(err, http.StatusForbidden) {
		s.emit.Log("management key cannot read credits (workspace-scoped key)")
		return
	}
	if err != nil {
		s.fail(account, err)
		return
	}
	balance := c.Data.TotalCredits - c.Data.TotalUsage
	s.emit.Finding(finding.Finding{
		Account:  account,
		Resource: finding.Resource{Type: "credits", ID: account, Name: "OpenRouter credits"},
		Kind:     finding.KindSpend,
		Severity: finding.SevInfo,
		Title: fmt.Sprintf("OpenRouter balance %s (%s purchased, %s used)",
			httpx.USD(balance), httpx.USD(c.Data.TotalCredits), httpx.USD(c.Data.TotalUsage)),
		Evidence: map[string]any{
			"total_credits_usd": c.Data.TotalCredits,
			"total_usage_usd":   c.Data.TotalUsage,
			"balance_usd":       balance,
		},
		Remediation: finding.Remediation{
			Summary: "Uncapped keys can spend the whole balance; check whether auto top-up is on (not exposed by the API)",
			URL:     creditsURL,
		},
	})
}

// keyAssessment applies the severity rules. OpenRouter has recorded last use only since the end
// of 2025: a null last_used_at with past usage means idle since then, not never used.
func keyAssessment(k apiKey, now time.Time) httpx.Assessment {
	var a httpx.Assessment
	if e := httpx.ParseTime(k.ExpiresAt); e != nil && e.Before(now) {
		return a.Done("expired")
	}
	if k.Limit == nil {
		a.Raise(finding.SevHigh, "no credit limit")
	}
	last := httpx.ParseTime(k.LastUsedAt)
	switch {
	case last == nil && (k.Usage > 0 || k.BYOKUsage > 0):
		a.Raise(finding.SevMedium, "no recorded use since the end of 2025")
	case last == nil:
		a.Raise(finding.SevMedium, "never used")
	case now.Sub(*last) > httpx.IdleAfter:
		a.Raise(finding.SevMedium, fmt.Sprintf("unused for %d days", httpx.Days(now, *last)))
	}
	return a.Done("in use with a credit limit")
}

func keyFinding(acct string, k apiKey, now time.Time) finding.Finding {
	a := keyAssessment(k, now)
	n := k.Name
	if n == "" {
		n = k.Hash
	}
	ev := map[string]any{
		"redacted":      k.Label, // OpenRouter's own masked form of the key
		"issues":        a.Reasons,
		"usage_usd":     k.Usage,
		"usage_month":   k.UsageMonthly,
		"byok_usage":    k.BYOKUsage,
		"workspace_id":  k.WorkspaceID,
		"expires_at":    httpx.ParseTime(k.ExpiresAt),
		"creator_user":  deref(k.CreatorUserID),
		"limit_usd":     k.Limit,
		"limit_left":    k.LimitRemaining,
		"limit_resets":  deref(k.LimitReset),
		"never_expires": k.ExpiresAt == nil || *k.ExpiresAt == "",
	}
	return finding.Finding{
		Account:    acct,
		Resource:   finding.Resource{Type: "api_key", ID: k.Hash, Name: n},
		Kind:       finding.KindCredential,
		Severity:   a.Severity,
		Title:      fmt.Sprintf("API key %q: %s", n, strings.Join(a.Reasons, "; ")),
		Evidence:   ev,
		CreatedAt:  httpx.ParseTime(k.CreatedAt),
		LastUsedAt: httpx.ParseTime(k.LastUsedAt),
		Remediation: finding.Remediation{
			Summary: "Set a credit limit with a reset period on every key; disable or delete keys nobody uses",
			URL:     keysURL,
		},
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
