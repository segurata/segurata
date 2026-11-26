// Package openrouter inventories an OpenRouter account with a management key: every API key in
// every workspace with its credit limit, last use and spend, plus the credit balance.
// Endpoints and their documentation are listed in docs/ai-connectors.md.
package openrouter

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/connectors/internal/keytrack"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
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
	`, store it with: security add-generic-password -s segurata-openrouter-admin -a "$USER" -w` +
	` and reference it as "keychain:segurata-openrouter-admin" under connectors.openrouter.secrets in ~/.config/segurata/config.json (docs/ai-connectors.md)`

// Connector is the built-in OpenRouter connector. Zero values use the real API and clock.
type Connector struct {
	BaseURL string
	Now     func() time.Time
}

func init() { connector.Register(&Connector{}) }

func (c *Connector) SetupHint(secret string) string {
	return connector.HintFor(secret, secretName, setupHint)
}

func (c *Connector) base() string { return httpx.Base(c.BaseURL, DefaultBaseURL) }

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     name,
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "OpenRouter keys per workspace, credit limits, last use, spend and balance",
		Needs:    []string{"secret:" + secretName},
		Theme:    finding.ThemeAISpend,
	}
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	key := req.Secrets[secretName]
	if key == "" {
		emit.Status(finding.Status{Account: account, State: finding.StateMissingCredentials, Detail: setupHint})
		return nil
	}
	s := &scan{
		ctx:  ctx,
		api:  httpx.New(c.base(), http.Header{"Authorization": {"Bearer " + key}}),
		emit: emit,
		now:  connector.Now(c.Now),
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
	s.emit.Status(finding.Status{Account: acct, State: httpx.State(err), Detail: err.Error()})
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

// list stops at a page shorter than pageSize.
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
	case httpx.IsStatus(err, http.StatusForbidden): // a workspace-scoped key lists its own keys only
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
			acct, textfmt.USD(monthly), active, uncapped),
		Evidence: map[string]any{
			"usage_month_to_date_usd":      monthly,
			"byok_usage_month_to_date_usd": byokMonthly,
			"keys":                         active,
			"keys_without_limit":           uncapped,
		},
		Remediation: finding.Remediation{Summary: "Give every key a credit limit with a reset period", URL: keysURL},
	})
}

func (w workspace) label() string { return cmp.Or(w.Name, w.Slug, w.ID) }

func (k apiKey) label() string { return cmp.Or(k.Name, k.Hash) }

// credits bound what an uncapped key can burn; only an organization-scoped key may read them.
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
			textfmt.USD(balance), textfmt.USD(c.Data.TotalCredits), textfmt.USD(c.Data.TotalUsage)),
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

// keyAssessment: OpenRouter records last use only since the end of 2025, so a null last_used_at
// with past usage means idle since then, not never used.
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
	case now.Sub(*last) > finding.IdleAfter:
		a.Raise(finding.SevMedium, fmt.Sprintf("unused for %d days", httpx.Days(now, *last)))
	}
	return a.Done("in use with a credit limit")
}

func keyFinding(acct string, k apiKey, now time.Time) finding.Finding {
	a := keyAssessment(k, now)
	n := k.label()
	ev := map[string]any{
		"redacted":      secretrisk.Masked(k.Label, 0), // the label gives no length
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
			Action:  unusedAction(k, now),
		},
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (c *Connector) Track(f finding.Finding) *finding.Track { return keytrack.Track("OpenRouter", f) }
