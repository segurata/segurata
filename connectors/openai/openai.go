// Package openai inventories an OpenAI organization through the Admin API: project API keys,
// admin keys, organization and project hard spend limits and alerts, and the last 30 days of cost.
// Endpoints and their documentation are listed in docs/ai-connectors.md.
package openai

import (
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
	name           = "openai"
	secretName     = "OPENAI_ADMIN_KEY"
	DefaultBaseURL = "https://api.openai.com/v1"
	account        = "organization"
	costWindow     = 30 * 24 * time.Hour

	keysURL   = "https://platform.openai.com/api-keys"
	adminURL  = "https://platform.openai.com/settings/organization/admin-keys"
	limitsURL = "https://platform.openai.com/settings/organization/limits"
)

const setupHint = "set " + secretName + ": create an Admin API key at " + adminURL +
	`, store it with: security add-generic-password -s segurata-openai-admin -a "$USER" -w` +
	` and reference it as "keychain:segurata-openai-admin" under connectors.openai.secrets in ~/.config/segurata/config.json (docs/ai-connectors.md)`

// Connector is the built-in OpenAI connector. Zero values use the real API and clock.
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
		Summary:  "OpenAI keys, admin keys, spend limits, spend alerts and 30-day cost",
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

func (s *scan) fail(err error) {
	s.failed = true
	s.emit.Status(finding.Status{Account: account, State: httpx.State(err), Detail: err.Error()})
}

func (s *scan) run() {
	projects, err := list[project](s, "/organization/projects", nil)
	if err != nil {
		s.fail(err) // most likely a wrong key; nothing else is meaningful
		return
	}
	listed, err := list[adminKey](s, "/organization/admin_api_keys", nil)
	admins, lastUsed := splitAdminListing(listed)
	if err != nil {
		s.fail(err)
		lastUsed = nil // unknown: no key is called never used
	}

	orgLimit := s.spendLimit("/organization/spend_limit")
	orgAlerts := s.alerts("/organization/spend_alerts")
	costs, costErr := s.costs()
	if costErr != nil {
		s.fail(costErr)
	}

	var total float64
	for _, v := range costs {
		total += v
	}
	s.emitBudget(finding.Resource{Type: "organization", ID: account, Name: "OpenAI organization"},
		"OpenAI organization", orgLimit, orgAlerts, total, costErr == nil, -1)

	for _, p := range projects {
		projLimit := s.spendLimit("/organization/projects/" + url.PathEscape(p.ID) + "/spend_limit")
		projAlerts := s.alerts("/organization/projects/" + url.PathEscape(p.ID) + "/spend_alerts")
		keys, err := list[projectKey](s, "/organization/projects/"+url.PathEscape(p.ID)+"/api_keys",
			url.Values{"owner_project_access": {"any"}})
		keyCount := len(keys)
		if err != nil {
			keyCount = -1
		}
		s.emitBudget(finding.Resource{Type: "project", ID: p.ID, Name: p.label()},
			fmt.Sprintf("OpenAI project %q", p.label()), projLimit, projAlerts, costs[p.ID], costErr == nil, keyCount)
		if err != nil {
			s.fail(err)
			continue
		}
		capped := limitCover{known: orgLimit.known && projLimit.known, set: orgLimit.set || projLimit.set}
		for _, k := range keys {
			usageKnown := k.LastUsedAt != nil || lastUsed != nil
			if k.LastUsedAt == nil {
				k.LastUsedAt = lastUsed[k.ID]
			}
			s.emit.Finding(projectKeyFinding(k, p, capped, usageKnown, s.now))
		}
	}

	for _, k := range admins {
		s.emit.Finding(adminKeyFinding(k, s.now))
	}
	if !s.failed {
		s.emit.Status(finding.Status{Account: account, State: finding.StateOK})
	}
}

type page[T any] struct {
	Data    []T     `json:"data"`
	HasMore bool    `json:"has_more"`
	LastID  *string `json:"last_id"`
}

func list[T any](s *scan, path string, q url.Values) ([]T, error) {
	var out []T
	after := ""
	for range 10000 {
		qq := url.Values{"limit": {"100"}}
		for k, v := range q {
			qq[k] = v
		}
		if after != "" {
			qq.Set("after", after)
		}
		var p page[T]
		if err := s.api.Get(s.ctx, path, qq, &p); err != nil {
			return out, err
		}
		out = append(out, p.Data...)
		if !p.HasMore || p.LastID == nil || *p.LastID == "" || *p.LastID == after {
			return out, nil
		}
		after = *p.LastID
	}
	return out, fmt.Errorf("GET %s: pagination did not end", path)
}

type project struct {
	ID   string  `json:"id"`
	Name *string `json:"name"`
}

func (p project) label() string {
	if p.Name != nil && *p.Name != "" {
		return *p.Name
	}
	return p.ID
}

type owner struct {
	Type string `json:"type"`
	User *struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"user"`
	ServiceAccount *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"service_account"`
}

func (o owner) label() string {
	switch {
	case o.User != nil && o.User.Email != "":
		return o.User.Email
	case o.User != nil:
		return o.User.Name
	case o.ServiceAccount != nil:
		return "service account " + o.ServiceAccount.Name
	}
	return ""
}

type projectKey struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	RedactedValue      string `json:"redacted_value"`
	CreatedAt          *int64 `json:"created_at"`
	LastUsedAt         *int64 `json:"last_used_at"`
	ExpiresAt          *int64 `json:"expires_at"`
	OwnerProjectAccess string `json:"owner_project_access"`
	Owner              owner  `json:"owner"`
}

type adminKey struct {
	ID            string  `json:"id"`
	Name          *string `json:"name"`
	RedactedValue string  `json:"redacted_value"`
	CreatedAt     *int64  `json:"created_at"`
	LastUsedAt    *int64  `json:"last_used_at"`
	ExpiresAt     *int64  `json:"expires_at"`
	Owner         struct {
		Name string `json:"name"`
	} `json:"owner"`
}

// keyHint: OpenAI masks one star per hidden character (an sk-proj redacted_value is as long as
// the key, checked 2026-11-24), so a long run of stars gives the key's length.
func keyHint(redacted string) string {
	n := 0
	if strings.Count(redacted, "*") >= 20 {
		n = len(redacted)
	}
	return secretrisk.Masked(redacted, n)
}

const adminKeyPrefix = "sk-admin"

// splitAdminListing: the admin listing also returns the project keys, and is the only listing
// that carries their last_used_at, kept here by key id.
func splitAdminListing(listed []adminKey) ([]adminKey, map[string]*int64) {
	var admins []adminKey
	lastUsed := map[string]*int64{}
	for _, k := range listed {
		if strings.HasPrefix(k.RedactedValue, adminKeyPrefix) {
			admins = append(admins, k)
			continue
		}
		if k.LastUsedAt != nil {
			lastUsed[k.ID] = k.LastUsedAt
		}
	}
	return admins, lastUsed
}

// limitState: GET .../spend_limit answers 404 when no hard limit is configured.
type limitState struct {
	known       bool
	set         bool
	cents       int64
	enforcement string
}

type spendLimit struct {
	ThresholdAmount int64 `json:"threshold_amount"`
	Enforcement     struct {
		Status string `json:"status"`
	} `json:"enforcement"`
}

func (s *scan) spendLimit(path string) limitState {
	var l spendLimit
	err := s.api.Get(s.ctx, path, nil, &l)
	switch {
	case httpx.IsStatus(err, http.StatusNotFound):
		return limitState{known: true}
	case err != nil:
		s.fail(err)
		return limitState{}
	}
	return limitState{known: true, set: true, cents: l.ThresholdAmount, enforcement: l.Enforcement.Status}
}

type alertState struct {
	known bool
	count int
}

func (s *scan) alerts(path string) alertState {
	alerts, err := list[struct {
		ID string `json:"id"`
	}](s, path, nil)
	if err != nil {
		s.fail(err)
		return alertState{}
	}
	return alertState{known: true, count: len(alerts)}
}

type costPage struct {
	Data []struct {
		Results []struct {
			Amount struct {
				Value float64 `json:"value"`
			} `json:"amount"`
			ProjectID *string `json:"project_id"`
		} `json:"results"`
	} `json:"data"`
	HasMore  bool    `json:"has_more"`
	NextPage *string `json:"next_page"`
}

// costs sums the last 30 days per project id; "" is cost not attributed to a project.
func (s *scan) costs() (map[string]float64, error) {
	out := map[string]float64{}
	q := url.Values{
		"start_time":   {strconv.FormatInt(s.now.Add(-costWindow).Unix(), 10)},
		"end_time":     {strconv.FormatInt(s.now.Unix(), 10)},
		"bucket_width": {"1d"},
		"group_by[]":   {"project_id"},
		"limit":        {"31"},
	}
	for range 1000 {
		var p costPage
		if err := s.api.Get(s.ctx, "/organization/costs", q, &p); err != nil {
			return out, err
		}
		for _, b := range p.Data {
			for _, r := range b.Results {
				id := ""
				if r.ProjectID != nil {
					id = *r.ProjectID
				}
				out[id] += r.Amount.Value
			}
		}
		if !p.HasMore || p.NextPage == nil || *p.NextPage == "" {
			return out, nil
		}
		q.Set("page", *p.NextPage)
	}
	return out, fmt.Errorf("GET /organization/costs: pagination did not end")
}

// budgetSeverity: alerts without a hard limit still let spend run.
func budgetSeverity(l limitState, a alertState) finding.Severity {
	switch {
	case l.set:
		return finding.SevInfo
	case l.known && a.known && a.count == 0:
		return finding.SevHigh
	case l.known && a.count > 0:
		return finding.SevMedium
	}
	return finding.SevLow
}

// emitBudget states the spend risk of the keys a limit covers once, not on each key. keys is -1
// when unknown or not a project.
func (s *scan) emitBudget(res finding.Resource, label string, l limitState, a alertState, cost float64, costKnown bool, keys int) {
	sev := budgetSeverity(l, a)
	ev := map[string]any{"spend_alerts": a.count}
	spent := ""
	if costKnown {
		ev["cost_30d_usd"] = cost
		spent = fmt.Sprintf(" (%s in the last 30 days)", textfmt.USD(cost))
	}
	if keys >= 0 {
		ev["api_keys"] = keys
		if !l.set && keys > 0 {
			spent = fmt.Sprintf(": %d API keys can spend without a cap", keys) + spent
		}
	}
	if l.set {
		ev["hard_limit_usd_per_month"] = float64(l.cents) / 100
		ev["hard_limit_enforcement"] = l.enforcement
	}
	if !a.known {
		delete(ev, "spend_alerts")
	}
	var title string
	switch sev {
	case finding.SevInfo:
		title = fmt.Sprintf("%s has a hard spend limit of %s/month%s", label, textfmt.USD(float64(l.cents)/100), spent)
	case finding.SevHigh:
		title = fmt.Sprintf("%s has no hard spend limit and no spend alerts%s", label, spent)
	case finding.SevMedium:
		title = fmt.Sprintf("%s has spend alerts but no hard spend limit%s", label, spent)
	default:
		title = fmt.Sprintf("%s: spend limit could not be read%s", label, spent)
	}
	s.emit.Finding(finding.Finding{
		Account:  account,
		Resource: res,
		Kind:     finding.KindSpend,
		Severity: sev,
		Title:    title,
		Evidence: ev,
		Blast:    finding.BlastMoney,
		Remediation: finding.Remediation{
			Summary: "Set a monthly hard spend limit and at least one spend alert (organization limits, or the project's Limits page)",
			URL:     limitsURL,
		},
	})
}

type limitCover struct{ known, set bool }

// keyAssessment: OpenAI keys have no spend limit of their own, so a missing project or
// organization limit is that finding's, and only changes the wording here. Without usageKnown a
// key with no recorded use is not called never used.
func keyAssessment(lastUsed, expires *time.Time, usageKnown, ownerGone bool, cover limitCover, now time.Time) httpx.Assessment {
	var a httpx.Assessment
	if expires != nil && expires.Before(now) {
		return a.Done("expired")
	}
	if ownerGone {
		a.Raise(finding.SevHigh, "its owner no longer has access to the project")
	}
	use := "in use"
	switch {
	case lastUsed == nil && !usageKnown:
		use = "last use unknown"
	case lastUsed == nil:
		a.Raise(finding.SevMedium, "never used")
	case now.Sub(*lastUsed) > finding.IdleAfter:
		a.Raise(finding.SevMedium, fmt.Sprintf("unused for %d days", httpx.Days(now, *lastUsed)))
	}
	switch {
	case cover.set:
		return a.Done(use + " and capped by a hard spend limit")
	case cover.known:
		return a.Done(use + "; no hard spend limit caps it (see the project finding)")
	}
	return a.Done(use)
}

func projectKeyFinding(k projectKey, p project, cover limitCover, usageKnown bool, now time.Time) finding.Finding {
	created, lastUsed, expires := httpx.Unix(k.CreatedAt), httpx.Unix(k.LastUsedAt), httpx.Unix(k.ExpiresAt)
	a := keyAssessment(lastUsed, expires, usageKnown, k.OwnerProjectAccess == "inactive", cover, now)
	action := ""
	if usageKnown {
		action = unusedAction(lastUsed, expires, now)
	}
	ev := map[string]any{
		"redacted":   keyHint(k.RedactedValue),
		"project":    p.label(),
		"project_id": p.ID,
		"owner":      k.Owner.label(),
		"issues":     a.Reasons,
	}
	if cover.known {
		ev["spend_capped"] = cover.set
	}
	if k.Owner.Type != "" {
		ev["owner_type"] = k.Owner.Type
	}
	if k.OwnerProjectAccess != "" {
		ev["owner_project_access"] = k.OwnerProjectAccess
	}
	if expires != nil {
		ev["expires_at"] = expires
	}
	return finding.Finding{
		Account:    account,
		Resource:   finding.Resource{Type: "api_key", ID: k.ID, Name: k.Name},
		Kind:       finding.KindCredential,
		Severity:   a.Severity,
		Title:      fmt.Sprintf("API key %q in project %q: %s", k.Name, p.label(), strings.Join(a.Reasons, "; ")),
		Evidence:   ev,
		CreatedAt:  created,
		LastUsedAt: lastUsed,
		Remediation: finding.Remediation{
			Summary: "Revoke keys nobody uses or owns. Spend caps are set on the project or the organization, not on the key.",
			URL:     keysURL,
			Action:  action,
		},
	}
}

// adminKeyFinding: admin keys spend nothing themselves but can mint keys, so idleness matters.
func adminKeyFinding(k adminKey, now time.Time) finding.Finding {
	created, lastUsed, expires := httpx.Unix(k.CreatedAt), httpx.Unix(k.LastUsedAt), httpx.Unix(k.ExpiresAt)
	a := keyAssessment(lastUsed, expires, true, false, limitCover{}, now)
	n := k.ID
	if k.Name != nil && *k.Name != "" {
		n = *k.Name
	}
	ev := map[string]any{"redacted": keyHint(k.RedactedValue), "owner": k.Owner.Name, "issues": a.Reasons}
	if expires != nil {
		ev["expires_at"] = expires
	}
	return finding.Finding{
		Account:    account,
		Resource:   finding.Resource{Type: "admin_api_key", ID: k.ID, Name: n},
		Kind:       finding.KindCredential,
		Severity:   a.Severity,
		Title:      fmt.Sprintf("Admin API key %q: %s", n, strings.Join(a.Reasons, "; ")),
		Evidence:   ev,
		CreatedAt:  created,
		LastUsedAt: lastUsed,
		Remediation: finding.Remediation{
			Summary: "Delete admin keys nobody uses; each one can create and revoke keys for the whole organization",
			URL:     adminURL,
			Action:  unusedAction(lastUsed, expires, now),
		},
	}
}

func (c *Connector) Track(f finding.Finding) *finding.Track { return keytrack.Track("OpenAI", f) }
