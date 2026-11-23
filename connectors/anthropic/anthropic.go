// Package anthropic inventories a Claude Console organization through the Admin API: API keys and
// whether anyone still owns or uses them, workspaces, and the last 30 days of cost per workspace.
// Endpoints and their documentation are listed in docs/ai-connectors.md.
package anthropic

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
	name           = "anthropic"
	secretName     = "ANTHROPIC_ADMIN_KEY"
	DefaultBaseURL = "https://api.anthropic.com"
	apiVersion     = "2026-10-21"
	costWindow     = 30 * 24 * time.Hour

	keysURL   = "https://platform.claude.com/settings/keys"
	limitsURL = "https://platform.claude.com/settings/limits"
	adminURL  = "https://platform.claude.com/settings/admin-keys"
	day       = 24 * time.Hour
)

const setupHint = "set " + secretName + ": create an Admin API key at " + adminURL +
	`, store it with: security add-generic-password -s securizame-anthropic-admin -a "$USER" -w` +
	` and reference it as "keychain:securizame-anthropic-admin" under connectors.anthropic.secrets in ~/.config/securizame/config.json (docs/ai-connectors.md)`

// Connector is the built-in Anthropic connector. Zero values use the real API and clock.
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
		Summary:  "Anthropic API keys, owners, recent use, workspaces and 30-day cost",
		Needs:    []string{"secret:" + secretName},
	}
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	key := req.Secrets[secretName]
	if key == "" {
		emit.Status(finding.Status{Account: "organization", State: finding.StateMissingCredentials, Detail: setupHint})
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
		ctx:     ctx,
		api:     httpx.New(base, http.Header{"X-Api-Key": {key}, "Anthropic-Version": {apiVersion}}),
		emit:    emit,
		now:     now().UTC(),
		account: "organization",
	}
	s.run()
	return nil
}

type scan struct {
	ctx     context.Context
	api     *httpx.Client
	emit    connector.Emitter
	now     time.Time
	account string
	failed  bool
}

func (s *scan) fail(err error) {
	s.failed = true
	s.emit.Status(finding.Status{Account: s.account, State: finding.StateError, Detail: err.Error()})
}

func (s *scan) run() {
	var org struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := s.api.Get(s.ctx, "/v1/organizations/me", nil, &org); err != nil {
		s.fail(err) // most likely a wrong or non-admin key; nothing else will work either
		return
	}
	if org.Name != "" {
		s.account = org.Name
	} else if org.ID != "" {
		s.account = org.ID
	}

	// Archived workspaces still hold keys, so list them too, or those keys show a bare id.
	workspaces, err := list[workspace](s, "/v1/organizations/workspaces", url.Values{"include_archived": {"true"}})
	if err != nil {
		s.fail(err)
	}
	wsName := map[string]string{}
	for _, w := range workspaces {
		wsName[w.ID] = w.Name
		if w.ArchivedAt != nil {
			wsName[w.ID] = w.Name + " (archived)"
		}
	}
	users, err := list[struct {
		ID string `json:"id"`
	}](s, "/v1/organizations/users", nil)
	members := map[string]bool{}
	if err != nil {
		s.fail(err)
		members = nil // unknown: do not call anyone's key orphaned
	}
	for _, u := range users {
		members[u.ID] = true
	}
	lastUse, usageErr := s.lastUsePerKey()
	if usageErr != nil {
		s.fail(usageErr)
		lastUse = nil
	}
	keys, err := list[apiKey](s, "/v1/organizations/api_keys", nil)
	if err != nil {
		s.fail(err)
	}
	for _, k := range keys {
		if k.Status == "archived" || k.Status == "expired" {
			continue // can no longer authenticate
		}
		s.emit.Finding(s.keyFinding(k, wsName, members, lastUse))
	}

	costs, err := s.costPerWorkspace()
	if err != nil {
		s.fail(err)
	} else {
		s.emitSpend(workspaces, costs)
	}
	if !s.failed {
		s.emit.Status(finding.Status{Account: s.account, State: finding.StateOK})
	}
}

// page is the Admin API's cursor list envelope.
type page[T any] struct {
	Data    []T     `json:"data"`
	HasMore bool    `json:"has_more"`
	LastID  *string `json:"last_id"`
}

// list follows after_id=last_id until has_more is false.
func list[T any](s *scan, path string, q url.Values) ([]T, error) {
	var out []T
	after := ""
	for range 10000 {
		qq := url.Values{"limit": {"1000"}}
		for k, v := range q {
			qq[k] = v
		}
		if after != "" {
			qq.Set("after_id", after)
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

// report pages a usage or cost report through next_page.
func report[T any](s *scan, path string, q url.Values, each func(start time.Time, results []T)) error {
	for range 1000 {
		var p struct {
			Data []struct {
				StartingAt string `json:"starting_at"`
				Results    []T    `json:"results"`
			} `json:"data"`
			HasMore  bool    `json:"has_more"`
			NextPage *string `json:"next_page"`
		}
		if err := s.api.Get(s.ctx, path, q, &p); err != nil {
			return err
		}
		for _, b := range p.Data {
			start := httpx.ParseTime(&b.StartingAt)
			if start == nil {
				return fmt.Errorf("GET %s: bucket with unreadable starting_at %q", path, b.StartingAt)
			}
			each(*start, b.Results)
		}
		if !p.HasMore || p.NextPage == nil || *p.NextPage == "" {
			return nil
		}
		q.Set("page", *p.NextPage)
	}
	return fmt.Errorf("GET %s: pagination did not end", path)
}

type workspace struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	CreatedAt  string  `json:"created_at"`
	ArchivedAt *string `json:"archived_at"`
}

type apiKey struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Status         string  `json:"status"`
	CreatedAt      *string `json:"created_at"`
	ExpiresAt      *string `json:"expires_at"`
	PartialKeyHint *string `json:"partial_key_hint"`
	CreatedBy      *struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"created_by"`
	Principal *struct {
		Type             string `json:"type"`
		UserID           string `json:"user_id"`
		ServiceAccountID string `json:"service_account_id"`
	} `json:"principal"`
	Scope struct {
		Type        string `json:"type"`
		WorkspaceID string `json:"workspace_id"`
	} `json:"scope"`
}

// usageWindow is how far back key usage is read: the idle threshold plus a margin of one day.
func usageWindow() time.Duration { return httpx.IdleAfter + day }

// lastUsePerKey reads the daily usage report grouped by API key and keeps, per key, the start of
// the latest day with any tokens. A key missing from the map had no usage in the window.
func (s *scan) lastUsePerKey() (map[string]time.Time, error) {
	type row struct {
		APIKeyID      *string `json:"api_key_id"`
		Uncached      int64   `json:"uncached_input_tokens"`
		CacheRead     int64   `json:"cache_read_input_tokens"`
		Output        int64   `json:"output_tokens"`
		CacheCreation struct {
			OneHour  int64 `json:"ephemeral_1h_input_tokens"`
			FiveMins int64 `json:"ephemeral_5m_input_tokens"`
		} `json:"cache_creation"`
		ServerToolUse struct {
			WebSearch int64 `json:"web_search_requests"`
		} `json:"server_tool_use"`
	}
	out := map[string]time.Time{}
	q := url.Values{
		"starting_at":  {s.now.Add(-usageWindow()).Truncate(day).Format(time.RFC3339)},
		"ending_at":    {s.now.Format(time.RFC3339)},
		"bucket_width": {"1d"},
		"group_by[]":   {"api_key_id"},
		"limit":        {"31"},
	}
	err := report(s, "/v1/organizations/usage_report/messages", q, func(start time.Time, rows []row) {
		for _, r := range rows {
			used := r.Uncached + r.CacheRead + r.Output + r.CacheCreation.OneHour + r.CacheCreation.FiveMins + r.ServerToolUse.WebSearch
			if r.APIKeyID == nil || used == 0 {
				continue
			}
			if start.After(out[*r.APIKeyID]) {
				out[*r.APIKeyID] = start
			}
		}
	})
	return out, err
}

// costPerWorkspace sums the cost report (cents as decimal strings) per workspace in USD.
// The default workspace is reported with a null workspace_id, kept here as "".
func (s *scan) costPerWorkspace() (map[string]float64, error) {
	type row struct {
		Amount      string  `json:"amount"`
		WorkspaceID *string `json:"workspace_id"`
	}
	out := map[string]float64{}
	q := url.Values{
		"starting_at": {s.now.Add(-costWindow).Format(time.RFC3339)},
		"ending_at":   {s.now.Format(time.RFC3339)},
		"group_by[]":  {"workspace_id"},
		"limit":       {"31"},
	}
	var parseErr error
	err := report(s, "/v1/organizations/cost_report", q, func(_ time.Time, rows []row) {
		for _, r := range rows {
			cents, err := strconv.ParseFloat(r.Amount, 64)
			if err != nil {
				parseErr = fmt.Errorf("cost report: unreadable amount %q", r.Amount)
				continue
			}
			id := ""
			if r.WorkspaceID != nil {
				id = *r.WorkspaceID
			}
			out[id] += cents / 100
		}
	})
	if err == nil {
		err = parseErr
	}
	return out, err
}

// keyAssessment applies the severity rules. Anthropic has no per-key spend limit, so the
// "no limit" rule does not apply; ownership and use do. members or lastUse nil means unknown.
func keyAssessment(k apiKey, created *time.Time, members map[string]bool, lastUse map[string]time.Time, now time.Time) httpx.Assessment {
	var a httpx.Assessment
	if k.Status != "active" {
		return a.Done(k.Status + " key")
	}
	// A workspace key (no principal) keeps working after whoever created it leaves.
	if members != nil && k.Principal == nil && k.CreatedBy != nil && k.CreatedBy.Type == "user" && !members[k.CreatedBy.ID] {
		a.Raise(finding.SevHigh, "created by someone who is no longer in the organization")
	}
	if lastUse != nil {
		if last, ok := lastUse[k.ID]; ok {
			if now.Sub(last) > httpx.IdleAfter {
				a.Raise(finding.SevMedium, fmt.Sprintf("unused for %d days", httpx.Days(now, last)))
			}
		} else if created != nil && now.Sub(*created) <= usageWindow() {
			a.Raise(finding.SevMedium, "never used")
		} else {
			a.Raise(finding.SevMedium, "no use in the last 90 days")
		}
	}
	return a.Done("active; Anthropic exposes no per-key spend limit")
}

func (s *scan) keyFinding(k apiKey, wsName map[string]string, members map[string]bool, lastUse map[string]time.Time) finding.Finding {
	created := httpx.ParseTime(k.CreatedAt)
	a := keyAssessment(k, created, members, lastUse, s.now)
	ev := map[string]any{"status": k.Status, "issues": a.Reasons, "scope": k.Scope.Type}
	if k.PartialKeyHint != nil {
		ev["redacted"] = *k.PartialKeyHint
	}
	where := "all workspaces"
	if k.Scope.WorkspaceID != "" {
		ev["workspace_id"] = k.Scope.WorkspaceID
		where = k.Scope.WorkspaceID
		if n := wsName[k.Scope.WorkspaceID]; n != "" {
			ev["workspace"] = n
			where = n
		}
	}
	if k.CreatedBy != nil {
		ev["created_by"] = k.CreatedBy.Type + ":" + k.CreatedBy.ID
	} else {
		ev["created_by"] = "not recorded"
	}
	if k.Principal != nil {
		ev["acts_as"] = k.Principal.Type + ":" + k.Principal.UserID + k.Principal.ServiceAccountID
	}
	if e := httpx.ParseTime(k.ExpiresAt); e != nil {
		ev["expires_at"] = e
	}
	// The usage report gives the last day with tokens, not a last-used timestamp, so LastUsedAt
	// stays nil and the day goes into the evidence.
	if t, ok := lastUse[k.ID]; ok {
		ev["last_usage_day"] = t.Format("2006-01-02")
	}
	return finding.Finding{
		Account:   s.account,
		Resource:  finding.Resource{Type: "api_key", ID: k.ID, Name: k.Name},
		Kind:      finding.KindCredential,
		Severity:  a.Severity,
		Title:     fmt.Sprintf("API key %q in %s: %s", k.Name, where, strings.Join(a.Reasons, "; ")),
		Evidence:  ev,
		CreatedAt: created,
		Remediation: finding.Remediation{
			Summary: "Archive keys nobody uses or owns; set a spend limit on each workspace in the Console",
			URL:     keysURL,
		},
	}
}

// emitSpend reports 30-day cost for the organization and each workspace. Spend limits for Claude
// Console organizations are not readable through the Admin API, so these stay low: look in Limits.
func (s *scan) emitSpend(workspaces []workspace, costs map[string]float64) {
	const note = "spend limits are not readable through the Admin API"
	remediation := finding.Remediation{
		Summary: "Check the organization and each workspace has a spend limit and notifications set in the Console",
		URL:     limitsURL,
	}
	var total float64
	for _, v := range costs {
		total += v
	}
	s.emit.Finding(finding.Finding{
		Account:     s.account,
		Resource:    finding.Resource{Type: "organization", ID: "organization", Name: s.account},
		Kind:        finding.KindSpend,
		Severity:    finding.SevLow,
		Title:       fmt.Sprintf("Anthropic organization spent %s in the last 30 days; %s", httpx.USD(total), note),
		Evidence:    map[string]any{"cost_30d_usd": total, "spend_limit": "not exposed by the API"},
		Remediation: remediation,
	})
	type ws struct{ id, name string }
	all := []ws{{"", "Default workspace"}}
	for _, w := range workspaces {
		all = append(all, ws{w.ID, w.Name})
	}
	for _, w := range all {
		cost := costs[w.id]
		sev := finding.SevInfo
		if cost > 0 {
			sev = finding.SevLow
		}
		id := w.id
		if id == "" {
			id = "default"
		}
		s.emit.Finding(finding.Finding{
			Account:     s.account,
			Resource:    finding.Resource{Type: "workspace", ID: id, Name: w.name},
			Kind:        finding.KindSpend,
			Severity:    sev,
			Title:       fmt.Sprintf("Workspace %q spent %s in the last 30 days; %s", w.name, httpx.USD(cost), note),
			Evidence:    map[string]any{"cost_30d_usd": cost, "spend_limit": "not exposed by the API"},
			Remediation: remediation,
		})
	}
}
