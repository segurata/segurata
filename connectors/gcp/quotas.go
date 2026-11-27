package gcp

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// ActionCapQuota sets a per-day cap, from connectors.gcp.config.quota_caps, on the request quotas
// of a pay-per-use API that has none of its own.
const ActionCapQuota = "gcp.quota.cap"

// costServices are pay-per-use APIs a runaway client or a stolen key bills by the request: the Maps
// Platform APIs (Places, Geocoding, Directions, Maps Static, Maps JavaScript, Routes; names from
// each API's "Set up in the Cloud console" page), the Gemini API, Vertex AI, Cloud Translation,
// Vision, Speech-to-Text, Text-to-Speech and Document AI. Kept short on purpose: a cap on an API
// outside it is the owner's call.
var costServices = []string{
	"places.googleapis.com",
	"geocoding-backend.googleapis.com",
	"directions-backend.googleapis.com",
	"static-maps-backend.googleapis.com",
	"maps-backend.googleapis.com",
	"routes.googleapis.com",
	"generativelanguage.googleapis.com",
	"aiplatform.googleapis.com",
	"translate.googleapis.com",
	"vision.googleapis.com",
	"speech.googleapis.com",
	"texttospeech.googleapis.com",
	"documentai.googleapis.com",
}

const quotasHost = "cloudquotas.googleapis.com"

type enabledService struct {
	Name   string `json:"name"`
	Config struct {
		Name string `json:"name"`
	} `json:"config"`
}

func (s enabledService) service() string { return cmp.Or(s.Config.Name, lastSegment(s.Name)) }

// quotaInfo is a Cloud Quotas QuotaInfo; DimensionsInfos[].details.value is the limit in effect.
type quotaInfo struct {
	QuotaID         string `json:"quotaId"`
	Metric          string `json:"metric"`
	RefreshInterval string `json:"refreshInterval"`
	IsConcurrent    bool   `json:"isConcurrent"`
	IsFixed         bool   `json:"isFixed"`
	DimensionsInfos []struct {
		Dimensions map[string]string `json:"dimensions"`
		Details    struct {
			Value string `json:"value"`
		} `json:"details"`
	} `json:"dimensionsInfos"`
}

// quotaPreference is a Cloud Quotas QuotaPreference: the value the project asked for.
type quotaPreference struct {
	Name        string            `json:"name"`
	Service     string            `json:"service"`
	QuotaID     string            `json:"quotaId"`
	Dimensions  map[string]string `json:"dimensions"`
	QuotaConfig struct {
		PreferredValue string `json:"preferredValue"`
		TraceID        string `json:"traceId"`
	} `json:"quotaConfig"`
}

const unlimited = "-1"

// requests reports a request-rate quota a cap can lower: not concurrent, not fixed, counting
// requests.
func (q quotaInfo) requests() bool {
	return !q.IsConcurrent && !q.IsFixed && strings.Contains(strings.ToLower(q.QuotaID+" "+q.Metric), "request")
}

// limit is the value in effect for every dimension value without one of its own.
func (q quotaInfo) limit() string {
	for _, d := range q.DimensionsInfos {
		if len(d.Dimensions) == 0 {
			return d.Details.Value
		}
	}
	return ""
}

// quotaLimit is one request quota of a service and the project's own preference for it.
type quotaLimit struct {
	id, interval, value string
	pref                *quotaPreference // dimensionless preference, if any
}

// capped: a preference of the project's own with a finite value. One Google recorded a trace id
// for is an increase request (the trace id "is only produced for increase requests"), not a cap.
func (l quotaLimit) capped() bool {
	return l.pref != nil && l.pref.QuotaConfig.PreferredValue != unlimited && l.pref.QuotaConfig.TraceID == ""
}

func shownValue(v string) string {
	switch v {
	case unlimited:
		return "unlimited"
	case "":
		return "unknown"
	}
	return v
}

func (l quotaLimit) String() string {
	if l.capped() {
		return l.id + " capped at " + shownValue(l.pref.QuotaConfig.PreferredValue)
	}
	return l.id + " " + shownValue(l.value)
}

// serviceQuotas are a service's per-day request quotas, or its per-minute ones when it has none
// per day.
type serviceQuotas struct {
	service string
	daily   bool
	limits  []quotaLimit
}

func (s serviceQuotas) uncapped() []quotaLimit {
	var out []quotaLimit
	for _, l := range s.limits {
		if !l.capped() {
			out = append(out, l)
		}
	}
	return out
}

// quotaParent is the Cloud Quotas container of a project, by number when known as Google's
// examples name it.
func quotaParent(project, number string) string {
	return "projects/" + cmp.Or(number, project) + "/locations/global"
}

// listAll reads every page of a Cloud Quotas list into the array under field.
func listAll[T any](ctx context.Context, api *httpx.Client, path, field string) ([]T, error) {
	var out []T
	q := url.Values{}
	for {
		var page map[string]json.RawMessage
		if err := api.Get(ctx, path, q, &page); err != nil {
			return nil, err
		}
		if raw, ok := page[field]; ok {
			var items []T
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, fmt.Errorf("GET %s: unexpected %s: %w", path, field, err)
			}
			out = append(out, items...)
		}
		var next string
		if raw, ok := page["nextPageToken"]; ok {
			_ = json.Unmarshal(raw, &next)
		}
		if next == "" {
			return out, nil
		}
		q.Set("pageToken", next)
	}
}

// readQuotas reads, for each service, its request quotas and the project's preferences for them.
func (g *gcloud) readQuotas(ctx context.Context, account, project, number string, services []string) ([]serviceQuotas, error) {
	api, err := g.api(ctx, quotasHost, account, g.userProject(project))
	if err != nil {
		return nil, err
	}
	parent := "/v1/" + quotaParent(project, number)
	prefs, err := listAll[quotaPreference](ctx, api, parent+"/quotaPreferences", "quotaPreferences")
	if err != nil {
		return nil, err
	}
	var out []serviceQuotas
	for _, svc := range services {
		infos, err := listAll[quotaInfo](ctx, api, parent+"/services/"+url.PathEscape(svc)+"/quotaInfos", "quotaInfos")
		if err != nil {
			return nil, err
		}
		byInterval := map[string][]quotaLimit{}
		for _, q := range infos {
			if !q.requests() || (q.RefreshInterval != "day" && q.RefreshInterval != "minute") {
				continue
			}
			l := quotaLimit{id: q.QuotaID, interval: q.RefreshInterval, value: q.limit()}
			for i, p := range prefs {
				if p.Service == svc && p.QuotaID == q.QuotaID && len(p.Dimensions) == 0 {
					l.pref = &prefs[i]
				}
			}
			byInterval[q.RefreshInterval] = append(byInterval[q.RefreshInterval], l)
		}
		sq := serviceQuotas{service: svc, daily: true, limits: byInterval["day"]}
		if len(sq.limits) == 0 {
			sq.daily, sq.limits = false, byInterval["minute"]
		}
		if len(sq.limits) > 0 {
			slices.SortFunc(sq.limits, func(a, b quotaLimit) int { return strings.Compare(a.id, b.id) })
			out = append(out, sq)
		}
	}
	return out, nil
}

// quotaScope holds the quota findings, so a project whose quotas cannot be read leaves its other
// findings checked.
func quotaScope(project string) string { return "quotas:" + project }

func quotaCapKey(service string) string { return `connectors.gcp.config.quota_caps."` + service + `"` }

func quotaFindings(account, project, number string, sqs []serviceQuotas) []finding.Finding {
	var out []finding.Finding
	for _, sq := range sqs {
		per := "per-day"
		if !sq.daily {
			per = "per-minute"
		}
		var shown []string
		for _, l := range sq.limits {
			shown = append(shown, l.String())
		}
		ev := map[string]any{"project": project, "service": sq.service, "interval": strings.TrimPrefix(per, "per-"), "quotas": shown}
		if number != "" {
			ev["project_number"] = number
		}
		f := finding.Finding{
			Account:  account,
			Resource: finding.Resource{Type: "api_quota", ID: project + "/" + sq.service, Name: sq.service},
			Kind:     finding.KindSpend,
			Severity: finding.SevInfo,
			Title:    fmt.Sprintf("%s in %s has a %s request cap of its own: %s", sq.service, project, per, strings.Join(shown, ", ")),
			Evidence: ev,
			Remediation: finding.Remediation{
				Summary: "Nothing to do. Check now and then that the cap still fits the app's traffic.",
				URL:     consoleURL("iam-admin/quotas", project),
			},
		}
		if uncapped := sq.uncapped(); len(uncapped) > 0 {
			shown = shown[:0]
			for _, l := range uncapped {
				shown = append(shown, l.String())
			}
			f.Severity = finding.SevMedium
			f.Title = fmt.Sprintf("%s in %s has no %s request cap below Google's default: %s", sq.service, project, per, strings.Join(shown, ", "))
			f.Remediation.Summary = "A quota is the most the API can bill: lower the per-day request quota to what the app needs, " +
				"so a runaway loop or a stolen key stops there (requests fail for the rest of the day). Set " +
				quotaCapKey(sq.service) + " to the requests per day you allow and segurata remediate sets it."
			f.Remediation.Action = ActionCapQuota
			if !sq.daily {
				f.Remediation.Summary = "This API has a per-minute request quota and none per day. Lower it in the console to what " +
					"the app needs; segurata caps per-day quotas only."
				f.Remediation.Action = ""
			}
		}
		out = append(out, f)
	}
	return out
}

// quotaInventory reports the request caps of the pay-per-use APIs the project has enabled. A
// failure is a status of quotaScope.
func (c *Connector) quotaInventory(ctx context.Context, g *gcloud, t target, emit connector.Emitter) {
	fail := func(what string, err error) {
		state, why := classify(err)
		emit.Status(finding.Status{Account: t.accounts[0], Scope: quotaScope(t.project), State: state,
			Detail: "project " + t.project + ": cannot tell which pay-per-use APIs have a request cap: " + what + ": " + why})
	}
	var enabled []enabledService
	a, err := t.firstAnswer(func(a string) error {
		return g.json(ctx, &enabled, "services", "list", "--enabled", "--project="+t.project, "--account="+a)
	})
	if err != nil {
		fail("services list", err)
		return
	}
	var services []string
	for _, s := range enabled {
		if slices.Contains(costServices, s.service()) {
			services = append(services, s.service())
		}
	}
	if len(services) == 0 {
		return
	}
	slices.Sort(services)
	sqs, err := g.readQuotas(ctx, a, t.project, t.number, services)
	if err != nil {
		fail("Cloud Quotas", err)
		return
	}
	for _, f := range quotaFindings(t.accounts[0], t.project, t.number, sqs) {
		f.Scope = quotaScope(t.project)
		emit.Finding(f)
	}
}

// preferenceID names the preference a cap creates: fixed, so the undo can name it.
func preferenceID(quotaID string) string {
	var b strings.Builder
	b.WriteString("segurata-")
	for _, r := range strings.ToLower(quotaID) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	id := b.String()
	return id[:min(len(id), 63)]
}

func (r *remediator) capPlan(ctx context.Context, g *gcloud, cfg settings, f finding.Finding) (connector.Plan, error) {
	project, err := evidenceString(f, "project")
	if err != nil {
		return connector.Plan{}, err
	}
	svc, err := evidenceString(f, "service")
	if err != nil {
		return connector.Plan{}, err
	}
	limit, ok := cfg.quotaCaps[svc]
	if !ok {
		return connector.Plan{}, fmt.Errorf("refused: no cap configured for %s. Set %s to the requests per day the app needs at most "+
			"(segurata never guesses an amount), then plan again", svc, quotaCapKey(svc))
	}
	number, _ := f.Evidence["project_number"].(string)
	sqs, err := g.readQuotas(ctx, f.Account, project, number, []string{svc})
	if err != nil {
		_, why := classify(err)
		return connector.Plan{}, fmt.Errorf("Cloud Quotas in %s: %s", project, why)
	}
	if len(sqs) == 0 || !sqs[0].daily {
		return connector.Plan{}, fmt.Errorf("nothing to do: %s in %s has no per-day request quota now", svc, project)
	}
	capValue := fmt.Sprint(limit)
	p := connector.Plan{Action: ActionCapQuota}
	var capped, left []string
	for _, l := range sqs[0].uncapped() {
		if v, err := strconv.ParseInt(l.value, 10, 64); err == nil && l.value != unlimited && v <= limit {
			left = append(left, fmt.Sprintf("Left out: %s is already %s a day, at or below the cap.", l.id, l.value))
			continue
		}
		common := []string{"--service=" + svc, "--quota-id=" + l.id}
		projectFlag := "--project=" + project
		var id, was string
		if l.pref != nil {
			id, was = lastSegment(l.pref.Name), cmp.Or(l.pref.QuotaConfig.PreferredValue, unlimited)
			p.Commands = append(p.Commands, g.step(append(append([]string{"quotas", "preferences", "update", id}, common...),
				"--preferred-value="+capValue, projectFlag, "--allow-high-percentage-quota-decrease", "--account="+f.Account)...))
		} else {
			id, was = preferenceID(l.id), cmp.Or(l.value, unlimited)
			p.Commands = append(p.Commands, g.step(append(append([]string{"quotas", "preferences", "create"}, common...),
				"--preferred-value="+capValue, projectFlag, "--preference-id="+id, "--allow-high-percentage-quota-decrease", "--account="+f.Account)...))
		}
		p.Undo = append(p.Undo, g.step(append(append([]string{"quotas", "preferences", "update", id}, common...),
			"--preferred-value="+was, projectFlag, "--account="+f.Account)...))
		capped = append(capped, fmt.Sprintf("%s (now %s)", l.id, shownValue(l.value)))
	}
	if len(p.Commands) == 0 {
		return connector.Plan{}, fmt.Errorf("nothing to do: every per-day request quota of %s in %s is capped or already at or below %d", svc, project, limit)
	}
	p.Summary = fmt.Sprintf("Cap %s in %s at %d requests per day: %s.", svc, project, limit, strings.Join(capped, ", "))
	p.SideEffects = append([]string{
		"When the project reaches the cap, requests to this API fail for the rest of the day; daily quotas reset at midnight Pacific time. Set it above the busiest day's traffic.",
		"--allow-high-percentage-quota-decrease lets the cap lower the limit by more than 10%, which any real cap on a default does. A cap below today's usage is still refused by Google (no --allow-quota-decrease-below-usage).",
		"Undo: Cloud Quotas cannot delete a quota preference, so the undo sets it back to the limit it had. Google treats that as an increase: it may ask for --email and take time to approve it.",
	}, left...)
	return p, nil
}
