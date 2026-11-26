package gcp

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/budget"
	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/finding"
)

type apiKey struct {
	Name         string        `json:"name"`
	UID          string        `json:"uid"`
	DisplayName  string        `json:"displayName"`
	CreateTime   string        `json:"createTime"`
	Restrictions *restrictions `json:"restrictions"`
}

type restrictions struct {
	Browser    any `json:"browserKeyRestrictions"`
	Server     any `json:"serverKeyRestrictions"`
	Android    any `json:"androidKeyRestrictions"`
	IOS        any `json:"iosKeyRestrictions"`
	APITargets []struct {
		Service string `json:"service"`
	} `json:"apiTargets"`
}

type serviceAccount struct {
	Email    string `json:"email"`
	Disabled bool   `json:"disabled"`
}

type saKey struct {
	Name           string `json:"name"`
	KeyType        string `json:"keyType"`
	ValidAfterTime string `json:"validAfterTime"`
	ValidBefore    string `json:"validBeforeTime"`
	Disabled       bool   `json:"disabled"`
}

type iamPolicy struct {
	Bindings []struct {
		Role    string   `json:"role"`
		Members []string `json:"members"`
	} `json:"bindings"`
}

type billingInfo struct {
	BillingAccountName string `json:"billingAccountName"`
	BillingEnabled     bool   `json:"billingEnabled"`
}

type billingAccount struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	Open         bool   `json:"open"`
	CurrencyCode string `json:"currencyCode"`
}

type gcpBudget struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	BudgetFilter struct {
		Projects          []string       `json:"projects"`
		ResourceAncestors []string       `json:"resourceAncestors"`
		Services          []string       `json:"services"`
		Subaccounts       []string       `json:"subaccounts"`
		Labels            map[string]any `json:"labels"`
		CalendarPeriod    string         `json:"calendarPeriod"`
		CustomPeriod      any            `json:"customPeriod"`
	} `json:"budgetFilter"`
	Amount struct {
		SpecifiedAmount *struct {
			CurrencyCode string `json:"currencyCode"`
			Units        string `json:"units"`
			Nanos        int64  `json:"nanos"`
		} `json:"specifiedAmount"`
		LastPeriodAmount any `json:"lastPeriodAmount"`
	} `json:"amount"`
	ThresholdRules []struct {
		ThresholdPercent float64 `json:"thresholdPercent"`
		SpendBasis       string  `json:"spendBasis"`
	} `json:"thresholdRules"`
	NotificationsRule struct {
		PubsubTopic                    string   `json:"pubsubTopic"`
		MonitoringNotificationChannels []string `json:"monitoringNotificationChannels"`
		DisableDefaultIamRecipients    bool     `json:"disableDefaultIamRecipients"`
		EnableProjectLevelRecipients   bool     `json:"enableProjectLevelRecipients"`
	} `json:"notificationsRule"`
	SpendCap *struct {
		InputState  string `json:"inputState"`
		OutputState string `json:"outputState"`
	} `json:"spendCap"`
}

func consoleURL(path, project string) string {
	return fmt.Sprintf("https://console.cloud.google.com/%s?project=%s", path, project)
}

func lastSegment(name string) string {
	return name[strings.LastIndexByte(name, '/')+1:]
}

// apiKeyFindings never sees a key string: `api-keys list` does not return it.
func apiKeyFindings(account, project string, keys []apiKey) []finding.Finding {
	var out []finding.Finding
	for _, k := range keys {
		uid := k.UID
		if uid == "" {
			uid = lastSegment(k.Name)
		}
		var apis []string
		appRestricted := false
		if r := k.Restrictions; r != nil {
			for _, t := range r.APITargets {
				apis = append(apis, t.Service)
			}
			appRestricted = r.Browser != nil || r.Server != nil || r.Android != nil || r.IOS != nil
		}
		var missing []string
		if len(apis) == 0 {
			missing = append(missing, "API restrictions")
		}
		if !appRestricted {
			missing = append(missing, "application restrictions")
		}
		name := k.DisplayName
		if name == "" {
			name = "(unnamed)"
		}
		f := finding.Finding{
			ID:        finding.StableID(connectorName, account, "api_key", project+"/"+uid),
			Account:   account,
			Resource:  finding.Resource{Type: "api_key", ID: finding.Redact(uid), Name: name},
			Kind:      finding.KindCredential,
			Severity:  finding.SevInfo,
			Title:     fmt.Sprintf("API key %q in %s is restricted", name, project),
			CreatedAt: httpx.ParseTime(&k.CreateTime),
			Evidence:  map[string]any{"project": project, "api_targets": apis, "application_restricted": appRestricted},
			Remediation: finding.Remediation{
				Summary: "Nothing to do. Review now and then that the key is still in use.",
				URL:     consoleURL("apis/credentials", project),
			},
		}
		if len(missing) > 0 {
			f.Severity = finding.SevHigh
			f.Title = fmt.Sprintf("API key %q in %s has no %s", name, project, strings.Join(missing, " and no "))
			f.Remediation.Summary = "Add an API restriction (only the APIs the key calls) and an application restriction " +
				"(HTTP referrers, IP addresses, Android or iOS apps). If nothing uses the key, delete it."
		}
		out = append(out, f)
	}
	return out
}

func saKeyFindings(account, project string, sa serviceAccount, keys []saKey, now time.Time) []finding.Finding {
	var out []finding.Finding
	for _, k := range keys {
		if k.KeyType != "" && k.KeyType != "USER_MANAGED" {
			continue
		}
		id := lastSegment(k.Name)
		created := httpx.ParseTime(&k.ValidAfterTime)
		sev, title := finding.SevMedium, fmt.Sprintf("Service account %s has a user-managed key", sa.Email)
		var ageDays int
		if created != nil {
			ageDays = httpx.Days(now, *created)
			if now.Sub(*created) > finding.IdleAfter {
				sev, title = finding.SevHigh, fmt.Sprintf("Service account %s has a user-managed key %d days old", sa.Email, ageDays)
			}
		}
		if k.Disabled {
			sev, title = finding.SevLow, fmt.Sprintf("Service account %s has a disabled user-managed key", sa.Email)
		}
		ev := map[string]any{"project": project, "service_account": sa.Email, "key_id": id,
			"valid_after_time": k.ValidAfterTime, "key_disabled": k.Disabled, "service_account_disabled": sa.Disabled}
		if created != nil {
			ev["age_days"] = ageDays
		}
		if k.ValidBefore != "" && !strings.HasPrefix(k.ValidBefore, "9999") {
			ev["valid_before_time"] = k.ValidBefore
		}
		out = append(out, finding.Finding{
			Account:   account,
			Resource:  finding.Resource{Type: "service_account_key", ID: project + "/" + sa.Email + "/" + id, Name: sa.Email},
			Kind:      finding.KindCredential,
			Severity:  sev,
			Title:     title,
			Evidence:  ev,
			CreatedAt: created,
			Remediation: finding.Remediation{
				Summary: "A downloaded key never expires on its own. Find what uses it, move that workload to attached " +
					"service accounts, impersonation or Workload Identity Federation, then delete the key.",
				URL: consoleURL("iam-admin/serviceaccounts", project),
			},
		})
	}
	return out
}

var broadRoles = map[string]bool{"roles/owner": true, "roles/editor": true}

// googleManaged reports service agents Google grants Editor itself and the owner cannot change
// (system.gserviceaccount.com owns every Apps Script default project). The default Compute Engine
// and App Engine accounts are not among them: Google advises taking Editor away from those.
func googleManaged(email string) bool {
	local, domain, _ := strings.Cut(email, "@")
	if domain == "cloudservices.gserviceaccount.com" || domain == "system.gserviceaccount.com" || strings.HasPrefix(domain, "gcp-sa-") {
		return true
	}
	digits, ok := strings.CutPrefix(local, "service-")
	return ok && digits != "" && strings.Trim(digits, "0123456789") == ""
}

func iamFindings(account, project string, p iamPolicy) []finding.Finding {
	roles := map[string][]string{}
	for _, b := range p.Bindings {
		if !broadRoles[b.Role] {
			continue
		}
		for _, m := range b.Members {
			email, ok := strings.CutPrefix(m, "serviceAccount:")
			if !ok || googleManaged(email) {
				continue
			}
			roles[email] = append(roles[email], b.Role)
		}
	}
	var out []finding.Finding
	for _, e := range slices.Sorted(maps.Keys(roles)) {
		rs := roles[e]
		sort.Strings(rs)
		short := make([]string, len(rs))
		for i, r := range rs {
			short[i] = strings.TrimPrefix(r, "roles/")
		}
		out = append(out, finding.Finding{
			Account:  account,
			Resource: finding.Resource{Type: "service_account_role", ID: project + "/" + e, Name: e},
			Kind:     finding.KindCredential,
			Severity: finding.SevHigh,
			Title:    fmt.Sprintf("Service account %s is %s of project %s", e, strings.Join(short, " and "), project),
			Evidence: map[string]any{"project": project, "service_account": e, "roles": rs},
			Remediation: finding.Remediation{
				Summary: "Replace the basic role with predefined roles that cover only what the workload does " +
					"(the IAM role recommender suggests them from real usage).",
				URL: consoleURL("iam-admin/iam", project),
			},
		})
	}
	return out
}

type linkedProject struct {
	id, number string
	risks      []budget.Risk
}

func projectIDs(ps []linkedProject) []string {
	ids := make([]string, len(ps))
	for i, p := range ps {
		ids[i] = p.id
	}
	sort.Strings(ids)
	return ids
}

// neutral maps a Budget API budget to the shared model. ids maps the project numbers the filter
// names to ids; currency is the billing account's.
func (b gcpBudget) neutral(currency string, ids map[string]string) budget.Budget {
	nb := budget.Budget{ID: lastSegment(b.Name), Name: b.DisplayName, Currency: currency, Period: budget.PeriodMonth}
	if nb.Name == "" {
		nb.Name = nb.ID
	}
	if a := b.Amount.SpecifiedAmount; a != nil {
		units, _ := strconv.ParseFloat(a.Units, 64)
		nb.Amount = units + float64(a.Nanos)/1e9
		if a.CurrencyCode != "" {
			nb.Currency = a.CurrencyCode
		}
	}
	nb.LastPeriod = b.Amount.LastPeriodAmount != nil
	f := b.BudgetFilter
	switch {
	case f.CustomPeriod != nil:
		nb.Period = budget.PeriodCustom
	case f.CalendarPeriod == "QUARTER":
		nb.Period = budget.PeriodQuarter
	case f.CalendarPeriod == "YEAR":
		nb.Period = budget.PeriodYear
	}
	for _, p := range f.Projects {
		p = strings.TrimPrefix(p, "projects/")
		if id, ok := ids[p]; ok {
			p = id
		}
		nb.Scope.Units = append(nb.Scope.Units, p)
	}
	// Folders and organizations narrow what is counted but are not taken as leaving a project out.
	nb.Scope.Filters = append(nb.Scope.Filters, f.ResourceAncestors...)
	var detail []string
	for _, list := range []struct {
		noun  string
		items []string
	}{{"service", f.Services}, {"subaccount", f.Subaccounts}} {
		if len(list.items) == 0 {
			continue
		}
		sorted := slices.Sorted(slices.Values(list.items))
		if len(sorted) <= 2 {
			nb.Scope.Filters = append(nb.Scope.Filters, list.noun+"s "+strings.Join(sorted, ", "))
			continue
		}
		nb.Scope.Filters = append(nb.Scope.Filters, fmt.Sprintf("%d %ss", len(sorted), list.noun))
		detail = append(detail, sorted...)
	}
	nb.Scope.Detail = strings.Join(detail, ",")
	for _, k := range slices.Sorted(maps.Keys(f.Labels)) {
		nb.Scope.Filters = append(nb.Scope.Filters, fmt.Sprintf("label %s=%v", k, f.Labels[k]))
	}
	for _, t := range b.ThresholdRules {
		nb.Thresholds = append(nb.Thresholds, budget.Threshold{Percent: t.ThresholdPercent * 100, Forecast: t.SpendBasis == "FORECASTED_SPEND"})
	}
	n := b.NotificationsRule
	if !n.DisableDefaultIamRecipients {
		nb.Notifies = append(nb.Notifies, budget.NotifyAdmins)
	}
	if n.EnableProjectLevelRecipients && len(f.Projects) == 1 {
		nb.Notifies = append(nb.Notifies, budget.NotifyProject)
	}
	if len(n.MonitoringNotificationChannels) > 0 {
		nb.Notifies = append(nb.Notifies, budget.NotifyMonitoring)
	}
	if n.PubsubTopic != "" {
		nb.Notifies = append(nb.Notifies, budget.NotifyPubSub)
		nb.Actions = append(nb.Actions, budget.ActionPubSub)
	}
	if c := b.SpendCap; c != nil && (c.InputState == "CONFIGURED" || c.OutputState == "CONFIGURED" || c.OutputState == "ENFORCED") {
		nb.Actions = append(nb.Actions, budget.ActionSpendCap)
	}
	return nb
}

func billingWording(billingID string) budget.Wording {
	return budget.Wording{
		UnitNoun:   "project",
		AllScope:   "all projects",
		ConsoleURL: "https://console.cloud.google.com/billing/" + billingID + "/budgets",
		DocsURL:    "https://cloud.google.com/billing/docs/how-to/budgets",
		ActionNoun: "a Pub/Sub topic or a spend cap",
		CapHowTo: "Budgets only email. To stop spend, publish a budget's notifications to a Pub/Sub topic and deploy the " +
			"function from Google's guide that removes billing from the project when the budget is exceeded. It shuts " +
			"down every service in the project and some resources may not come back, so try it on a test budget first.",
		CapURL:     "https://cloud.google.com/billing/docs/how-to/disable-billing-with-notifications",
		RisksWhere: "in projects billed here",
	}
}

func billingFindings(account, billingID, currency string, budgets []gcpBudget, linked []linkedProject, ids map[string]string) []finding.Finding {
	c := budget.Container{
		ID:       billingID,
		Label:    "billing account " + billingID,
		Units:    projectIDs(linked),
		NoBudget: finding.Resource{Type: "billing_account", ID: billingID, Name: billingID},
	}
	for _, p := range linked {
		c.Risks = append(c.Risks, p.risks...)
	}
	nb := make([]budget.Budget, len(budgets))
	for i, b := range budgets {
		nb[i] = b.neutral(currency, ids)
	}
	fs := budget.Evaluate(c, nb, billingWording(billingID))
	for i := range fs {
		fs[i].Account = account
		if fs[i].Evidence == nil {
			fs[i].Evidence = map[string]any{}
		}
		fs[i].Evidence["billing_account"] = billingID
	}
	return fs
}

// projectRisks counts what lets someone run spend up: unrestricted API keys and enabled
// user-managed service account keys.
func projectRisks(project string, fs []finding.Finding) []budget.Risk {
	var keys, saKeys int
	for _, f := range fs {
		switch {
		case f.Resource.Type == "api_key" && f.Severity == finding.SevHigh:
			keys++
		case f.Resource.Type == "service_account_key" && f.Severity != finding.SevLow:
			saKeys++
		}
	}
	var out []budget.Risk
	if keys > 0 {
		out = append(out, budget.Risk{Unit: project, What: "unrestricted API key", Count: keys})
	}
	if saKeys > 0 {
		out = append(out, budget.Risk{Unit: project, What: "user-managed service account key", Count: saKeys})
	}
	return out
}
