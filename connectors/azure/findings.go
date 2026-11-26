package azure

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/budget"
	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

const (
	urlBudgets       = "https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets"
	urlBudgetActions = "https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/cost-management-budget-scenario"
	urlSecrets       = "https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials"

	expiringWithin = 30 * 24 * time.Hour
)

// portalMaxEnd is the latest expiry the Entra portal allows, 24 months from creation, plus a day
// of clock and timezone margin: anything later was set through the API to never expire in practice.
func portalMaxEnd(now time.Time) time.Time { return now.AddDate(2, 0, 1) }

var subscriptionWording = budget.Wording{
	AllScope:   "whole subscription",
	DocsURL:    urlBudgets,
	ActionNoun: "an action group",
	CapHowTo: "Budgets only notify. Add an action group to the budget's 100% alert that calls a Logic App or " +
		"Automation runbook to stop or deallocate resources when the threshold is crossed.",
	CapURL:     urlBudgetActions,
	RisksWhere: "in the tenant",
}

var timeGrains = map[string]string{
	"Monthly": budget.PeriodMonth, "BillingMonth": budget.PeriodMonth,
	"Quarterly": budget.PeriodQuarter, "BillingQuarter": budget.PeriodQuarter,
	"Annually": budget.PeriodYear, "BillingAnnual": budget.PeriodYear,
}

func budgetFindings(subscriptionID, label string, budgets []azBudget, risks []budget.Risk) []finding.Finding {
	var nb []budget.Budget
	for _, b := range budgets {
		if n := b.neutral(); n.ID != "" {
			nb = append(nb, n)
		}
	}
	c := budget.Container{
		ID:       subscriptionID,
		Label:    "subscription " + label,
		Risks:    risks,
		NoBudget: finding.Resource{Type: "azure_budget", ID: subscriptionID + "/none", Name: "budgets"},
	}
	return budget.Evaluate(c, nb, subscriptionWording)
}

// neutral maps a usage budget, which does not measure spend, to the zero Budget. Older API
// versions have no thresholdType: their notification keys start with it
// ("Forecasted_GreaterThan_100_Percent").
func (b azBudget) neutral() budget.Budget {
	p := b.budgetProps
	if b.Properties != nil {
		p = *b.Properties
	}
	if p.Category != "" && p.Category != "Cost" {
		return budget.Budget{}
	}
	nb := budget.Budget{ID: b.Name, Name: b.Name, Amount: p.Amount, Period: budget.PeriodCustom}
	if g, ok := timeGrains[p.TimeGrain]; ok {
		nb.Period = g
	}
	if p.CurrentSpend != nil {
		nb.Currency = p.CurrentSpend.Unit
	}
	if p.Filter != nil {
		nb.Scope.Filters = p.Filter.describe()
	}
	notifies := map[string]bool{}
	for _, key := range slices.Sorted(maps.Keys(p.Notifications)) {
		n := p.Notifications[key]
		if !n.Enabled {
			continue
		}
		forecast := n.ThresholdType == "Forecasted" || (n.ThresholdType == "" && strings.HasPrefix(strings.ToLower(key), "forecasted"))
		nb.Thresholds = append(nb.Thresholds, budget.Threshold{Percent: n.Threshold, Forecast: forecast})
		notifies[budget.NotifyEmails] = notifies[budget.NotifyEmails] || len(n.ContactEmails) > 0
		notifies[budget.NotifyRoles] = notifies[budget.NotifyRoles] || len(n.ContactRoles) > 0
		notifies[budget.NotifyActionGroup] = notifies[budget.NotifyActionGroup] || len(n.ContactGroups) > 0
	}
	for _, k := range []string{budget.NotifyEmails, budget.NotifyRoles, budget.NotifyActionGroup} {
		if notifies[k] {
			nb.Notifies = append(nb.Notifies, k)
		}
	}
	if notifies[budget.NotifyActionGroup] {
		nb.Actions = []string{budget.ActionActionGroup}
	}
	return nb
}

func (f budgetFilter) describe() []string {
	var out []string
	if d := f.Dimensions; d != nil {
		out = append(out, d.Name+": "+strings.Join(d.Values, ", "))
	}
	if t := f.Tags; t != nil {
		out = append(out, "tag "+t.Name+": "+strings.Join(t.Values, ", "))
	}
	for _, sub := range f.And {
		out = append(out, sub.describe()...)
	}
	return out
}

func secretFinding(a app, p passwordCredential, now time.Time) finding.Finding {
	name := a.DisplayName
	if p.DisplayName != "" {
		name += " / " + p.DisplayName
	}
	ev := map[string]any{"app_id": a.AppID, "key_id": p.KeyID}
	if p.Hint != "" { // the secret's first characters, without its length
		ev["hint"] = secretrisk.Hint{Prefix: p.Hint}.String()
	}
	if p.EndDateTime != nil {
		ev["expires_at"] = p.EndDateTime.UTC().Format(time.RFC3339)
	}
	f := finding.Finding{
		Resource:  finding.Resource{Type: "azure_app_secret", ID: a.AppID + "/" + p.KeyID, Name: name},
		Kind:      finding.KindCredential,
		Severity:  finding.SevInfo,
		Evidence:  ev,
		CreatedAt: p.StartDateTime,
		Remediation: finding.Remediation{
			Summary: "Prefer certificates or federated credentials; otherwise keep secrets short-lived and rotate before expiry.",
			URL:     urlSecrets,
		},
	}
	switch end := p.EndDateTime; {
	case end == nil:
		f.Severity = finding.SevHigh
		f.Title = fmt.Sprintf("Client secret of app %q has no expiry date", a.DisplayName)
	case end.After(portalMaxEnd(now)):
		f.Severity = finding.SevHigh
		f.Title = fmt.Sprintf("Client secret of app %q never expires in practice (expires %s)", a.DisplayName, day(*end))
	case end.Before(now):
		f.Severity = finding.SevLow
		f.Title = fmt.Sprintf("Client secret of app %q expired on %s and is still registered", a.DisplayName, day(*end))
		f.Remediation.Summary = "Delete the expired secret. `segurata remediate` deletes every expired secret of the tenant in one plan."
		f.Remediation.Action = ActionDeleteExpiredSecrets
	case end.Sub(now) <= expiringWithin:
		f.Severity = finding.SevMedium
		f.Title = fmt.Sprintf("Client secret of app %q expires %s, in %d days", a.DisplayName, day(*end), httpx.Days(*end, now))
		f.Remediation.Summary = "Add a new credential, move the app to it and delete this secret before it expires."
	default:
		f.Title = fmt.Sprintf("Client secret of app %q expires %s", a.DisplayName, day(*end))
	}
	return f
}

func day(t time.Time) string {
	return t.UTC().Format(time.DateOnly)
}
