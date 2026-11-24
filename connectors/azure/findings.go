package azure

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/budget"
	"github.com/segurata/segurata/internal/finding"
)

const (
	urlBudgets       = "https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets"
	urlBudgetActions = "https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/cost-management-budget-scenario"
	urlSecrets       = "https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials"

	// expiringWithin is when a secret about to lapse needs a rotation plan.
	expiringWithin = 30 * 24 * time.Hour
	// neverExpiresAfter: the Entra portal caps new secrets at 24 months, so anything further out
	// was set through the API to effectively never expire.
	neverExpiresAfter = 2 * 365 * 24 * time.Hour
)

// subscriptionWording is how the shared budget rules speak about an Azure subscription.
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

// budgetFindings judges a subscription's cost budgets with the shared rules. Usage budgets do
// not measure spend and are left out.
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

// neutral maps a cost budget to the shared model; a usage budget maps to the zero Budget. Only
// enabled notifications count. thresholdType is missing from older API versions, whose
// notification keys start with the type ("Forecasted_GreaterThan_100_Percent").
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

// describe words a budget filter as "ResourceGroupName: rg1, rg2" and "tag env: prod".
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

// secretFinding grades one client secret by its expiry. Only the provider's hint (first
// characters) and key id are kept, never the value, which Graph does not return anyway.
func secretFinding(a app, p passwordCredential, now time.Time) finding.Finding {
	name := a.DisplayName
	if p.DisplayName != "" {
		name += " / " + p.DisplayName
	}
	ev := map[string]any{"app_id": a.AppID, "key_id": p.KeyID, "hint": p.Hint}
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
	case end.Sub(now) > neverExpiresAfter:
		f.Severity = finding.SevHigh
		f.Title = fmt.Sprintf("Client secret of app %q never expires in practice (expires %s)", a.DisplayName, day(*end))
	case end.Before(now):
		f.Severity = finding.SevLow
		f.Title = fmt.Sprintf("Client secret of app %q expired on %s and is still registered", a.DisplayName, day(*end))
		f.Remediation.Summary = "Delete the expired secret. `segurata remediate` deletes every expired secret of the tenant in one plan."
		f.Remediation.Action = ActionDeleteExpiredSecrets
	case end.Sub(now) <= expiringWithin:
		f.Severity = finding.SevMedium
		f.Title = fmt.Sprintf("Client secret of app %q expires %s, in %d days", a.DisplayName, day(*end), int(end.Sub(now).Hours()/24))
		f.Remediation.Summary = "Add a new credential, move the app to it and delete this secret before it expires."
	default:
		f.Title = fmt.Sprintf("Client secret of app %q expires %s", a.DisplayName, day(*end))
	}
	return f
}

func day(t time.Time) string {
	return t.UTC().Format(time.DateOnly)
}
