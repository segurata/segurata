package azure

import (
	"fmt"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

const (
	urlBudgets = "https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets"
	urlSecrets = "https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials"

	// expiringWithin is when a secret about to lapse needs a rotation plan.
	expiringWithin = 30 * 24 * time.Hour
	// neverExpiresAfter: the Entra portal caps new secrets at 24 months, so anything further out
	// was set through the API to effectively never expire.
	neverExpiresAfter = 2 * 365 * 24 * time.Hour
)

func budgetFindings(subscriptionID string, budgets []budget) []finding.Finding {
	if len(budgets) == 0 {
		return []finding.Finding{{
			Resource: finding.Resource{Type: "azure_budget", ID: subscriptionID + "/none", Name: "budgets"},
			Kind:     finding.KindSpend,
			Severity: finding.SevHigh,
			Title:    "Subscription has no budget: nothing warns you when spend runs away",
			Remediation: finding.Remediation{
				Summary: "Create a monthly cost budget with alerts at 50%, 80% and 100% of actual and forecasted cost.",
				URL:     urlBudgets,
			},
		}}
	}
	var out []finding.Finding
	for _, b := range budgets {
		alerts := b.enabledAlerts()
		f := finding.Finding{
			Resource:    finding.Resource{Type: "azure_budget", ID: subscriptionID + "/" + b.Name, Name: b.Name},
			Kind:        finding.KindSpend,
			Severity:    finding.SevInfo,
			Title:       fmt.Sprintf("Budget %q with %d alerts", b.Name, alerts),
			Evidence:    map[string]any{"amount": b.Amount, "time_grain": b.TimeGrain, "enabled_alerts": alerts},
			Remediation: finding.Remediation{Summary: "Keep at least one enabled alert with a contact on the budget.", URL: urlBudgets},
		}
		if alerts == 0 {
			f.Severity = finding.SevMedium
			f.Title = fmt.Sprintf("Budget %q has no enabled alerts", b.Name)
		}
		out = append(out, f)
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
	ev := map[string]any{"app_id": a.AppID, "key_id": p.KeyID}
	if p.Hint != "" { // Graph's hint is the secret's first characters; it gives no length
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
