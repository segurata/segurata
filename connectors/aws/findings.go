package aws

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/budget"
	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

const (
	urlRootMFA       = "https://docs.aws.amazon.com/IAM/latest/UserGuide/enable-mfa-for-root.html"
	urlRootKeys      = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_delete-key.html"
	urlAccessKeys    = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
	urlUserMFA       = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html"
	urlBudgets       = "https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-create.html"
	urlBudgetActions = "https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-controls.html"
	urlAnomaly       = "https://docs.aws.amazon.com/cost-management/latest/userguide/getting-started-ad.html"
	urlSSO           = "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html"
	urlConfigFiles   = "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html"
	urlR2Tokens      = "https://dash.cloudflare.com/?to=/:account/r2/overview"
)

func rootProfileFinding(profile string) finding.Finding {
	return finding.Finding{
		Resource: finding.Resource{Type: "aws_root_profile", ID: profile, Name: profile},
		Kind:     finding.KindCredential,
		Severity: finding.SevCritical,
		Title:    fmt.Sprintf("AWS CLI profile %q signs in as the root user", profile),
		Remediation: finding.Remediation{
			Summary: "Delete the root access key and use an IAM Identity Center (SSO) profile for the CLI.",
			URL:     urlRootKeys,
		},
	}
}

func rootFindings(summary map[string]int) []finding.Finding {
	var out []finding.Finding
	if summary["AccountMFAEnabled"] == 0 {
		out = append(out, finding.Finding{
			Resource:    finding.Resource{Type: "aws_root_mfa", ID: "root", Name: "root user"},
			Kind:        finding.KindSetting,
			Severity:    finding.SevCritical,
			Title:       "Root user has no MFA",
			Evidence:    map[string]any{"AccountMFAEnabled": summary["AccountMFAEnabled"]},
			Remediation: finding.Remediation{Summary: "Enable MFA on the root user, ideally a passkey or hardware key.", URL: urlRootMFA},
		})
	}
	if n := summary["AccountAccessKeysPresent"]; n > 0 {
		out = append(out, finding.Finding{
			Resource:    finding.Resource{Type: "aws_root_access_keys", ID: "root", Name: "root user"},
			Kind:        finding.KindCredential,
			Severity:    finding.SevCritical,
			Title:       "Root user has access keys",
			Evidence:    map[string]any{"AccountAccessKeysPresent": n},
			Remediation: finding.Remediation{Summary: "Delete the root user's access keys; nothing should call AWS as root.", URL: urlRootKeys},
		})
	}
	return out
}

func keyFinding(user string, k accessKey, lastUsed *time.Time, now time.Time) finding.Finding {
	created := k.CreateDate
	age := httpx.Days(now, created)
	f := finding.Finding{
		Resource:   finding.Resource{Type: "aws_access_key", ID: k.AccessKeyId, Name: user},
		Kind:       finding.KindCredential,
		Severity:   finding.SevInfo,
		Title:      fmt.Sprintf("Access key of IAM user %s (%d days old)", user, age),
		Evidence:   map[string]any{"key_id": secretrisk.RedactID(awsKeyPrefixes, k.AccessKeyId), "status": k.Status, "age_days": age},
		CreatedAt:  &created,
		LastUsedAt: lastUsed,
		Remediation: finding.Remediation{
			Summary: "Rotate access keys at least every 90 days and delete keys nobody uses; prefer SSO or roles over long-lived keys.",
			URL:     urlAccessKeys,
		},
	}
	switch {
	case k.Status != "Active":
		f.Severity = finding.SevLow
		f.Title = fmt.Sprintf("Inactive access key of IAM user %s still exists (%d days old)", user, age)
	case lastUsed == nil && now.Sub(created) > finding.IdleAfter:
		f.Severity = finding.SevHigh
		f.Title = fmt.Sprintf("Access key of IAM user %s has never been used (%d days old)", user, age)
	case lastUsed != nil && now.Sub(*lastUsed) > finding.IdleAfter:
		f.Severity = finding.SevHigh
		f.Title = fmt.Sprintf("Access key of IAM user %s unused for %d days", user, httpx.Days(now, *lastUsed))
	case now.Sub(created) > finding.IdleAfter:
		f.Severity = finding.SevHigh
		f.Title = fmt.Sprintf("Access key of IAM user %s is %d days old", user, age)
	}
	return f
}

func userMFAFinding(user string, console bool, mfaDevices int) (finding.Finding, bool) {
	if !console || mfaDevices > 0 {
		return finding.Finding{}, false
	}
	return finding.Finding{
		Resource:    finding.Resource{Type: "aws_user_mfa", ID: user, Name: user},
		Kind:        finding.KindSetting,
		Severity:    finding.SevHigh,
		Title:       fmt.Sprintf("IAM user %s signs in to the console without MFA", user),
		Remediation: finding.Remediation{Summary: "Assign an MFA device to the user or remove its console password.", URL: urlUserMFA},
	}, true
}

var accountWording = budget.Wording{
	AllScope:   "whole account",
	ConsoleURL: "https://console.aws.amazon.com/billing/home#/budgets",
	DocsURL:    urlBudgets,
	ActionNoun: "a budget action",
	CapHowTo: "Budgets only notify. Add a budget action that, at 100% of actual or forecasted spend, applies an IAM " +
		"policy or SCP denying new resources, or stops chosen EC2 or RDS instances, automatically or after your approval.",
	CapURL:     urlBudgetActions,
	RisksWhere: "in this account",
}

func accountContainer(accountID, label string, activeKeys, rootKeys int) budget.Container {
	return budget.Container{
		ID:       accountID,
		Label:    "account " + label,
		Risks:    []budget.Risk{{What: "active IAM user access key", Count: activeKeys}, {What: "root access key", Count: rootKeys}},
		NoBudget: finding.Resource{Type: "aws_budget", ID: "none", Name: "budgets"},
	}
}

var timeUnits = map[string]string{"DAILY": budget.PeriodDay, "MONTHLY": budget.PeriodMonth, "QUARTERLY": budget.PeriodQuarter, "ANNUALLY": budget.PeriodYear}

// neutral: every AWS notification has at least one subscriber, of a kind not read; LESS_THAN
// notifications do not warn of overspend.
func (b awsBudget) neutral(ns []notification) budget.Budget {
	nb := budget.Budget{ID: b.BudgetName, Name: b.BudgetName, Period: budget.PeriodCustom}
	if p, ok := timeUnits[b.TimeUnit]; ok {
		nb.Period = p
	}
	if l := b.BudgetLimit; l != nil {
		nb.Amount, _ = strconv.ParseFloat(l.Amount, 64)
		nb.Currency = l.Unit
	}
	for _, k := range slices.Sorted(maps.Keys(b.CostFilters)) {
		nb.Scope.Filters = append(nb.Scope.Filters, k+": "+strings.Join(b.CostFilters[k], ", "))
	}
	if raw := strings.TrimSpace(string(b.FilterExpression)); raw != "" && raw != "{}" && raw != "null" {
		nb.Scope.Filters = append(nb.Scope.Filters, "cost filter")
		nb.Scope.Detail = raw
	}
	for _, n := range ns {
		if n.ComparisonOperator == "LESS_THAN" {
			continue
		}
		pct := n.Threshold
		if n.ThresholdType == "ABSOLUTE_VALUE" {
			if nb.Amount <= 0 {
				continue
			}
			pct = n.Threshold / nb.Amount * 100
		}
		nb.Thresholds = append(nb.Thresholds, budget.Threshold{Percent: pct, Forecast: n.NotificationType == "FORECASTED"})
	}
	if len(nb.Thresholds) > 0 {
		nb.Notifies = []string{budget.NotifySubscribers}
	}
	return nb
}

func monthToDateFinding(amount, unit string, start time.Time) finding.Finding {
	return finding.Finding{
		Resource: finding.Resource{Type: "aws_spend_month_to_date", ID: start.Format("2006-01"), Name: start.Format("2006-01")},
		Kind:     finding.KindSpend,
		Severity: finding.SevInfo,
		Title:    fmt.Sprintf("Month-to-date spend: %s %s", amount, unit),
		Evidence: map[string]any{"amount": amount, "unit": unit, "metric": "UnblendedCost"},
	}
}

func noAnomalyMonitorFinding() finding.Finding {
	return finding.Finding{
		Resource:    finding.Resource{Type: "aws_anomaly_monitor", ID: "none", Name: "Cost Anomaly Detection"},
		Kind:        finding.KindSpend,
		Severity:    finding.SevMedium,
		Title:       "No Cost Anomaly Detection monitor",
		Remediation: finding.Remediation{Summary: "Create a services monitor with an email subscription.", URL: urlAnomaly},
	}
}
