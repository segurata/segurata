package aws

import (
	"fmt"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

const (
	urlRootMFA     = "https://docs.aws.amazon.com/IAM/latest/UserGuide/enable-mfa-for-root.html"
	urlRootKeys    = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_delete-key.html"
	urlAccessKeys  = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
	urlUserMFA     = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html"
	urlBudgets     = "https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-create.html"
	urlAnomaly     = "https://docs.aws.amazon.com/cost-management/latest/userguide/getting-started-ad.html"
	urlSSO         = "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html"
	urlConfigFiles = "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html"
	urlR2Tokens    = "https://dash.cloudflare.com/?to=/:account/r2/overview"
)

func days(d time.Duration) int { return int(d.Hours() / 24) }

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

// rootFindings reads the root user's state from `iam get-account-summary`.
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

// keyFinding grades one IAM access key by status, age and last use.
func keyFinding(user string, k accessKey, lastUsed *time.Time, now time.Time) finding.Finding {
	created := k.CreateDate
	age := days(now.Sub(created))
	f := finding.Finding{
		Resource:   finding.Resource{Type: "aws_access_key", ID: k.AccessKeyId, Name: user},
		Kind:       finding.KindCredential,
		Severity:   finding.SevInfo,
		Title:      fmt.Sprintf("Access key of IAM user %s (%d days old)", user, age),
		Evidence:   map[string]any{"key_id": finding.Redact(k.AccessKeyId), "status": k.Status, "age_days": age},
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
	case lastUsed == nil && now.Sub(created) > staleAfter:
		f.Severity = finding.SevHigh
		f.Title = fmt.Sprintf("Access key of IAM user %s has never been used (%d days old)", user, age)
	case lastUsed != nil && now.Sub(*lastUsed) > staleAfter:
		f.Severity = finding.SevHigh
		f.Title = fmt.Sprintf("Access key of IAM user %s unused for %d days", user, days(now.Sub(*lastUsed)))
	case now.Sub(created) > staleAfter:
		f.Severity = finding.SevHigh
		f.Title = fmt.Sprintf("Access key of IAM user %s is %d days old", user, age)
	}
	return f
}

// userMFAFinding flags users who can sign in to the console without a second factor.
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

func noBudgetFinding() finding.Finding {
	return finding.Finding{
		Resource: finding.Resource{Type: "aws_budget", ID: "none", Name: "budgets"},
		Kind:     finding.KindSpend,
		Severity: finding.SevHigh,
		Title:    "No AWS budget: nothing warns you when spend runs away",
		Remediation: finding.Remediation{
			Summary: "Create a monthly cost budget with email alerts at 50%, 80% and 100% (actual) and 100% (forecasted).",
			URL:     urlBudgets,
		},
	}
}

func budgetFinding(b budget, notifications int) finding.Finding {
	ev := map[string]any{"type": b.BudgetType, "time_unit": b.TimeUnit, "notifications": notifications}
	if b.BudgetLimit != nil {
		ev["limit"] = b.BudgetLimit.Amount + " " + b.BudgetLimit.Unit
	}
	f := finding.Finding{
		Resource:    finding.Resource{Type: "aws_budget", ID: b.BudgetName, Name: b.BudgetName},
		Kind:        finding.KindSpend,
		Severity:    finding.SevInfo,
		Title:       fmt.Sprintf("Budget %q with %d alerts", b.BudgetName, notifications),
		Evidence:    ev,
		Remediation: finding.Remediation{Summary: "Keep at least one actual and one forecasted alert on the budget.", URL: urlBudgets},
	}
	if notifications == 0 {
		f.Severity = finding.SevMedium
		f.Title = fmt.Sprintf("Budget %q has no alerts", b.BudgetName)
	}
	return f
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
