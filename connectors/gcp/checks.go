package gcp

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/finding"
)

// Shapes of the gcloud --format=json outputs this connector reads. Only the fields it uses.

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
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Open        bool   `json:"open"`
}

type budget struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	BudgetFilter struct {
		Projects []string `json:"projects"`
	} `json:"budgetFilter"`
	ThresholdRules []struct {
		ThresholdPercent float64 `json:"thresholdPercent"`
	} `json:"thresholdRules"`
	NotificationsRule struct {
		PubsubTopic                    string   `json:"pubsubTopic"`
		MonitoringNotificationChannels []string `json:"monitoringNotificationChannels"`
		DisableDefaultIamRecipients    bool     `json:"disableDefaultIamRecipients"`
	} `json:"notificationsRule"`
}

func consoleURL(path, project string) string {
	return fmt.Sprintf("https://console.cloud.google.com/%s?project=%s", path, project)
}

// lastSegment returns what follows the last slash of a resource name.
func lastSegment(name string) string {
	return name[strings.LastIndexByte(name, '/')+1:]
}

// apiKeyFindings flags keys missing API restrictions or application restrictions. It never sees
// the key string: `api-keys list` does not return it, and get-key-string is not allowed.
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

// saKeyFindings flags user-managed service account keys: medium, high when older than 90 days.
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
			if now.Sub(*created) > httpx.IdleAfter {
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

// broadRoles are the basic roles that give a service account control of the whole project.
var broadRoles = map[string]bool{"roles/owner": true, "roles/editor": true}

// googleManaged reports service agents that Google itself grants Editor to and that cannot hold
// user keys. The default Compute Engine and App Engine accounts are not skipped: Google advises
// taking Editor away from them.
func googleManaged(email string) bool {
	local, domain, _ := strings.Cut(email, "@")
	if domain == "cloudservices.gserviceaccount.com" || strings.HasPrefix(domain, "gcp-sa-") {
		return true
	}
	digits, ok := strings.CutPrefix(local, "service-")
	return ok && digits != "" && strings.Trim(digits, "0123456789") == ""
}

// iamFindings flags service accounts holding Owner or Editor on the project.
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

// alerting reports whether a budget would notify someone when a threshold is crossed.
func (b budget) alerting() bool {
	if len(b.ThresholdRules) == 0 {
		return false
	}
	n := b.NotificationsRule
	return !n.DisableDefaultIamRecipients || n.PubsubTopic != "" || len(n.MonitoringNotificationChannels) > 0
}

// covers reports whether the budget includes usage from the project. A budget with no project
// filter covers the whole billing account; filters name projects by number or id.
func (b budget) covers(projectID, projectNumber string) bool {
	if len(b.BudgetFilter.Projects) == 0 {
		return true
	}
	for _, p := range b.BudgetFilter.Projects {
		p = strings.TrimPrefix(p, "projects/")
		if p == projectID || (projectNumber != "" && p == projectNumber) {
			return true
		}
	}
	return false
}

type linkedProject struct{ id, number string }

// projectIDs returns the sorted ids of the linked projects.
func projectIDs(ps []linkedProject) []string {
	ids := make([]string, len(ps))
	for i, p := range ps {
		ids[i] = p.id
	}
	sort.Strings(ids)
	return ids
}

// billingFindings judges one billing account: no alerting budget at all is one high finding for
// the account; otherwise each linked project that no alerting budget covers is high.
func billingFindings(account, billingID string, budgets []budget, linked []linkedProject) []finding.Finding {
	var alerting []budget
	for _, b := range budgets {
		if b.alerting() {
			alerting = append(alerting, b)
		}
	}
	ids := projectIDs(linked)
	rem := finding.Remediation{
		Summary: "Create a budget on the billing account with threshold alerts (for example 50%, 90% and 100%) " +
			"so someone is emailed before the bill grows. A budget alerts, it does not cap spend.",
		URL: "https://cloud.google.com/billing/docs/how-to/budgets",
	}
	accountRes := finding.Resource{Type: "billing_account", ID: billingID, Name: billingID}
	if len(alerting) == 0 {
		return []finding.Finding{{
			Account:     account,
			Resource:    accountRes,
			Kind:        finding.KindSpend,
			Severity:    finding.SevHigh,
			Title:       fmt.Sprintf("Billing account %s has no budget with alerts", billingID),
			Evidence:    map[string]any{"billing_account": billingID, "budgets": len(budgets), "linked_projects": ids},
			Remediation: rem,
		}}
	}
	out := []finding.Finding{{
		Account:     account,
		Resource:    accountRes,
		Kind:        finding.KindSpend,
		Severity:    finding.SevInfo,
		Title:       fmt.Sprintf("Billing account %s has %d budget(s) with alerts", billingID, len(alerting)),
		Evidence:    map[string]any{"billing_account": billingID, "budgets": len(budgets), "alerting_budgets": len(alerting), "linked_projects": ids},
		Remediation: finding.Remediation{Summary: "Nothing to do.", URL: rem.URL},
	}}
	for _, p := range linked {
		if slices.ContainsFunc(alerting, func(b budget) bool { return b.covers(p.id, p.number) }) {
			continue
		}
		out = append(out, finding.Finding{
			Account:  account,
			Resource: finding.Resource{Type: "project_budget", ID: billingID + "/" + p.id, Name: p.id},
			Kind:     finding.KindSpend,
			Severity: finding.SevHigh,
			Title:    fmt.Sprintf("Project %s is billed to %s but no budget with alerts covers it", p.id, billingID),
			Evidence: map[string]any{"billing_account": billingID, "project": p.id},
			Remediation: finding.Remediation{
				Summary: "Add this project to an existing budget's scope, or create a budget for it with threshold alerts.",
				URL:     rem.URL,
			},
		})
	}
	return out
}
