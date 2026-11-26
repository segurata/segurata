package vercel

import (
	"fmt"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/finding"
)

const (
	urlTokens          = "https://vercel.com/account/settings/tokens"
	urlSpendManagement = "https://vercel.com/docs/spend-management"
)

func ms(v *int64) *time.Time {
	if v == nil || *v == 0 {
		return nil
	}
	t := time.UnixMilli(*v).UTC()
	return &t
}

func tokenFinding(t token, now time.Time) finding.Finding {
	created, active, expires, leaked := ms(t.CreatedAt), ms(t.ActiveAt), ms(t.ExpiresAt), ms(t.LeakedAt)
	var scopes []string
	for _, s := range t.Scopes {
		scope := s.Type
		if s.TeamID != "" {
			scope += ":" + s.TeamID
		}
		scopes = append(scopes, scope)
	}
	ev := map[string]any{"kind": t.Kind, "type": t.Type, "origin": t.Origin, "scopes": scopes}
	if expires != nil {
		ev["expires_at"] = expires.Format(time.RFC3339)
	}
	f := finding.Finding{
		Resource:   finding.Resource{Type: "vercel_token", ID: t.ID, Name: t.Name},
		Kind:       finding.KindCredential,
		Severity:   finding.SevInfo,
		Title:      fmt.Sprintf("Vercel token %q (%s)", t.Name, t.Kind),
		Evidence:   ev,
		CreatedAt:  created,
		LastUsedAt: active,
		Remediation: finding.Remediation{
			Summary: "Delete tokens nobody uses; give the rest an expiry and the narrowest team scope.",
			URL:     urlTokens,
		},
	}
	switch {
	case leaked != nil:
		f.Severity = finding.SevCritical
		f.Title = fmt.Sprintf("Vercel token %q was reported leaked", t.Name)
		ev["leaked_at"] = leaked.Format(time.RFC3339)
		if t.LeakedURL != "" {
			ev["leaked_url"] = t.LeakedURL
		}
		f.Remediation.Summary = "Revoke the token now and check the team's activity log since the leak date."
	case active != nil && now.Sub(*active) > httpx.IdleAfter:
		f.Severity = finding.SevHigh
		f.Title = fmt.Sprintf("Vercel token %q unused for %d days", t.Name, httpx.Days(now, *active))
	case expires == nil:
		f.Severity = finding.SevMedium
		f.Title = fmt.Sprintf("Vercel token %q never expires", t.Name)
	}
	return f
}

// teamFindings asks for a manual Spend Management check on plans billed by usage: the REST API
// does not expose budgets (verified against https://vercel.com/openapi.json).
func teamFindings(t team) []finding.Finding {
	plan := t.plan()
	ev := map[string]any{"slug": t.Slug, "plan": plan}
	if t.Membership != nil {
		ev["role"] = t.Membership.Role
	}
	out := []finding.Finding{{
		Resource: finding.Resource{Type: "vercel_team", ID: t.ID, Name: t.Name},
		Kind:     finding.KindSetting,
		Severity: finding.SevInfo,
		Title:    fmt.Sprintf("Team %q on the %s plan", t.Name, plan),
		Evidence: ev,
	}}
	if plan == "pro" || plan == "enterprise" {
		out = append(out, finding.Finding{
			Resource: finding.Resource{Type: "vercel_spend_management", ID: t.ID, Name: t.Name},
			Kind:     finding.KindSpend,
			Severity: finding.SevLow,
			Title:    fmt.Sprintf("Check Spend Management on team %q: the API does not expose it", t.Name),
			Evidence: map[string]any{"plan": plan},
			Remediation: finding.Remediation{
				Summary: "In Settings > Billing > Spend Management, set a team budget with \"Pause production deployments\" on; a budget alone only notifies.",
				URL:     urlSpendManagement,
			},
		})
	}
	return out
}
