package supabase

import (
	"fmt"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/finding"
)

const (
	urlCostControl = "https://supabase.com/docs/guides/platform/cost-control"
	urlAPIKeys     = "https://supabase.com/docs/guides/api/api-keys"
)

// orgFindings records the plan and, where usage can be billed beyond quota, asks for a manual
// spend cap check: the Management API does not expose it (verified against
// https://api.supabase.com/api/v1-json).
func orgFindings(o organization) []finding.Finding {
	out := []finding.Finding{{
		Resource: finding.Resource{Type: "supabase_organization", ID: o.Slug, Name: o.Name},
		Kind:     finding.KindSetting,
		Severity: finding.SevInfo,
		Title:    fmt.Sprintf("Organization %q on the %s plan", o.Name, o.Plan),
		Evidence: map[string]any{"plan": o.Plan},
	}}
	if o.Plan != "free" && o.Plan != "" {
		out = append(out, finding.Finding{
			Resource: finding.Resource{Type: "supabase_spend_cap", ID: o.Slug, Name: o.Name},
			Kind:     finding.KindSpend,
			Severity: finding.SevLow,
			Title:    fmt.Sprintf("Check the spend cap of organization %q: the API does not expose it", o.Name),
			Evidence: map[string]any{"plan": o.Plan},
			Remediation: finding.Remediation{
				Summary: "In the organization's Billing > Cost Control, keep the Spend Cap on unless you need overage, and watch usage.",
				URL:     urlCostControl,
			},
		})
	}
	return out
}

// keyFinding lists one API key by name and type. Legacy service_role keys are long-lived JWTs that
// bypass Row Level Security and cannot be revoked one by one, so they are worth migrating.
func keyFinding(p project, k apiKey) finding.Finding {
	typ := "unknown"
	if k.Type != nil {
		typ = *k.Type
	}
	id := k.ID
	if id == "" {
		id = typ + ":" + k.Name
	}
	f := finding.Finding{
		Resource:  finding.Resource{Type: "supabase_api_key", ID: p.Ref + "/" + id, Name: p.Name + " / " + k.Name},
		Kind:      finding.KindCredential,
		Severity:  finding.SevInfo,
		Title:     fmt.Sprintf("API key %q (%s) of project %q", k.Name, typ, p.Name),
		Evidence:  map[string]any{"project_ref": p.Ref, "type": typ, "region": p.Region, "project_status": p.Status},
		CreatedAt: httpx.ParseTime(k.InsertedAt),
		Remediation: finding.Remediation{
			Summary: "Keep secret keys server-side only and rotate them when someone with access leaves.",
			URL:     urlAPIKeys,
		},
	}
	if typ == "legacy" && k.Name == "service_role" {
		f.Severity = finding.SevMedium
		f.Title = fmt.Sprintf("Project %q still has the legacy service_role key enabled", p.Name)
		f.Remediation.Summary = "Create secret API keys, move server code to them and disable the legacy JWT-based keys."
	}
	return f
}
