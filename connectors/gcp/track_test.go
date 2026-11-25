package gcp

import (
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestTrack(t *testing.T) {
	c := New()
	key := c.Track(finding.Finding{Account: "me@x.com", Resource: finding.Resource{Type: "api_key"}, Evidence: map[string]any{"project": "shop"}})
	if key.Group != finding.GroupProject || key.Key != "shop" || key.Project != "shop" || key.Title != "Restrict {count} in GCP project shop" {
		t.Errorf("api key %+v", key)
	}
	if role := c.Track(finding.Finding{Account: "me@x.com", Resource: finding.Resource{Type: "service_account_role"}}); role.Key != "me@x.com" || role.Project != "" {
		t.Errorf("no project: %+v", role)
	}
	if b := c.Track(finding.Finding{Resource: finding.Resource{Type: "billing_budget"}, Evidence: map[string]any{"project": "shop"}}); b.Group != "" || b.Project != "shop" {
		t.Errorf("other type %+v", b)
	}
	if b := c.Track(finding.Finding{Resource: finding.Resource{Type: "billing_budget"}}); b != nil {
		t.Errorf("nothing to declare: %+v", b)
	}
}
