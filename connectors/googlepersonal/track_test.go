package googlepersonal

import (
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestTrack(t *testing.T) {
	g := GooglePersonal{}.Track(finding.Finding{Account: "me@gmail.com", Severity: finding.SevLow, Resource: finding.Resource{Type: "oauth_grant"}})
	if g.Group != finding.GroupAccountSeverity || g.Kind != finding.TrackReview || g.Title != "Review {count} with limited access to me@gmail.com" {
		t.Errorf("grant %+v", g)
	}
	if (GooglePersonal{}).Track(finding.Finding{Resource: finding.Resource{Type: "account_setting"}}) != nil {
		t.Error("only grants group")
	}
}
