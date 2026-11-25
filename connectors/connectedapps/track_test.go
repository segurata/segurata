package connectedapps

import (
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestTrack(t *testing.T) {
	var c Connector
	slack := c.Track(finding.Finding{Account: "slack:acme", Severity: finding.SevHigh, Resource: finding.Resource{Type: "slack_app", Name: "Zapier"}})
	if slack.Group != finding.GroupAccountSeverity || slack.Kind != finding.TrackReview || slack.Title != "Review {count} with broad permissions in acme" {
		t.Errorf("slack %+v", slack)
	}
	notion := c.Track(finding.Finding{Title: "Sync can read and change the Notion pages shared with it (your own integration)",
		Resource: finding.Resource{Type: "notion_integration", Name: "Sync"}})
	if notion.Group != finding.GroupFamily || notion.Noun != "Notion integration" || notion.TitleOne != "Sync can read and change the Notion pages shared with it (your own integration)" ||
		notion.Title != "{count} can read and change the Notion pages shared with them (your own integrations)" {
		t.Errorf("notion %+v", notion)
	}
	if other := c.Track(finding.Finding{Title: "Recorder has used your account", Resource: finding.Resource{Type: "zoom_app", Name: "Recorder"}}); other.Nouns != "apps" {
		t.Errorf("unknown service %+v", other)
	}
}
