package openai

import (
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestTrackGroupsAPIKeys(t *testing.T) {
	var c Connector
	if got := c.Track(finding.Finding{Resource: finding.Resource{Type: "api_key"}}); got == nil || got.Noun != "OpenAI API key" {
		t.Fatalf("%+v", got)
	}
}
