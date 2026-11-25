package keytrack

import (
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestTrack(t *testing.T) {
	key := finding.Finding{Instance: "work", Resource: finding.Resource{Type: "api_key"}}
	got := Track("OpenAI", key)
	if got == nil || got.Group != finding.GroupAccountSeverity || got.Title != "Revoke or limit {count} (work)" || got.Nouns != "OpenAI API keys" {
		t.Fatalf("%+v", got)
	}
	if Track("OpenAI", finding.Finding{Resource: finding.Resource{Type: "spend_limit"}}) != nil {
		t.Fatal("only API keys group")
	}
}
