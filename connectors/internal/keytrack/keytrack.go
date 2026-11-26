// Package keytrack groups AI provider connectors' API key findings in the tracker.
package keytrack

import "github.com/segurata/segurata/internal/finding"

// Track makes one item per account and severity, "Revoke or limit 3 OpenAI API keys (work)";
// other findings group by default.
func Track(provider string, f finding.Finding) *finding.Track {
	if f.Resource.Type != "api_key" {
		return nil
	}
	title := "Revoke or limit {count}"
	if f.Instance != "" {
		title += " (" + f.Instance + ")"
	}
	return &finding.Track{Group: finding.GroupAccountSeverity, Noun: provider + " API key", Nouns: provider + " API keys", Title: title}
}
