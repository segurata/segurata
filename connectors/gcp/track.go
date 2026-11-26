package gcp

import (
	"cmp"

	"github.com/segurata/segurata/internal/finding"
)

var projectGroups = map[string]struct{ verb, noun, nouns string }{
	"api_key":              {"Restrict", "API key", "API keys"},
	"service_account_key":  {"Rotate or delete", "user-managed service-account key", "user-managed service-account keys"},
	"service_account_role": {"Narrow the roles of", "service account", "service accounts"},
}

// Track groups keys and service-account roles per project, as in "Restrict 2 API keys in GCP
// project shop", and names the project of any other finding for decision rules.
func (c *Connector) Track(f finding.Finding) *finding.Track {
	project, _ := f.Evidence["project"].(string)
	g, ok := projectGroups[f.Resource.Type]
	if !ok {
		if project == "" {
			return nil
		}
		return &finding.Track{Project: project}
	}
	key := cmp.Or(project, f.Account)
	return &finding.Track{Group: finding.GroupProject, Key: key, Project: project, Noun: g.noun, Nouns: g.nouns,
		Title: g.verb + " {count} in GCP project " + key}
}
