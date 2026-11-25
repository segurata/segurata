package googlepersonal

import "github.com/segurata/segurata/internal/finding"

// Track makes one review item of an account's OAuth grants per severity: "Review 4 apps with broad
// access to me@gmail.com". Other findings group by default.
func (GooglePersonal) Track(f finding.Finding) *finding.Track {
	if f.Resource.Type != "oauth_grant" {
		return nil
	}
	return &finding.Track{Group: finding.GroupAccountSeverity, Kind: finding.TrackReview, Noun: "app", Nouns: "apps",
		Title: "Review {count} with " + f.Severity.Pick("high-risk", "broad", "limited") + " access to " + f.Account}
}
