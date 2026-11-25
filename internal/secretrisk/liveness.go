package secretrisk

import "time"

// LiveState is what a provider said about a leaked secret when asked with it.
type LiveState string

const (
	Live    LiveState = "live"    // the provider accepted it
	Dead    LiveState = "dead"    // the provider rejected it as invalid, revoked or expired
	Unknown LiveState = "unknown" // no answer that tells: network, rate limit, server error, ambiguous
)

// Liveness is the result of local-secrets' liveness check of one secret: one call to the
// provider's read-only identity endpoint with the secret (see connectors/internal/liveness and
// docs/architecture.md, "Liveness"). Never the value, and never the provider's own message, which
// may echo part of it: Reason is segurata's words.
type Liveness struct {
	State     LiveState `json:"state"`
	CheckedAt time.Time `json:"checked_at"`
	Provider  string    `json:"provider"`
	Endpoint  string    `json:"endpoint,omitempty"` // "GET api.openai.com/v1/models"
	Reason    string    `json:"reason,omitempty"`   // "HTTP 401", "invalid_auth"
	// Account is who the provider says the secret signs in as, "<provider>:<id>" (github:octocat,
	// aws:123456789012, slack:T0123), when the endpoint says: evidence for attribution.
	Account string `json:"account,omitempty"`
}
