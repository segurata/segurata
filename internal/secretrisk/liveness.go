package secretrisk

import "time"

// LiveState is what a provider said about a leaked secret when asked with it.
type LiveState string

const (
	Live    LiveState = "live"    // the provider accepted it
	Dead    LiveState = "dead"    // the provider rejected it as invalid, revoked or expired
	Unknown LiveState = "unknown" // no answer that tells: network, rate limit, server error, ambiguous
	// Unregistered is an SSH key looked up with the owner's credentials and registered nowhere
	// segurata can see. Not proof it is dead: it lowers the priority, it closes nothing.
	Unregistered LiveState = "unregistered"
)

// Liveness is the result of local-secrets' liveness check of one secret: one call to the
// provider's read-only identity endpoint with the secret, or, for a secret that cannot be tried by
// itself (a lone AWS key id, a private key), a lookup with the owner's own credentials (see
// connectors/internal/liveness and docs/architecture.md, "Liveness"). Never the value, and never the provider's own message, which
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
	// ByOwner marks a lookup with the owner's own credentials that never sent the secret: Endpoint
	// is what was read ("GET api.github.com/user/keys"), Reason what it says of the secret
	// ("GitHub SSH key 'laptop'", "Inactive in account 123456789012").
	ByOwner bool `json:"by_owner,omitempty"`
}

// Said is what the check found, for reasons and history: "GET api.github.com/user answered HTTP
// 401", or for a lookup "GitHub SSH key 'laptop' (GET api.github.com/user/keys)".
func (l Liveness) Said() string {
	if l.ByOwner {
		return l.Reason + " (" + l.Endpoint + ")"
	}
	return l.Endpoint + " answered " + l.Reason
}
