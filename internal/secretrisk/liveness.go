package secretrisk

import "time"

// LiveState is what a provider said about a leaked secret when asked with it.
type LiveState string

const (
	Live    LiveState = "live"    // the provider accepted it
	Dead    LiveState = "dead"    // the provider rejected it as invalid, revoked or expired
	Unknown LiveState = "unknown" // no answer that tells: network, rate limit, server error, ambiguous
	// Unregistered is an SSH key registered nowhere the owner's credentials can see: it lowers the
	// priority and closes nothing.
	Unregistered LiveState = "unregistered"
)

// LiveStates are every state, in the order listings show them.
var LiveStates = []LiveState{Live, Dead, Unregistered, Unknown}

// Liveness is the result of local-secrets' liveness check of one secret (docs/architecture.md,
// "Liveness"). It never holds the value nor the provider's own message, which may echo part of it.
type Liveness struct {
	State     LiveState `json:"state"`
	CheckedAt time.Time `json:"checked_at"`
	Provider  string    `json:"provider"`
	Endpoint  string    `json:"endpoint,omitempty"` // "GET api.openai.com/v1/models"
	Reason    string    `json:"reason,omitempty"`   // segurata's words: "HTTP 401", "invalid_auth"
	Account   string    `json:"account,omitempty"`  // who it signs in as, "<provider>:<id>"
	// ByOwner marks a lookup with the owner's own credentials that never sent the secret.
	ByOwner bool `json:"by_owner,omitempty"`
	Rules   int  `json:"rules,omitempty"` // the LivenessRules that judged it
}

// Said is what the check found, for reasons and history.
func (l Liveness) Said() string {
	if l.ByOwner {
		return l.Reason + " (" + l.Endpoint + ")"
	}
	return l.Endpoint + " answered " + l.Reason
}

// LivenessRules is the version of the verdict rules. 2: dead only on a provider's documented
// invalid-key signal; 1 also read a bare 401 as dead.
const LivenessRules = 2

// Trusted reports whether the result may stand: a dead verdict of older rules may have been a
// bare 401 from a key that still works.
func (l Liveness) Trusted() bool {
	return l.State != Dead || l.ByOwner || l.Rules >= LivenessRules
}
