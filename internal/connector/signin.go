package connector

import (
	"encoding/json"

	"github.com/segurata/segurata/internal/finding"
)

// SignInPage is where the owner clears a reauth or signedout status. `segurata signin` opens URL,
// polls Expr read-only and stops once Done accepts its value; it never types or clicks.
type SignInPage struct {
	URL  string
	Do   string // what the owner does there: "confirm your GitHub password"
	Expr string
	// Done is nil when only the owner can say (Enter).
	Done func(json.RawMessage) bool
	// Brief reruns the instance as soon as Done holds: what the owner did lasts minutes (sudo mode).
	Brief bool
}

// SignInner gives the page for a status, ok false when it has none.
type SignInner interface {
	SignInPage(st finding.Status) (page SignInPage, ok bool)
}
