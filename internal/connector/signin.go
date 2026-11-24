package connector

import (
	"encoding/json"

	"github.com/segurata/segurata/internal/finding"
)

// SignInPage is the page where the owner clears a reauth or signedout status of a browser
// connector, and how to tell from the page, read-only, that they are through. `segurata signin`
// opens it in a normal tab, evaluates Expr every few seconds and stops waiting once Done accepts
// the value; it never types or clicks anything.
type SignInPage struct {
	URL  string // opened in a foreground tab of the browser at cdp_url
	Do   string // what the owner does there: "confirm your GitHub password"
	Expr string // JavaScript evaluated on the page; read-only
	// Done reports whether the value of Expr shows the page the connector reads, no longer the
	// sign-in or re-authentication it reported. nil means only the owner can say (Enter).
	Done func(json.RawMessage) bool
	// Brief is set when what the owner does lasts only minutes (GitHub sudo mode): the connector
	// instance is run again as soon as Done holds, not after every page is through.
	Brief bool
}

// SignInner is optional: a browser connector that implements it says where the owner clears one
// of its reauth or signedout statuses. ok is false for a status it has no page for (a CLI that
// is signed out: the status names the command instead).
type SignInner interface {
	SignInPage(st finding.Status) (page SignInPage, ok bool)
}
