package connector

import "context"

// Level is how a prerequisite check came out.
type Level string

const (
	OK   Level = "OK"
	Warn Level = "WARN" // the connector runs, but part of it will be skipped or is at risk
	Fail Level = "FAIL" // the connector cannot do its job until this is fixed
)

// Check is one prerequisite checked by `securizame doctor`. Detail and Fix never hold a secret:
// a token or key is at most obtained and discarded.
type Check struct {
	Level  Level
	What   string // what was checked: "gcloud account a@b.com", "gh scopes"
	Detail string
	Fix    string // the exact command or step that fixes it; empty when Level is OK
}

// Doctor is implemented by built-in connectors that check their own prerequisites (CLIs, their
// sign-in, tokens) with the same read-only code paths and allowlists their inventory uses. It is
// optional: for a connector without it, the core checks the `cli:` and `secret:` needs of its
// description generically. Doctor must change nothing, prompt for nothing and print no secret.
type Doctor interface {
	Doctor(ctx context.Context, req Request) []Check
}
