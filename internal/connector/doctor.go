package connector

import "context"

// Level is how a prerequisite check came out.
type Level string

const (
	OK   Level = "OK"
	Warn Level = "WARN" // the connector runs, but part of it will be skipped or is at risk
	Fail Level = "FAIL" // the connector cannot do its job until this is fixed
)

// Check is one prerequisite checked by `segurata doctor`. Detail and Fix never hold a secret.
type Check struct {
	Level  Level
	What   string // what was checked: "gcloud account a@b.com", "gh scopes"
	Detail string
	Fix    string // the exact command or step that fixes it
}

// Doctor checks a built-in connector's own prerequisites through its inventory's read-only paths;
// without it the core checks the `cli:` and `secret:` needs. It changes and prompts for nothing.
type Doctor interface {
	Doctor(ctx context.Context, req Request) []Check
}
