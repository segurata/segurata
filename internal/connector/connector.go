// Package connector is the contract shared by built-in and external connectors.
package connector

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

// ProtocolVersion is the newest external connector protocol the core speaks. Version 2 adds
// remediation (`plan` and `apply`); the core still speaks version 1 (MinProtocolVersion) to
// connectors that only inventory. See docs/connectors.md.
const (
	ProtocolVersion    = 2
	MinProtocolVersion = 1
)

// Description is what `segurata-<name> describe` prints.
type Description struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Protocol int      `json:"protocol"`
	Summary  string   `json:"summary"`
	Needs    []string `json:"needs"` // "cdp", "cli:gcloud", "secret:OPENAI_ADMIN_KEY"
	// Remediates lists the remediation actions an external connector plans and applies itself
	// (protocol 2 and later). Built-in connectors leave it empty and implement Remediator.
	Remediates []string `json:"remediates,omitempty"`
}

// NeedsCDP reports whether the connector drives the browser over the Chrome DevTools Protocol.
func (d Description) NeedsCDP() bool { return slices.Contains(d.Needs, "cdp") }

// Request is what the core hands a connector on `inventory`. Secrets arrive already resolved.
type Request struct {
	Protocol int               `json:"protocol"`
	CDPURL   string            `json:"cdp_url,omitempty"`
	Config   map[string]any    `json:"config,omitempty"`
	Secrets  map[string]string `json:"secrets,omitempty"`
}

// Emitter receives records as the connector produces them.
//
// Statuses already say which accounts (or, with Status.Scope, which parts of one) were inspected.
// Scope declares coverage no status carries: a repository the rate limit left unread, a project
// beyond a cap. Every scope a connector meant to inspect and did not must be either a status other
// than ok or a Scope(id, false, reason); otherwise its findings look resolved. See
// docs/connectors.md, "Coverage".
type Emitter interface {
	Finding(finding.Finding)
	Status(finding.Status)
	Scope(id string, inspected bool, reason string)
	Log(msg string)
}

type Connector interface {
	Describe() Description
	// Inventory is read-only. It returns an error only when it could not start at all;
	// per-account problems are reported as statuses.
	Inventory(ctx context.Context, req Request, emit Emitter) error
}

// SetupHinter is optional: a connector that implements it says how to set up one of the secrets
// its Description needs. When a secret reference in the config cannot be resolved, the core owns
// the one missing_credentials status and does not call Inventory; the hint goes in its detail.
type SetupHinter interface {
	SetupHint(secret string) string
}

// HintFor is the SetupHint of a connector that needs one secret: hint when asked is that secret,
// "" otherwise.
func HintFor(asked, secret, hint string) string {
	if asked != secret {
		return ""
	}
	return hint
}

// Now is the current time in UTC from clock, or from the real clock when clock is nil: built-in
// connectors take an optional clock so tests can fix the time.
func Now(clock func() time.Time) time.Time {
	if clock == nil {
		clock = time.Now
	}
	return clock().UTC()
}

var builtins = map[string]Connector{}

// Register is called from each built-in connector's init.
func Register(c Connector) { builtins[c.Describe().Name] = c }

// Builtins returns the compiled-in connectors sorted by name.
func Builtins() []Connector {
	out := make([]Connector, 0, len(builtins))
	for _, c := range builtins {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Describe().Name < out[j].Describe().Name })
	return out
}
