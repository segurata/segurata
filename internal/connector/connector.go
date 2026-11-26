// Package connector is the contract shared by built-in and external connectors.
package connector

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/finding"
)

// ProtocolVersion is the newest external connector protocol the core speaks (docs/connectors.md).
const (
	ProtocolVersion     = 2
	minProtocolVersion  = 1
	remediationProtocol = 2 // the first with `plan` and `apply`
)

// Description is what `segurata-<name> describe` prints.
type Description struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Protocol int      `json:"protocol"`
	Summary  string   `json:"summary"`
	Needs    []string `json:"needs"` // "cdp", "cli:gcloud", "secret:OPENAI_ADMIN_KEY"
	// Remediates are the actions an external connector plans and applies itself; built-in
	// connectors implement Remediator instead.
	Remediates []string `json:"remediates,omitempty"`
	// Timeout is a Go duration ("6h") for a connector that routinely needs more than an hour.
	Timeout string        `json:"timeout,omitempty"`
	Theme   finding.Theme `json:"theme,omitzero"`
	// Covers are the plan areas (docs/plan.md) the connector audits.
	Covers []finding.Area `json:"covers,omitempty"`
}

// RunTimeout is Timeout parsed, 0 when it is empty or not a positive duration.
func (d Description) RunTimeout() time.Duration {
	t, err := time.ParseDuration(d.Timeout)
	if err != nil || t < 0 {
		return 0
	}
	return t
}

// NeedsCDP reports whether the connector drives the browser over the Chrome DevTools Protocol.
func (d Description) NeedsCDP() bool { return slices.Contains(d.Needs, "cdp") }

// Request is what the core hands a connector on `inventory`. Secrets arrive already resolved.
type Request struct {
	Protocol int               `json:"protocol"`
	CDPURL   string            `json:"cdp_url,omitempty"`
	Config   map[string]any    `json:"config,omitempty"`
	Secrets  map[string]string `json:"secrets,omitempty"`
	// Known says whose each secret is; built-in connectors only, never sent to a plugin.
	Known *attribution.Known `json:"-"`
}

// Emitter receives records as the connector produces them. Every scope a connector meant to
// inspect and did not must be a status other than ok or a Scope(id, false, reason), or its findings
// look resolved (docs/connectors.md, "Coverage").
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

// SetupHinter says how to set up a secret; the hint goes into the core's missing_credentials status.
type SetupHinter interface {
	SetupHint(secret string) string
}

// Tracker gives the finding.Track of each finding a built-in connector emits without one.
type Tracker interface {
	Track(f finding.Finding) *finding.Track
}

// HintFor is the SetupHint of a connector that needs one secret.
func HintFor(asked, secret, hint string) string {
	if asked != secret {
		return ""
	}
	return hint
}

// Now is clock() in UTC, or the real time when clock is nil.
func Now(clock func() time.Time) time.Time {
	if clock == nil {
		clock = time.Now
	}
	return clock().UTC()
}

var builtins = map[string]Connector{}

func Register(c Connector) { builtins[c.Describe().Name] = c }

// Builtins are the compiled-in connectors, sorted by name.
func Builtins() []Connector {
	out := make([]Connector, 0, len(builtins))
	for _, c := range builtins {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Describe().Name < out[j].Describe().Name })
	return out
}
