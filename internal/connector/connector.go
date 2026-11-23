// Package connector is the contract shared by built-in and external connectors.
package connector

import (
	"context"
	"sort"

	"github.com/segurata/segurata/internal/finding"
)

const ProtocolVersion = 1

// Description is what `securizame-<name> describe` prints.
type Description struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Protocol int      `json:"protocol"`
	Summary  string   `json:"summary"`
	Needs    []string `json:"needs"` // "cdp", "cli:gcloud", "secret:OPENAI_ADMIN_KEY"
}

// Request is what the core hands a connector on `inventory`. Secrets arrive already resolved.
type Request struct {
	Protocol int               `json:"protocol"`
	CDPURL   string            `json:"cdp_url,omitempty"`
	Config   map[string]any    `json:"config,omitempty"`
	Secrets  map[string]string `json:"secrets,omitempty"`
}

// Emitter receives records as the connector produces them.
type Emitter interface {
	Finding(finding.Finding)
	Status(finding.Status)
	Log(msg string)
}

type Connector interface {
	Describe() Description
	// Inventory is read-only. It returns an error only when it could not start at all;
	// per-account problems are reported as statuses.
	Inventory(ctx context.Context, req Request, emit Emitter) error
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
