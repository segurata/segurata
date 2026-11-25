package tracker

import (
	"cmp"

	_ "github.com/segurata/segurata/connectors" // registers the built-in connectors
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// Declare does to a run's records what the connectors and the core do before writing them: each
// finding gets the Track its built-in connector declares, and the run the theme and areas its
// connector declares (internal/run). Plugins write their findings' Track themselves; their
// descriptions are in plugins. Records of other connectors are left as they are, as in a run
// written before connectors declared anything.
func Declare(recs []any) []any {
	out := make([]any, 0, len(recs)+2)
	name, themed := "", false
	for _, r := range recs {
		switch r := r.(type) {
		case finding.Finding:
			name = cmp.Or(name, r.Connector)
			if tr, ok := builtin(r.Connector).(connector.Tracker); ok && r.Track == nil {
				r.Track = tr.Track(r)
			}
			out = append(out, r)
			continue
		case finding.Status:
			name = cmp.Or(name, r.Connector)
		case finding.Theme:
			themed = true
		}
		out = append(out, r)
	}
	d, ok := describe(name)
	if !ok || themed {
		return out
	}
	out = append(out, finding.ThemeFor(d.Theme))
	if len(d.Covers) > 0 {
		out = append(out, d.Covers)
	}
	return out
}

// builtin is the built-in connector of that name, or nil.
func builtin(name string) connector.Connector {
	for _, c := range connector.Builtins() {
		if c.Describe().Name == name {
			return c
		}
	}
	return nil
}

// describe is what the connector of that name declares: a built-in one, or one of plugins.
func describe(name string) (connector.Description, bool) {
	if c := builtin(name); c != nil {
		return c.Describe(), true
	}
	d, ok := plugins[name]
	return d, ok
}

// plugins are what the external connectors of the tests declare (plugins/prowler, examples/hibp).
var plugins = map[string]connector.Description{
	"prowler": {Theme: finding.Theme{ID: finding.ThemeCloud.ID}},
	"hibp":    {Covers: []finding.Area{{ID: "hibp"}}},
}
