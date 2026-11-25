package tracker

import (
	"cmp"

	_ "github.com/segurata/segurata/connectors" // registers the built-in connectors
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// Declare does to a run's records what the connectors and the core do before writing them: each
// finding gets the Track its built-in connector declares, and the run the theme its connector
// declares (internal/run). The prowler plugin's declarations are in its findings already and its
// theme in pluginThemes. Records of other connectors are left as they are.
func Declare(recs []any) []any {
	out := make([]any, 0, len(recs)+1)
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
	if th := declaredTheme(name); !themed && th.ID != "" {
		out = append(out, th)
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

// declaredTheme is the theme the core writes in a connector's run_end.
func declaredTheme(name string) finding.Theme {
	if c := builtin(name); c != nil {
		return finding.ThemeFor(c.Describe().Theme)
	}
	return finding.ThemeFor(pluginThemes[name])
}

// pluginThemes are the themes the external connectors of the tests declare.
var pluginThemes = map[string]finding.Theme{}
