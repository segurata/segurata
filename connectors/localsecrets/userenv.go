package localsecrets

import (
	"maps"
	"slices"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

const registrySource = "registry"

// userEnv searches the user's persistent environment variables, which setx writes to the
// registry and every new process inherits, as `NAME=value` lines of one config file: an AWS key
// id in one variable makes a secret-ish one an AWS secret key.
func (s *scan) userEnv() {
	if s.c.UserEnv == nil {
		return
	}
	vars, err := s.c.UserEnv()
	if err != nil {
		s.emit.Scope(finding.PathScope(secretrisk.FilesScope, secretrisk.UserEnvKey), false, "registry: "+err.Error())
		return
	}
	type match struct{ path, mt, line string }
	var ms []match
	var keyID bool
	for _, name := range slices.Sorted(maps.Keys(vars)) {
		line := name + "=" + vars[name]
		for _, loc := range matcherFor("config").findAll(line) {
			m := match{secretrisk.UserEnvKey + `\` + name, line[loc[0]:loc[1]], line}
			if c, ok := classify(m.path, m.mt, withAssignment); ok && c.p.typ == "aws-access-key-id" && pairableKeyID(c.subs(m.mt)[c.p.group]) {
				keyID = true
			}
			ms = append(ms, m)
		}
	}
	for _, m := range ms {
		ev, value, c, ok := lineEvidence(m.path, m.mt, m.line, withAssignment, s.now)
		if ok && keyID && c.p.typ == assignment.typ && awsSecretNearKeyID(c.varName, value) {
			ev, value, ok = valueEvidence(awsSecretKey, []string{c.subs(m.mt)[0], value}, c.varName, m.line, s.now)
		}
		if !ok {
			continue
		}
		ev.Source, ev.Kind = registrySource, "config"
		s.add(m.path, ev, value)
	}
}
