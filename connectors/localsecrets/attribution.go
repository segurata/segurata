package localsecrets

import (
	"os"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Attribution runs at scan time, the only moment the value is at hand: the evidence keeps the
// account identifiers the value names and, for contextServices, those its file names; never the
// value.

var contextServices = map[string]bool{"aws": true, "google": true, "gcp": true}

const maxContext = 1 << 20 // largest file read for context

// attribute puts the value's claims before those already set (leakClaims).
func (s *scan) attribute(abs string, ev *secretrisk.Evidence, value string) {
	c := attribution.FromValue(value).Or(ev.Claims)
	if ev.Source != "gitleaks" && ev.Source != registrySource && contextServices[secretrisk.TypeFor(ev.Type, ev.Redacted).Service] {
		if st, err := os.Stat(abs); err == nil && st.Mode().IsRegular() && st.Size() <= maxContext {
			if raw, err := os.ReadFile(abs); err == nil {
				c = c.Or(attribution.FromContext(string(raw)))
			}
		}
	}
	ev.Claims = c
}

// leakClaims are the commit's author and, for contextServices, the matched line's claims.
func leakClaims(l leak, ev secretrisk.Evidence) attribution.Claims {
	var c attribution.Claims
	if contextServices[secretrisk.TypeFor(ev.Type, ev.Redacted).Service] {
		c = attribution.FromContext(l.Match + "\n" + l.Line)
	}
	c.AuthorEmail = l.Email
	return c
}
