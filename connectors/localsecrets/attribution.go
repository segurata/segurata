package localsecrets

import (
	"os"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Attribution at scan time, the only place the raw value is at hand: the evidence gets the account
// identifiers the value names (the AWS account an access key id encodes, the Slack workspace of a
// webhook, the GCP project number of an OAuth client id) and, for AWS and Google credentials,
// those the file around it names (the key id next to a secret access key, project_id in a
// credentials file). Only these derived identifiers are stored, never the key id. The tracker
// compares them with the owner's accounts: see internal/attribution and docs/architecture.md,
// "Attribution".

// contextServices are the services whose secrets are identified by the file around them.
var contextServices = map[string]bool{"aws": true, "google": true, "gcp": true}

// maxContext is the largest file read for context.
const maxContext = 1 << 20

// attribute sets ev's claims from value and, for AWS and Google credentials outside git history,
// from the file at abs. Claims already set (by leakClaims) come after the value's own.
func (s *scan) attribute(abs string, ev *secretrisk.Evidence, value string) {
	c := attribution.FromValue(value).Or(ev.Claims)
	if ev.Source != "gitleaks" && contextServices[secretrisk.TypeFor(ev.Type, ev.Redacted).Service] {
		if st, err := os.Stat(abs); err == nil && st.Mode().IsRegular() && st.Size() <= maxContext {
			if raw, err := os.ReadFile(abs); err == nil {
				c = c.Or(attribution.FromContext(string(raw)))
			}
		}
	}
	ev.Claims = c
}

// leakClaims are what a gitleaks finding says besides the value: the commit's author and, for AWS
// and Google credentials, the claims of the matched line (the file as it was in that commit is not
// read).
func leakClaims(l leak, ev secretrisk.Evidence) attribution.Claims {
	var c attribution.Claims
	if contextServices[secretrisk.TypeFor(ev.Type, ev.Redacted).Service] {
		c = attribution.FromContext(l.Match + "\n" + l.Line)
	}
	c.AuthorEmail = l.Email
	return c
}
