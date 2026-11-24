package connectors

import (
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
)

// Every built-in connector that needs a secret says how to set it up, so the core's one
// missing_credentials status for an unresolvable reference carries the connector's own steps.
// workspace is the exception: its secret is an alternative to a gcloud sign-in, whose steps depend
// on the tenant's config.
func TestConnectorsThatNeedASecretGiveASetupHint(t *testing.T) {
	for _, c := range connector.Builtins() {
		d := c.Describe()
		for _, n := range d.Needs {
			secret, ok := strings.CutPrefix(n, "secret:")
			if !ok || d.Name == "workspace" {
				continue
			}
			h, ok := c.(connector.SetupHinter)
			if !ok || h.SetupHint(secret) == "" {
				t.Errorf("%s needs %s but gives no setup hint", d.Name, secret)
				continue
			}
			if h.SetupHint("SOMETHING_ELSE") != "" {
				t.Errorf("%s gives a hint for a secret it does not need", d.Name)
			}
		}
	}
}
