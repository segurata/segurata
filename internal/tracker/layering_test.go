package tracker

import (
	"os/exec"
	"strings"
	"testing"
)

// The tracker reads run files; it never runs a connector or reads a credential. Importing either
// would make every tracker command link the secret resolvers and the Keychain.
func TestTheTrackerNeverLinksSecretsOrTheKeychain(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	out, err := exec.Command(gobin, "list", "-deps", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, banned := range []string{"/internal/secrets", "/internal/keychain", "/internal/run", "/internal/connector"} {
			if strings.HasSuffix(dep, banned) {
				t.Errorf("tracker depends on %s", dep)
			}
		}
	}
}
