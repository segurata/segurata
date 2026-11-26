// Package connectortest builds fake external connectors from shell scripts, and fake remediators,
// for tests. A package that uses Script or Plugin runs its tests through proctest.Main.
package connectortest

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/proc/proctest"
)

// QuietIO is an IO with no input and buffers for output nobody reads.
func QuietIO() connector.IO {
	return connector.IO{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
}

// Script makes segurata-<name>, running the POSIX shell body, in a temp dir and returns its path
// (proctest.Script).
func Script(t *testing.T, name, body string) string {
	t.Helper()
	return proctest.Script(t, "", "segurata-"+name, body)
}

// Plugin is Script followed by connector.LoadExternal; describe must succeed. It waits longer for
// describe than the core does, so a loaded machine does not fail the test.
func Plugin(t *testing.T, name, body string) *connector.External {
	t.Helper()
	e, err := connector.LoadExternalWithin(Script(t, name, body), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
