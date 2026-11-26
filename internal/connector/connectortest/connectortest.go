// Package connectortest builds fake external connectors from shell scripts, and fake remediators,
// for tests.
package connectortest

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/connector"
)

// QuietIO is an IO with no input and buffers for output nobody reads.
func QuietIO() connector.IO {
	return connector.IO{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
}

// NeedShell skips the test where shell scripts cannot run.
func NeedShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script connector")
	}
}

// Script writes a POSIX shell script as segurata-<name> in a temp dir and returns its path. It
// skips the test where shell scripts cannot run.
func Script(t *testing.T, name, body string) string {
	t.Helper()
	NeedShell(t)
	p := filepath.Join(t.TempDir(), "segurata-"+name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
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
