package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector/connectortest"
)

// Every verb asks for the connectors, some of them many times per command (status asks once per
// setup item); plugins answer describe once per process.
func TestConnectorsAreDiscoveredOncePerProcess(t *testing.T) {
	connectortest.NeedShell(t)
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho x >> '" + calls + "'\necho '{\"name\":\"once\",\"protocol\":2}'\n"
	if err := os.WriteFile(filepath.Join(dir, "segurata-once"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	for range 3 {
		browserConnector("once")
		all()
	}
	raw, _ := os.ReadFile(calls)
	if n := strings.Count(string(raw), "x"); n != 1 {
		t.Fatalf("describe ran %d times", n)
	}
}
