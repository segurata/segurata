package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

// verbCell is a backticked verb at the start of a row of the Verbs table: "| `accept` / `unaccept` |".
var verbCell = regexp.MustCompile("`([a-z-]+)`")

// TestVerbsTableListsEveryCommand keeps docs/architecture.md, "Verbs", in step with commands.
func TestVerbsTableListsEveryCommand(t *testing.T) {
	raw, err := os.ReadFile("../../docs/architecture.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(raw), "### Verbs\n")
	if !ok {
		t.Fatal("docs/architecture.md has no Verbs section")
	}
	section, _, _ = strings.Cut(section, "\n###")
	var documented []string
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		first, _, _ := strings.Cut(strings.TrimPrefix(line, "|"), "|")
		for _, m := range verbCell.FindAllStringSubmatch(first, -1) {
			documented = append(documented, m[1])
		}
	}
	var dispatched []string
	for _, c := range commands {
		dispatched = append(dispatched, c.name)
	}
	slices.Sort(documented)
	slices.Sort(dispatched)
	if !slices.Equal(documented, dispatched) {
		t.Errorf("docs/architecture.md lists %v, commands dispatches %v", documented, dispatched)
	}
}
