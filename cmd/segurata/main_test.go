package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/segurata/segurata/internal/connector/connectortest"
	"github.com/segurata/segurata/internal/tracker"
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
	freshDiscovery(t)
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

// inventory ends in a tracker sync: what it found is in tracker.json when it returns.
func TestInventoryEndsInATrackerSync(t *testing.T) {
	plugin := connectortest.Script(t, "stub", `case "$1" in
describe) echo '{"name":"stub","protocol":2}';;
inventory) cat >/dev/null
  echo '{"type":"finding","account":"me","resource":{"type":"thing","id":"t1","name":"t1"},"kind":"setting","severity":"high","title":"Stub thing is off","remediation":{"summary":"Turn it on."}}'
  echo '{"type":"status","account":"me","state":"ok"}';;
esac
`)
	home := t.TempDir()
	t.Setenv("PATH", filepath.Dir(plugin))
	t.Setenv("HOME", home)
	t.Setenv("SEGURATA_HOME", filepath.Join(home, "state"))
	t.Setenv("SEGURATA_CONFIG", filepath.Join(home, "config.json"))
	freshDiscovery(t)

	if code := inventory([]string{"--out", filepath.Join(home, "out"), "stub"}); code != 0 {
		t.Fatalf("inventory exit %d", code)
	}
	tr, err := tracker.Load(filepath.Join(home, "state", "tracker.json"))
	if err != nil {
		t.Fatalf("no tracker after inventory: %v", err)
	}
	if tr.LastSyncAt == nil || !slices.ContainsFunc(tr.Items, func(it *tracker.Item) bool { return it.Title == "Stub thing is off" }) {
		t.Errorf("the sync did not fold the run: %d items", len(tr.Items))
	}
}

// freshDiscovery makes the next all() discover the connectors on the test's PATH.
func freshDiscovery(t *testing.T) {
	saved := all
	all = sync.OnceValue(discover)
	t.Cleanup(func() { all = saved })
}
