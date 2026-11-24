package main

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

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
