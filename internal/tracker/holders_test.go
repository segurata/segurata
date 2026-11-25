package tracker

import (
	"testing"
	"time"
)

// A finding whose item was replaced (its title, and so its family key, changed) is held by the
// closed old item and the open new one: the one that saw it last holds it, so a run written
// before connectors declared grouping does not reopen the old item and close the new one.
func TestFindingHolderIsTheItemThatSawItLast(t *testing.T) {
	t0 := time.Date(2026, 11, 24, 17, 0, 0, 0, time.UTC)
	old := &Item{ID: "T-1", Key: "group:x|old", Status: Done, Findings: []FindingRef{{ID: "f1", LastSeen: t0}}}
	cur := &Item{ID: "T-2", Key: "group:x|new", Status: Open, Findings: []FindingRef{{ID: "f1", LastSeen: t0.Add(3 * time.Hour)}}}
	for _, items := range [][]*Item{{old, cur}, {cur, old}} {
		tr := &Tracker{Items: items}
		if got := tr.findingHolders()["f1"]; got != cur {
			t.Fatalf("holder %s, want T-2", got.ID)
		}
	}
	// Same sighting: an open item wins over a closed one.
	same := &Item{ID: "T-3", Key: "group:x|same", Status: Open, Findings: []FindingRef{{ID: "f1", LastSeen: t0}}}
	if got := (&Tracker{Items: []*Item{old, same}}).findingHolders()["f1"]; got != same {
		t.Fatalf("holder %s, want T-3", got.ID)
	}
}
