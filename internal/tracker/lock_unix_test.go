//go:build unix

package tracker

import (
	"strings"
	"testing"
	"time"
)

// Commands that change the tracker take its lock and wait for another command holding it; views
// do not. status --mark-seen records the time into the tracker as it is when it saves.
func TestChangingCommandsTakeTheTrackerLock(t *testing.T) {
	x := newCLIFixture(t)
	if _, e, code := x.run(t, "sync", "--out", x.out); code != 0 {
		t.Fatal(e)
	}
	unlock, err := Lock(x.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func(w time.Duration) { lockWait = w }(lockWait)
	lockWait = 100 * time.Millisecond
	for _, args := range [][]string{{"note", "T-1", "x"}, {"sync", "--out", x.out}} {
		if _, e, code := x.run(t, args...); code != 1 || !strings.Contains(e, "in use by another segurata command") {
			t.Errorf("%v while locked: %d %q", args, code, e)
		}
	}
	for _, args := range [][]string{{"list"}, {"show", "T-1"}, {"status"}} {
		if _, e, code := x.run(t, args...); code != 0 {
			t.Errorf("%v while locked: %d %q", args, code, e)
		}
	}
	unlock()
	if _, e, code := x.run(t, "note", "T-1", "after"); code != 0 {
		t.Fatalf("after unlock: %q", e)
	}
}
