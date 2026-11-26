//go:build unix || windows

package tracker

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/fileacl/fileacltest"
)

// Commands that change the tracker take its lock and wait for another command holding it; views
// do not. status --mark-seen records the time into the tracker as it is when it saves.
func TestChangingCommandsTakeTheTrackerLock(t *testing.T) {
	x := newCLIFixture(t)
	if _, e, code := x.run(t, "sync", "--out", x.out); code != 0 {
		t.Fatal(e)
	}
	unlock, err := lock(x.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func(w time.Duration) { lockWait = w }(lockWait)
	lockWait = 0
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

// A second holder, another handle in this process as much as another command, waits for lockWait
// and then gives up; the lock file is private like the tracker beside it.
func TestLockWaitsThenGivesUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tracker.json")
	unlock, err := lock(path)
	if err != nil {
		t.Fatal(err)
	}
	fileacltest.AssertPrivate(t, path+".lock")
	defer func(w time.Duration) { lockWait = w }(lockWait)
	lockWait = 100 * time.Millisecond
	start := time.Now()
	if _, err := lock(path); err == nil || !strings.Contains(err.Error(), "in use by another segurata command") {
		t.Fatalf("second lock: %v", err)
	}
	if waited := time.Since(start); waited < lockWait {
		t.Errorf("gave up after %s", waited)
	}
	unlock()
	again, err := lock(path)
	if err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	again()
}
