package statefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/fileacl"
	"github.com/segurata/segurata/internal/fileacl/fileacltest"
	"github.com/segurata/segurata/internal/winsys"
)

// holdOpen opens path the way Go's os.Open does, without FILE_SHARE_DELETE, and closes it after d.
func holdOpen(t *testing.T, path string, d time.Duration) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(d, func() { f.Close() })
	t.Cleanup(func() {
		timer.Stop()
		f.Close()
	})
}

func assertContent(t *testing.T, path, want string) {
	t.Helper()
	if got, err := ReadFile(path); err != nil || string(got) != want {
		t.Fatalf("%s: %q %v, want %q", filepath.Base(path), got, err, want)
	}
}

func assertOnlyFile(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Errorf("leftover files: %v %v", entries, err)
	}
}

func TestWriteWaitsForAReaderWithoutShareDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "tracker.json")
	if err := Write(path, []byte("old\n")); err != nil {
		t.Fatal(err)
	}
	holdOpen(t, path, 200*time.Millisecond)
	start := time.Now()
	if err := Write(path, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited < 150*time.Millisecond {
		t.Errorf("replaced after %s while the file was open", waited)
	}
	assertContent(t, path, "new\n")
	fileacltest.AssertPrivate(t, path)
	assertOnlyFile(t, path)
}

func TestWriteGivesUpOnAFileHeldOpen(t *testing.T) {
	defer func(d time.Duration) { retryFor = d }(retryFor)
	retryFor = 100 * time.Millisecond
	path := filepath.Join(t.TempDir(), "tracker.json")
	if err := Write(path, []byte("old\n")); err != nil {
		t.Fatal(err)
	}
	holdOpen(t, path, time.Minute)
	err := Write(path, []byte("new\n"))
	if !errors.Is(err, os.ErrPermission) && !errors.Is(err, winsys.ErrorSharingViolation) {
		t.Fatalf("err %v", err)
	}
	assertContent(t, path, "old\n")
	assertOnlyFile(t, path)
}

func TestOpenNeverBlocksAWriter(t *testing.T) {
	defer func(d time.Duration) { retryFor = d }(retryFor)
	retryFor = 0
	path := filepath.Join(t.TempDir(), "tracker.json")
	if err := Write(path, []byte("old\n")); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Write(path, []byte("new\n")); err != nil {
		t.Fatalf("a reader blocked the rename: %v", err)
	}
	if err := Replace(path, []byte("newer\n"), fileacl.Private); err != nil {
		t.Fatalf("a reader blocked the replace: %v", err)
	}
	assertContent(t, path, "newer\n")
	if _, err := Open(filepath.Join(filepath.Dir(path), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing file: %v", err)
	}
}

// A user's file rewritten by redact or rotation keeps its DACL, explicit entries included, where a
// rename would give it the temporary file's private descriptor.
func TestReplaceKeepsTheUsersAccessList(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileacltest.Expose(t, path)
	before := fileacltest.Access(t, path)
	holdOpen(t, path, 200*time.Millisecond)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Replace(path, []byte("new\n"), st.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	if after := fileacltest.Access(t, path); after != before {
		t.Fatalf("access %s, was %s", after, before)
	}
	assertContent(t, path, "new\n")
	assertOnlyFile(t, path)
}

func TestReplaceOfAMissingFileIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new")
	if err := Replace(path, []byte("x"), fileacl.Private); err != nil {
		t.Fatal(err)
	}
	fileacltest.AssertPrivate(t, path)
}
