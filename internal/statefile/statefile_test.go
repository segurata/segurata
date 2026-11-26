package statefile

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/fileacl/fileacltest"
)

func TestReplaceKeepsTheGivenModeAndLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rc")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	if err := Replace(path, []byte("new\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || after.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v err %v", after.Mode().Perm(), err)
	}
	if os.SameFile(before, after) {
		t.Error("written in place instead of renamed over")
	}
	if got, _ := os.ReadFile(path); string(got) != "new\n" {
		t.Errorf("content %q", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("leftover files: %v", entries)
	}
}

func TestWriteJSONIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "x.json")
	if err := WriteJSON(path, map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	fileacltest.AssertPrivate(t, path)
	fileacltest.AssertPrivateDir(t, filepath.Dir(path))
}

func TestBackupsInTheSameSecondDoNotCollide(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	now := time.Date(2026, 11, 24, 15, 43, 0, 0, time.UTC)
	a, err := Backup(p, []byte("one"), now)
	if err != nil || a != p+".segurata-bak-20261124T154300Z" {
		t.Fatalf("first backup %q %v", a, err)
	}
	b, err := Backup(p, []byte("two"), now)
	if err != nil || b != a+"-2" {
		t.Fatalf("second backup in the same second: %q %v", b, err)
	}
	for name, want := range map[string]string{a: "one", b: "two"} {
		if raw, err := os.ReadFile(name); err != nil || string(raw) != want {
			t.Errorf("%s: %q, %v", name, raw, err)
		}
		fileacltest.AssertPrivate(t, name)
	}
	if _, err := Backup(filepath.Join(p, "missing", "x"), nil, now); err == nil {
		t.Error("a backup in a missing directory succeeded")
	}
}

// ReadJSON is the one reader of segurata's own JSON state: a missing file is not an error, a
// file that cannot be read or decoded is, and each caller decides what that costs it.
func TestReadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.json")
	var v struct{ A int }
	if found, err := ReadJSON(path, &v); found || err != nil {
		t.Fatalf("missing: found %v, err %v", found, err)
	}
	if err := WriteJSON(path, map[string]int{"A": 7}); err != nil {
		t.Fatal(err)
	}
	if found, err := ReadJSON(path, &v); !found || err != nil || v.A != 7 {
		t.Fatalf("written: found %v, err %v, v %+v", found, err, v)
	}
	if err := os.WriteFile(path, []byte("{torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	if found, err := ReadJSON(path, &v); !found || err == nil {
		t.Fatalf("torn: found %v, err %v", found, err)
	}
	if found, err := ReadJSON(dir, &v); found || err == nil {
		t.Fatalf("a directory: found %v, err %v", found, err)
	}
}
