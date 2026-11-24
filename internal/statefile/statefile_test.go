package statefile

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v", st.Mode().Perm(), err)
	}
	if dir, _ := os.Stat(filepath.Dir(path)); dir.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", dir.Mode().Perm())
	}
}

func TestBackupsInTheSameSecondDoNotCollide(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	now := time.Date(2026, 11, 24, 15, 43, 0, 0, time.UTC)
	a, err := Backup(p, []byte("one"), now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Backup(p, []byte("two"), now)
	if err != nil || a == b {
		t.Fatalf("second backup in the same second: %q %q %v", a, b, err)
	}
}
