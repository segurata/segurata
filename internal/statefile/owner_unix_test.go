//go:build unix

package statefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnerIDIsTheFilesOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x")
	if err := Write(path, nil); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if uid, ok := OwnerID(st); !ok || uid != os.Getuid() {
		t.Errorf("OwnerID = %d %v, want %d", uid, ok, os.Getuid())
	}
}
