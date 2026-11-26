package searchpath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanDropsDuplicatesAndUnexpandable(t *testing.T) {
	a := filepath.Join(t.TempDir(), "bin")
	b := t.TempDir()
	sep := string(os.PathListSeparator)
	got := Clean(strings.Join([]string{a, "~/src/bin", "", b + string(filepath.Separator), a, "rel/bin", b}, sep))
	if got != strings.Join([]string{a, b}, sep) {
		t.Fatalf("got %q", got)
	}
}
