package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultOutDirIgnoresTheWorkingDirectory(t *testing.T) {
	t.Setenv("SEGURATA_OUT", "")
	t.Setenv("SEGURATA_HOME", "/tmp/seg-home")
	if got := DefaultOutDir(); got != "/tmp/seg-home/out" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("SEGURATA_OUT", "/tmp/elsewhere")
	if got := DefaultOutDir(); got != "/tmp/elsewhere" {
		t.Fatalf("SEGURATA_OUT: got %q", got)
	}
}

func loadBody(t *testing.T, body string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

// An instance label names the run file, out/<date>/<name>-<label>.jsonl: one that could leave
// that directory or clash with the separator is refused.
func TestLoadRejectsInstanceLabelsThatAreNotFileNameSafe(t *testing.T) {
	for _, key := range []string{"aws:", "aws:../x", "aws:a/b", "aws:a b", "aws:a:b"} {
		if _, err := loadBody(t, `{"connectors": {"`+key+`": {}}}`); err == nil {
			t.Errorf("%q: loaded", key)
		}
	}
	if _, err := loadBody(t, `{"connectors": {"aws:Work_1.prod-eu": {}, "aws": {}}}`); err != nil {
		t.Errorf("good labels refused: %v", err)
	}
}
