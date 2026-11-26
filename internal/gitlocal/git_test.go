package gitlocal

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A tracked file is tracked wherever segurata runs, a subdirectory of its work tree included.
func TestTrackedFromInsideTheWorkTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	deep := filepath.Join(root, "sub", "deep")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".zshrc", ".untracked"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", ".zshrc"}} {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	for _, cwd := range []string{deep, root, "/"} {
		t.Chdir(cwd)
		for name, want := range map[string]bool{".zshrc": true, ".untracked": false} {
			got, err := Tracked(context.Background(), filepath.Join(root, name))
			if err != nil || got != want {
				t.Errorf("from %s: Tracked(%s) = %v, %v; want %v", cwd, name, got, err, want)
			}
		}
	}
}
