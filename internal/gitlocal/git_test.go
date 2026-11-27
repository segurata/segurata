package gitlocal

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// In a git worktree, whose .git is a file pointing to the main repository, a file is tracked as the
// worktree's index says.
func TestTrackedInAWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	main, wt := filepath.Join(dir, "main"), filepath.Join(dir, "wt")
	if err := os.MkdirAll(main, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(main, "app.yml"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "app.yml"}, {"commit", "-q", "-m", "init"}, {"worktree", "add", "-q", wt}} {
		cmd := exec.Command("git", append([]string{"-C", main, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(wt, ".env"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"app.yml": true, ".env": false} {
		if got, err := Tracked(context.Background(), filepath.Join(wt, name)); err != nil || got != want {
			t.Errorf("Tracked(%s) = %v, %v; want %v", name, got, err, want)
		}
	}
}

// Git's own refusal of a repository another account owns comes back naming safe.directory, with
// the original error still in the chain.
func TestDubiousOwnershipNamesSafeDirectory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	cmd := exec.Command("git", "-C", root, "ls-files")
	cmd.Env = append(os.Environ(), "GIT_TEST_ASSUME_DIFFERENT_OWNER=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	_, err := cmd.Output()
	ee, ok := errors.AsType[*exec.ExitError](err)
	if !ok {
		t.Skipf("this git does not check ownership: %v", err)
	}
	got := Classify(err, string(ee.Stderr))
	unsafe, ok := errors.AsType[*UnsafeRepositoryError](got)
	if !ok || !errors.Is(got, err) {
		t.Fatalf("not classified: %v\n%s", got, ee.Stderr)
	}
	if unsafe.Repo == "" || !strings.Contains(got.Error(), "safe.directory "+unsafe.Repo) || strings.Contains(got.Error(), "safe.directory=*") {
		t.Errorf("message: %v", got)
	}
}

func TestClassifyLeavesOtherFailuresAlone(t *testing.T) {
	base := errors.New("exit status 128")
	if got := Classify(base, "fatal: not a git repository"); got != base {
		t.Errorf("another failure was reclassified: %v", got)
	}
	if Classify(nil, "dubious ownership") != nil {
		t.Error("a success became an error")
	}
	if got := Classify(base, "fatal: detected dubious ownership"); !strings.Contains(got.Error(), "<repository>") {
		t.Errorf("without a path: %v", got)
	}
	// Git for Windows, translated, with a quoted path.
	stderr := "fatal: posesión dudosa detectada en el repositorio a 'C:/Users/ana/src/my app'\n" +
		"Para añadir una excepción para este directorio, ejecuta:\n\n\tgit config --global --add safe.directory 'C:/Users/ana/src/my app'\n"
	got, ok := errors.AsType[*UnsafeRepositoryError](Classify(base, stderr))
	if !ok || got.Repo != "C:/Users/ana/src/my app" || !strings.Contains(got.Error(), "safe.directory 'C:/Users/ana/src/my app'`") {
		t.Errorf("translated message: %v", got)
	}
}
