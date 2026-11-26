//go:build windows

package redact

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const holdEnv = "SEGURATA_TEST_HOLD_OPEN"

// TestHoldOpenHelper is the helper process holdOpen starts: it keeps a file open until its stdin
// closes.
func TestHoldOpenHelper(t *testing.T) {
	p := os.Getenv(holdEnv)
	if p == "" {
		t.Skip("helper process only")
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fmt.Println("ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// holdOpen keeps path open in another process until the test ends.
func holdOpen(t *testing.T, path string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHoldOpenHelper$")
	cmd.Env = append(os.Environ(), holdEnv+"="+path)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		in.Close()
		_ = cmd.Wait()
	})
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper did not open %s: %q %v", path, line, err)
	}
}

// The Restart Manager names the one file of a set another process holds, through the batch
// splitting, and only that one.
func TestDefaultOpenFilesFindsTheFileAnotherProcessHolds(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for i := range 7 {
		p := filepath.Join(dir, fmt.Sprintf("f%d.jsonl", i))
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	if open, err := DefaultOpenFiles(context.Background(), paths); err != nil || len(open) != 0 {
		t.Fatalf("nothing held: %v %v", open, err)
	}
	holdOpen(t, paths[4])
	open, err := DefaultOpenFiles(context.Background(), paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || !open[paths[4]] {
		t.Fatalf("open %v, want only %s", open, paths[4])
	}
}

func TestRedactLeavesAFileAnotherProcessHoldsAlone(t *testing.T) {
	fx := newFixture(t)
	held := fx.write(".claude/projects/a/held.jsonl", fx.transcript(), 0o600)
	free := fx.write(".claude/projects/a/free.jsonl", fx.transcript(), 0o600)
	before := fx.read(held)
	holdOpen(t, held)
	c, out, errb := fx.cli("", false)
	c.OpenFiles = DefaultOpenFiles
	if code := c.Run(context.Background(), []string{"--trails", "--apply", "--yes"}); code != 0 {
		t.Fatalf("exit %d:\n%s%s", code, out, errb)
	}
	if fx.read(held) != before || !strings.Contains(out.String(), "1 file "+skipOpen) {
		t.Fatalf("a held file was rewritten:\n%s", out)
	}
	if strings.Contains(fx.read(free), fx.secrets["anthropic"]) {
		t.Error("the file nobody holds was not redacted")
	}
}
