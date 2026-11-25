//go:build unix

package proc_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/proc"
)

// A cancelled command takes its whole process group with it: a child the command started in the
// background (Prowler's own subprocesses, holding a live token) must not keep running, and one
// that ignores SIGTERM is killed once WaitDelay is up.
func TestCancelKillsTheProcessGroup(t *testing.T) {
	for name, child := range map[string]string{
		"plain":         "sleep 30 &",
		"ignoring TERM": "(trap '' TERM; exec sleep 30) &",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			pidFile := filepath.Join(dir, "pid")
			script := filepath.Join(dir, "spawn")
			body := "#!/bin/sh\n" + child + "\necho $! > '" + pidFile + "'\nwait\n"
			if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			if err := proc.Command(ctx, script).Run(); err == nil {
				t.Fatal("a cancelled command succeeded")
			}
			raw, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(proc.WaitDelay + 3*time.Second)
			for !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
				if time.Now().After(deadline) {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("the child %d outlived its cancelled parent", pid)
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}
