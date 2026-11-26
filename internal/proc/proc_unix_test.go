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
	"github.com/segurata/segurata/internal/proc/proctest"
)

// A cancelled command takes its whole process group with it: a child the command started in the
// background (Prowler's own subprocesses, holding a live token) must not keep running, and one
// that ignores SIGTERM is killed once WaitDelay is up.
func TestCancelKillsTheProcessGroup(t *testing.T) {
	for name, child := range map[string]string{
		"plain":         "(: > ready; exec sleep 30) &",
		"ignoring TERM": "(trap '' TERM; : > ready; exec sleep 30) &",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			pidFile := filepath.Join(dir, "pid")
			script := filepath.Join(dir, "spawn")
			body := "#!/bin/sh\ncd '" + dir + "'\n" + child + "\necho $! > pid.tmp && mv pid.tmp pid\nwait\n"
			if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cmd := proc.Command(ctx, script)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			proctest.AwaitFile(t, filepath.Join(dir, "ready"))
			proctest.AwaitFile(t, pidFile)
			cancel()
			if err := cmd.Wait(); err == nil {
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
