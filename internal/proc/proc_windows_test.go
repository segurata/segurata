package proc_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/proc"
	"github.com/segurata/segurata/internal/proc/proctest"
)

// gone waits for the process to exit, and reports whether it did.
func gone(pid int, within time.Duration) bool {
	h, err := syscall.OpenProcess(syscall.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return true
	}
	defer syscall.CloseHandle(h)
	ev, err := syscall.WaitForSingleObject(h, uint32(within/time.Millisecond))
	return err == nil && ev == syscall.WAIT_OBJECT_0
}

func kill(pid int) {
	if h, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, uint32(pid)); err == nil {
		_ = syscall.TerminateProcess(h, 1)
		syscall.CloseHandle(h)
	}
}

// A cancelled command takes its whole job with it, a grandchild in a process group of its own
// (which CTRL_BREAK misses) and a parent that ignores CTRL_BREAK included.
func TestCancelEndsTheWholeJob(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := proc.Command(ctx, proctest.Spawn(t, dir, false))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	parent, child := cmd.Process.Pid, proctest.PID(t, dir)
	defer kill(child)
	cancel()
	if err := cmd.Wait(); err == nil {
		t.Fatal("a cancelled command succeeded")
	}
	for _, pid := range []int{parent, child} {
		if !gone(pid, proc.WaitDelay+5*time.Second) {
			t.Fatalf("process %d outlived its cancelled command", pid)
		}
	}
}

// Wait ends what a program left behind, even when it exited cleanly.
func TestWaitEndsWhatTheProgramLeftBehind(t *testing.T) {
	dir := t.TempDir()
	if err := proc.Command(context.Background(), proctest.Spawn(t, dir, true)).Run(); err != nil {
		t.Fatal(err)
	}
	child := proctest.PID(t, dir)
	defer kill(child)
	if !gone(child, 5*time.Second) {
		t.Fatalf("the orphan %d outlived its parent's command", child)
	}
}

// An Interactive command has no process group of its own, so Interrupt ends it instead of sending
// a CTRL_BREAK that would reach segurata too.
func TestInterruptEndsAnInteractiveCommand(t *testing.T) {
	cmd := proc.Interactive(context.Background(), proctest.Hung(t, "hung", ""))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := proc.Interrupt(cmd); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("an interrupted command succeeded")
	}
}

// A batch wrapper never gets an argument cmd.exe would run as a command; a safe one runs.
func TestBatchWrapperRefusesBeforeStarting(t *testing.T) {
	dir := t.TempDir()
	wrapper := filepath.Join(dir, "tool.cmd")
	if err := os.WriteFile(wrapper, []byte("@echo ran %1> \"%~dp0ran\"\r\n@echo ran %1\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := proc.Command(context.Background(), wrapper, "literal&").Output()
	if _, ok := errors.AsType[*exec.Error](err); !ok || !errors.Is(err, proc.ErrBatchArgument) {
		t.Fatalf("want a refusal, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the refused wrapper ran: %v", err)
	}
	// Without the extension exec finds tool.cmd through PATHEXT; the guard must see it too.
	if _, err := proc.Command(context.Background(), filepath.Join(dir, "tool"), "a|b").Output(); !errors.Is(err, proc.ErrBatchArgument) {
		t.Fatalf("want a refusal of the extensionless path, got %v", err)
	}
	out, err := proc.Command(context.Background(), wrapper, "safe").Output()
	if err != nil || strings.TrimSpace(string(out)) != "ran safe" {
		t.Fatalf("%q %v", out, err)
	}
}
