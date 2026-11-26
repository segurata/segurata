package proc_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/proc"
	"github.com/segurata/segurata/internal/proc/proctest"
)

func TestAKilledWrapperDoesNotWaitForItsChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := proc.Command(ctx, proctest.Hung(t, "hung", "")).Output(); err == nil {
		t.Fatal("a hung command succeeded")
	}
	if took := time.Since(start); took > proc.WaitDelay+5*time.Second {
		t.Fatalf("Wait blocked for %s on the orphaned child", took)
	}
}

func TestExecEndsAHungProgramWithItsContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := proc.Exec(ctx, nil, proctest.Hung(t, "op", "")); err == nil {
		t.Fatal("a hung program succeeded")
	}
	if took := time.Since(start); took > proc.WaitDelay+5*time.Second {
		t.Fatalf("took %s", took)
	}
}

// Cancelling asks first: SIGTERM to the group on Unix, CTRL_BREAK on Windows, which a program that
// cleans up (Prowler removing the output that holds its findings) gets to act on.
func TestCancelLetsTheProgramCleanUp(t *testing.T) {
	if !proctest.OwnConsole(t) {
		return
	}
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := proc.Command(ctx, proctest.Trap(t, dir))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	proctest.AwaitFile(t, filepath.Join(dir, "ready"))
	cancel()
	_ = cmd.Wait()
	if _, err := os.Stat(filepath.Join(dir, "stopped")); err != nil {
		t.Fatal("the program was killed without being asked to stop")
	}
}

// Interrupt is the polite stop alone, which a scheduled inventory turns into run_end.
func TestInterruptAsksTheProgramToStop(t *testing.T) {
	if !proctest.OwnConsole(t) {
		return
	}
	dir := t.TempDir()
	cmd := proc.Command(context.Background(), proctest.Trap(t, dir))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	proctest.AwaitFile(t, filepath.Join(dir, "ready"))
	if err := proc.Interrupt(cmd); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("the program did not stop cleanly: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "stopped")); err != nil {
		t.Fatal("the program was not interrupted")
	}
}

func TestOutputKeepsStderrForTheCaller(t *testing.T) {
	cmd := proc.Command(context.Background(), proctest.Script(t, "", "fails", "echo out; echo oops >&2; exit 3"))
	out, err := cmd.Output()
	exit, ok := errors.AsType[*exec.ExitError](err)
	if !ok || exit.ExitCode() != 3 || strings.TrimSpace(string(exit.Stderr)) != "oops" || strings.TrimSpace(string(out)) != "out" {
		t.Fatalf("out %q err %v", out, err)
	}
	both, err := proc.Command(context.Background(), proctest.Script(t, "", "both", "echo out; echo err >&2")).CombinedOutput()
	if err != nil || !strings.Contains(string(both), "out") || !strings.Contains(string(both), "err") {
		t.Fatalf("%q %v", both, err)
	}
}

func TestStartTwiceKeepsTheFirstProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := proc.Command(ctx, proctest.Hung(t, "hung", ""))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err == nil {
		t.Fatal("a second Start succeeded")
	}
	if cmd.ProcessState != nil {
		t.Fatal("the second Start ended the first process")
	}
	cancel()
	_ = cmd.Wait()
}
