// Package proc starts the child processes segurata runs under a context.
package proc

import (
	"context"
	"os/exec"
	"time"
)

// WaitDelay is how long Wait still waits for a child's output after the child exited or its
// context ended.
const WaitDelay = 3 * time.Second

// Command is exec.CommandContext with WaitDelay set. Killing a child does not close the pipes a
// grandchild inherited: a wrapper script that does not exec its program (Homebrew's az runs
// python that way) leaves the program holding stdout, and without WaitDelay, Wait blocks until
// that program exits however long the timeout was.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = WaitDelay
	return cmd
}
