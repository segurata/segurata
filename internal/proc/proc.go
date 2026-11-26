// Package proc starts child processes under a context. On Unix each runs in a process group of its
// own that cancelling ends, SIGTERM first so a program can clean up (Prowler's temporary directory,
// the token it was lent), then SIGKILL after WaitDelay, so no background child outlives it. On
// Windows only the direct child is killed.
package proc

import (
	"context"
	"os/exec"
	"time"
)

// WaitDelay bounds Wait after the child exited or its context ended, and the time between SIGTERM
// and SIGKILL.
const WaitDelay = 3 * time.Second

// Command is exec.CommandContext with WaitDelay and its own process group. Without WaitDelay a
// grandchild holding an inherited pipe (Homebrew's az wraps python) would block Wait past the
// timeout. The group is not the terminal's foreground one: a command that reads the terminal
// must use Interactive.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := Interactive(ctx, name, args...)
	ownGroup(cmd)
	return cmd
}

// Interactive is Command in segurata's own process group, for a program attached to the terminal.
func Interactive(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = WaitDelay
	return cmd
}
