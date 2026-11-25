// Package proc starts the child processes segurata runs under a context.
//
// On Unix each command runs in a process group of its own, and cancelling the context ends the
// whole group: SIGTERM first, so a program can clean up (Prowler's temporary directory, the token
// it was lent), then SIGKILL once WaitDelay is up. A child the command started in the background
// never outlives it. On Windows only the direct child is killed, as exec.CommandContext does: a
// program it started keeps running until it exits by itself.
package proc

import (
	"context"
	"os/exec"
	"time"
)

// WaitDelay is how long Wait still waits for a child's output after the child exited or its
// context ended, and how long a cancelled process group has between SIGTERM and SIGKILL.
const WaitDelay = 3 * time.Second

// Command is exec.CommandContext with WaitDelay set and, on Unix, its own process group that
// cancelling kills. Killing a child does not close the pipes a grandchild inherited: a wrapper
// script that does not exec its program (Homebrew's az runs python that way) leaves the program
// holding stdout, and without WaitDelay, Wait blocks until that program exits however long the
// timeout was.
//
// The group is not the terminal's foreground group, so a command that reads the terminal (a sudo
// password prompt) must use Interactive instead.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := Interactive(ctx, name, args...)
	ownGroup(cmd)
	return cmd
}

// Interactive is Command for a program attached to the owner's terminal: it stays in segurata's
// process group, which the terminal reads from, and cancelling kills only the program itself.
func Interactive(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = WaitDelay
	return cmd
}
