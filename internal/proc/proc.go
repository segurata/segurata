// Package proc starts child processes under a context. On Unix each runs in a process group of its
// own that cancelling ends, SIGTERM first so a program can clean up (Prowler's temporary directory,
// the token it was lent), then SIGKILL after WaitDelay, so no background child outlives it. On
// Windows only the direct child is killed.
package proc

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
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

// Runner runs one external program with stdin and returns its stdout.
type Runner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

// Exec is the real Runner, bounded to 30 seconds. Its error carries stderr, never stdout, which
// may hold a secret value.
func Exec(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := Command(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}
