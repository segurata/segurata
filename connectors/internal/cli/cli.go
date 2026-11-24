// Package cli runs the CLIs connectors are built on (gcloud, aws, az, rg, gitleaks, git,
// ssh-keygen), and guards them with a read-only check so a bug can never run a mutating command.
// Standard library only.
package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/proc"
)

// Runner runs one CLI command and returns its stdout. Connectors hold one so tests can inject a
// fake in place of Exec.
type Runner interface {
	Run(ctx context.Context, args ...string) ([]byte, error)
}

// RunnerFunc adapts a function to Runner.
type RunnerFunc func(ctx context.Context, args ...string) ([]byte, error)

func (f RunnerFunc) Run(ctx context.Context, args ...string) ([]byte, error) { return f(ctx, args...) }

// Exec runs a real binary with a timeout per command.
type Exec struct {
	Path    string        // binary name, looked up in PATH, or a path to it
	Timeout time.Duration // per command
	Env     []string      // KEY=VALUE pairs added to the inherited environment
}

// Error is a CLI that ran and failed. Stderr is kept whole because that is where the CLIs explain
// failures, and callers classify them from it.
type Error struct {
	Cmd    string // binary and command path, without flags or values after them
	Stderr string
	Err    error
}

func (e *Error) Error() string {
	if s := strings.TrimSpace(e.Stderr); s != "" {
		return fmt.Sprintf("%s: %v: %s", e.Cmd, e.Err, s)
	}
	return fmt.Sprintf("%s: %v", e.Cmd, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Run runs the command. A missing binary keeps exec.ErrNotFound in the chain, a timeout keeps
// context.DeadlineExceeded, and any other failure is an *Error. On an *Error the stdout printed so
// far is returned too, for tools such as rg that exit non-zero after a partial success.
func (e Exec) Run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()
	cmd := proc.Command(ctx, e.Path, args...)
	if len(e.Env) > 0 {
		cmd.Env = append(os.Environ(), e.Env...)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err == nil {
		return out, nil
	}
	label := commandLabel(e.Path, args)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("%s timed out after %s: %w", label, e.Timeout, context.DeadlineExceeded)
	}
	return out, &Error{Cmd: label, Stderr: stderr.String(), Err: err}
}

// commandLabel names a command by its binary's name and the arguments before the first flag.
func commandLabel(path string, args []string) string {
	parts := []string{filepath.Base(path)}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			break
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

// ErrRefused is returned for a command outside the allowlist, before anything runs.
var ErrRefused = errors.New("refused non read-only command")

// Allowlist holds the only command paths a connector may run, each a space-separated leaf command
// such as "iam list-users". A command is allowed when its positional arguments start with one of
// them; whatever follows the path is an argument of that leaf command.
type Allowlist []string

// Check refuses args unless they start with an allowed command path. Self-contained flags
// (--name=value) are skipped wherever they appear. A bare flag before the path is complete is
// refused, because it may take the next word as its value and shift the command the CLI runs.
func (a Allowlist) Check(args []string) error {
	for _, entry := range a {
		if hasPath(args, strings.Fields(entry)) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrRefused, strings.Join(args, " "))
}

func hasPath(args, path []string) bool {
	if len(path) == 0 {
		return false
	}
	i := 0
	for _, arg := range args {
		if i == len(path) {
			return true
		}
		if strings.HasPrefix(arg, "-") {
			if !strings.Contains(arg, "=") {
				return false
			}
			continue
		}
		if arg != path[i] {
			return false
		}
		i++
	}
	return i == len(path)
}

// Guard returns a Runner that checks every command against the allowlist before r sees it.
func (a Allowlist) Guard(r Runner) Runner { return Guard(a, r) }

// Checker decides whether a command line may run. Allowlist fits CLIs with subcommands; CheckFunc
// fits flag-driven tools (rg, ssh-keygen) whose read-only shapes are easier to state as code.
type Checker interface {
	Check(args []string) error
}

// CheckFunc adapts a function to Checker. It should wrap ErrRefused when it refuses.
type CheckFunc func(args []string) error

func (f CheckFunc) Check(args []string) error { return f(args) }

// Guard returns a Runner that checks every command with c before r sees it.
func Guard(c Checker, r Runner) Runner {
	return RunnerFunc(func(ctx context.Context, args ...string) ([]byte, error) {
		if err := c.Check(args); err != nil {
			return nil, err
		}
		return r.Run(ctx, args...)
	})
}
