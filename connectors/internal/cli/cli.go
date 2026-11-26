// Package cli runs the CLIs connectors are built on, behind a read-only check so a bug can never
// run a mutating command.
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

// Runner runs one CLI command and returns its stdout.
type Runner interface {
	Run(ctx context.Context, args ...string) ([]byte, error)
}

type RunnerFunc func(ctx context.Context, args ...string) ([]byte, error)

func (f RunnerFunc) Run(ctx context.Context, args ...string) ([]byte, error) { return f(ctx, args...) }

// Exec runs a real binary.
type Exec struct {
	Path    string        // looked up in PATH unless it is a path
	Timeout time.Duration // per command
	Env     []string      // added to the inherited environment
	// StderrCheck judges the stderr of a command that exited 0, for a CLI that reports some
	// failures only there (gitleaks logs the git errors it swallows).
	StderrCheck func(stderr string) error
}

// Error is a CLI that ran and failed, with its whole stderr: callers classify failures from it.
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

// Stderr is what a failed command printed on stderr, or the error itself when it printed nothing.
func Stderr(err error) string {
	if ce, ok := errors.AsType[*Error](err); ok && strings.TrimSpace(ce.Stderr) != "" {
		return ce.Stderr
	}
	return err.Error()
}

// Run keeps exec.ErrNotFound or context.DeadlineExceeded in the chain; any other failure is an
// *Error, returned with the stdout so far for tools such as rg that exit non-zero after a partial
// success.
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
	if err == nil && e.StderrCheck != nil {
		err = e.StderrCheck(stderr.String())
	}
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

var ErrRefused = errors.New("refused non read-only command")

// Allowlist holds the only command paths a connector may run, such as "iam list-users"; whatever
// follows a path is an argument of that leaf command.
type Allowlist []string

// Check skips --name=value flags wherever they appear, and refuses a bare flag before the path is
// complete: it may take the next word as its value and shift the command the CLI runs.
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

func (a Allowlist) Guard(r Runner) Runner { return Guard(a, r) }

// Checker decides whether a command line may run: an Allowlist for CLIs with subcommands, a
// CheckFunc for flag-driven tools whose read-only shapes are easier stated as code.
type Checker interface {
	Check(args []string) error
}

// CheckFunc should wrap ErrRefused when it refuses.
type CheckFunc func(args []string) error

func (f CheckFunc) Check(args []string) error { return f(args) }

func Guard(c Checker, r Runner) Runner {
	return RunnerFunc(func(ctx context.Context, args ...string) ([]byte, error) {
		if err := c.Check(args); err != nil {
			return nil, err
		}
		return r.Run(ctx, args...)
	})
}
