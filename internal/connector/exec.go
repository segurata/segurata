package connector

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/segurata/segurata/internal/proc"
)

// ErrRefused is returned for a command that is not on the action's allowlist, before anything runs.
var ErrRefused = errors.New("refused command outside the remediation allowlist")

// Allowlist maps each action to the exact command lines it may run; there is no pattern matching.
type Allowlist map[string][]Step

func (a Allowlist) Check(action string, s Step) error {
	if slices.ContainsFunc(a[action], s.Equal) {
		return nil
	}
	return fmt.Errorf("%w: %s: %s", ErrRefused, action, s)
}

// ActionChmod600 is the core's own action (remediate.Files) for the file at evidence.path: 600, or
// 700 when its owner could execute it. Any connector may attach it.
const ActionChmod600 = "file.chmod600"

// Executor runs one step on the terminal; System is the real one.
type Executor interface {
	Run(ctx context.Context, s Step, io IO) error
}

// sudoPath is absolute so a sudo earlier in PATH cannot intercept the password prompt.
const sudoPath = "/usr/bin/sudo"

type System struct{}

func (System) Run(ctx context.Context, s Step, io IO) error {
	if len(s.Argv) == 0 {
		return errors.New("empty command")
	}
	name, args := s.Argv[0], s.Argv[1:]
	if s.Sudo {
		name, args = sudoPath, s.Argv
	}
	cmd := proc.Interactive(ctx, name, args...) // sudo reads the password from the terminal itself
	cmd.Stdin, cmd.Stdout, cmd.Stderr = io.In, io.Out, io.Err
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", s, err)
	}
	return nil
}

// Run checks every command of p before it runs any, in order, with ex (nil is System).
func (a Allowlist) Run(ctx context.Context, p Plan, ex Executor, io IO) error {
	if ex == nil {
		ex = System{}
	}
	for _, s := range p.Commands {
		if err := a.Check(p.Action, s); err != nil {
			return err
		}
	}
	for _, s := range p.Commands {
		fmt.Fprintf(io.Err, "$ %s\n", s)
		if err := ex.Run(ctx, s, io); err != nil {
			return err
		}
	}
	return nil
}
