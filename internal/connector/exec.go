package connector

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
)

// ErrRefused is returned for a command that is not on the action's allowlist, before anything runs.
var ErrRefused = errors.New("refused command outside the remediation allowlist")

// Allowlist maps each action to the exact command lines it may run, sudo flag included. There is no
// pattern matching: a step runs only when an entry equals it argument for argument.
type Allowlist map[string][]Step

// Check refuses s unless it is one of the action's allowed steps.
func (a Allowlist) Check(action string, s Step) error {
	if slices.ContainsFunc(a[action], s.Equal) {
		return nil
	}
	return fmt.Errorf("%w: %s: %s", ErrRefused, action, s)
}

// ActionChmod600 makes one file readable and writable by its owner only (700 when the owner could
// execute it, so a script keeps running). It is a generic action the core applies (remediate.Files):
// any connector can attach it to a finding by setting Remediation.Action and putting the file's
// path in evidence.path (absolute, or starting with ~/). With Remediation.Group, one plan closes
// every file of the group.
const ActionChmod600 = "file.chmod600"

// Executor runs one step on the terminal. Tests inject a fake; System is the real one.
type Executor interface {
	Run(ctx context.Context, s Step, io IO) error
}

// sudoPath is absolute so a sudo earlier in PATH cannot intercept the password prompt.
const sudoPath = "/usr/bin/sudo"

// System runs steps as real processes with the terminal attached. A sudo step becomes
// `/usr/bin/sudo <argv>`: sudo reads the password from the terminal itself; nothing here reads,
// stores or pipes it.
type System struct{}

func (System) Run(ctx context.Context, s Step, io IO) error {
	if len(s.Argv) == 0 {
		return errors.New("empty command")
	}
	name, args := s.Argv[0], s.Argv[1:]
	if s.Sudo {
		name, args = sudoPath, s.Argv
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = io.In, io.Out, io.Err
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", s, err)
	}
	return nil
}

// Run checks every command of p against the allowlist, and only when all pass runs them in order
// with ex (nil is System), stopping at the first failure. File changes are not commands; the
// remediator applies them.
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
