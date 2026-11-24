// Package remediate is the core of `segurata remediate`: it finds a finding in the latest run,
// shows the exact plan, asks for confirmation, runs only allowlisted commands and checks afterwards
// that the finding is gone. See docs/architecture.md, "Remediation".
package remediate

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"slices"

	"github.com/segurata/segurata/internal/connector"
)

// ErrRefused is returned for a command that is not on the action's allowlist, before anything runs.
var ErrRefused = errors.New("refused command outside the remediation allowlist")

// Allowlist maps each action to the exact command lines it may run, sudo flag included. There is no
// pattern matching: a step runs only when an entry equals it argument for argument.
type Allowlist map[string][]connector.Step

// Check refuses s unless it is one of the action's allowed steps.
func (a Allowlist) Check(action string, s connector.Step) error {
	if slices.ContainsFunc(a[action], s.Equal) {
		return nil
	}
	return fmt.Errorf("%w: %s: %s", ErrRefused, action, s)
}

// Executor runs one step on the terminal. Tests inject a fake; System is the real one.
type Executor interface {
	Run(ctx context.Context, s connector.Step, io connector.IO) error
}

// sudoPath is absolute so a sudo earlier in PATH cannot intercept the password prompt.
const sudoPath = "/usr/bin/sudo"

// System runs steps as real processes with the terminal attached. A sudo step becomes
// `/usr/bin/sudo <argv>`: sudo reads the password from the terminal itself; nothing here reads,
// stores or pipes it.
type System struct{}

func (System) Run(ctx context.Context, s connector.Step, io connector.IO) error {
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

// Run checks every command of p against the allowlist, and only when all pass runs them in order,
// stopping at the first failure. File changes are not commands; the remediator applies them.
func Run(ctx context.Context, p connector.Plan, allow Allowlist, ex Executor, io connector.IO) error {
	for _, s := range p.Commands {
		if err := allow.Check(p.Action, s); err != nil {
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

// SamePlan refuses to apply a plan that differs from the one the remediator states now, so Apply
// never acts on a stale or altered plan.
func SamePlan(want, got connector.Plan) error {
	if !reflect.DeepEqual(want, got) {
		return errors.New("the plan changed since it was shown: run remediate again to see the current one")
	}
	return nil
}
