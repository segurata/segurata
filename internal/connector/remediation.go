package connector

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

// Remediator is implemented by connectors that can fix some of their own findings. It is optional:
// the core checks for it with a type assertion. External connectors remediate through protocol 2
// (`plan` and `apply`, see External), wrapped by the core in a Remediator of its own.
type Remediator interface {
	// Plan states exactly what Apply would change for f, without changing anything.
	Plan(ctx context.Context, f finding.Finding) (Plan, error)
	// Apply carries out p, which must be the plan Plan returns for f now.
	Apply(ctx context.Context, f finding.Finding, p Plan, io IO) error
}

// Plan is the exact scope of one remediation, shown before anything runs.
type Plan struct {
	Action      string       `json:"action"`
	Summary     string       `json:"summary"`
	Commands    []Step       `json:"commands,omitempty"`
	Files       []FileChange `json:"files,omitempty"`
	Undo        []Step       `json:"undo,omitempty"`
	SideEffects []string     `json:"side_effects,omitempty"`
}

// NeedsSudo reports whether any command runs as root.
func (p Plan) NeedsSudo() bool {
	return slices.ContainsFunc(p.Commands, func(s Step) bool { return s.Sudo })
}

// Step is one exact command line. A sudo step runs as `sudo <argv>` with the terminal attached, so
// sudo asks for the password itself and segurata never sees it.
type Step struct {
	Argv []string `json:"argv"`
	Sudo bool     `json:"sudo,omitempty"`
}

// String is the command as the owner would type it in a shell.
func (s Step) String() string {
	parts := make([]string, 0, len(s.Argv)+1)
	if s.Sudo {
		parts = append(parts, "sudo")
	}
	for _, a := range s.Argv {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}

// Equal reports whether two steps are the same command line run the same way.
func (s Step) Equal(o Step) bool {
	return s.Sudo == o.Sudo && slices.Equal(s.Argv, o.Argv)
}

func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`!*?[]{}()<>|&;#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// FileChange is a permission change made in-process, without running a command.
type FileChange struct {
	Path string      `json:"path"`
	Mode os.FileMode `json:"mode"`
	Was  os.FileMode `json:"was"`
}

func (c FileChange) String() string {
	return fmt.Sprintf("chmod %o %s (now %o)", c.Mode.Perm(), shellQuote(c.Path), c.Was.Perm())
}

// IO is the terminal a remediation runs on. Sudo prompts appear on it.
type IO struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}
