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
	// Apply carries out p. The core calls it only after Plan for f, asked again just before, returned
	// p unchanged, so Apply needs no stale-plan check of its own.
	Apply(ctx context.Context, f finding.Finding, p Plan, io IO) error
}

// GroupRemediator is implemented by a Remediator whose actions fix several findings in one plan:
// those sharing finding.Remediation.Group (a GitHub owner's repositories, a tenant's expired
// secrets). The core gathers the group, f first, and calls these instead of Plan and Apply.
type GroupRemediator interface {
	Remediator
	PlanGroup(ctx context.Context, fs []finding.Finding) (Plan, error)
	ApplyGroup(ctx context.Context, fs []finding.Finding, p Plan, io IO) error
}

// CredentialedRemediator is implemented by a built-in Remediator that talks to its provider with
// the instance's credentials. The core hands them over before Plan.
type CredentialedRemediator interface {
	WithCredentials(c Credentials) Remediator
}

// Credentials are what a remediation of one connector instance may use: the inventory request
// (read credentials, already resolved) and the references of the instance's remediation_secrets,
// write credentials kept apart from the inventory's. Inventory never sees the latter; only Apply
// resolves one, through Write.
type Credentials struct {
	Request   Request
	WriteRefs map[string]string                                     // name -> reference, unresolved
	Resolve   func(ctx context.Context, ref string) (string, error) // secrets.Resolve
}

// HasWrite reports whether the config names a reference for the write secret, without resolving it.
func (c Credentials) HasWrite(name string) bool { return c.WriteRefs[name] != "" }

// Write resolves one write secret. Only Apply calls it, after the owner confirmed.
func (c Credentials) Write(ctx context.Context, name string) (string, error) {
	ref := c.WriteRefs[name]
	if ref == "" || c.Resolve == nil {
		return "", fmt.Errorf("%s is not configured under remediation_secrets", name)
	}
	v, err := c.Resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return v, nil
}

// Plan is the exact scope of one remediation, shown before anything runs.
type Plan struct {
	Action      string       `json:"action"`
	Summary     string       `json:"summary"`
	Commands    []Step       `json:"commands,omitempty"`
	Calls       []Call       `json:"calls,omitempty"`
	Files       []FileChange `json:"files,omitempty"`
	Undo        []Step       `json:"undo,omitempty"`
	SideEffects []string     `json:"side_effects,omitempty"`
	// Blocked says why the plan cannot be applied now and what to set up first (a write credential
	// that is not configured). A dry run shows it; --apply refuses before asking.
	Blocked string `json:"blocked,omitempty"`
}

// NeedsSudo reports whether any command runs as root.
func (p Plan) NeedsSudo() bool {
	return slices.ContainsFunc(p.Commands, func(s Step) bool { return s.Sudo })
}

// NeedsTerminal reports whether any command needs the owner at the terminal while it runs.
func (p Plan) NeedsTerminal() bool {
	return slices.ContainsFunc(p.Commands, func(s Step) bool { return s.Terminal })
}

// Step is one exact command line. A sudo step runs as `sudo <argv>` with the terminal attached, so
// sudo asks for the password itself and segurata never sees it. A terminal step is interactive in
// the same way (a browser sign-in, a prompt): it never runs without a terminal, --yes or not.
type Step struct {
	Argv     []string `json:"argv"`
	Sudo     bool     `json:"sudo,omitempty"`
	Terminal bool     `json:"terminal,omitempty"`
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
	return s.Sudo == o.Sudo && s.Terminal == o.Terminal && slices.Equal(s.Argv, o.Argv)
}

// Call is one HTTP request without a body, made in-process with a write credential named by
// Secret (never its value).
type Call struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

func (c Call) String() string {
	return fmt.Sprintf("%s %s (with %s)", c.Method, c.URL, c.Secret)
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
