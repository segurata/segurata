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

// Remediator fixes some of a built-in connector's own findings.
type Remediator interface {
	// Plan states exactly what Apply would change for f, without changing anything.
	Plan(ctx context.Context, f finding.Finding) (Plan, error)
	// Apply runs only after a fresh Plan for f returned p unchanged.
	Apply(ctx context.Context, f finding.Finding, p Plan, io IO) error
}

// GroupRemediator fixes every finding sharing finding.Remediation.Group in one plan, first one first.
type GroupRemediator interface {
	Remediator
	PlanGroup(ctx context.Context, fs []finding.Finding) (Plan, error)
	ApplyGroup(ctx context.Context, fs []finding.Finding, p Plan, io IO) error
}

// CredentialedRemediator receives the instance's credentials before Plan.
type CredentialedRemediator interface {
	WithCredentials(c Credentials) Remediator
}

// Credentials are an instance's resolved read request and its unresolved remediation_secrets,
// write credentials that only Apply resolves, through Write.
type Credentials struct {
	Request   Request
	WriteRefs map[string]string                                     // name -> reference, unresolved
	Resolve   func(ctx context.Context, ref string) (string, error) // secrets.Resolve
}

func (c Credentials) HasWrite(name string) bool { return c.WriteRefs[name] != "" }

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
	// Blocked says what to set up before the plan can be applied; --apply refuses it.
	Blocked string `json:"blocked,omitempty"`
}

func (p Plan) NeedsSudo() bool {
	return slices.ContainsFunc(p.Commands, func(s Step) bool { return s.Sudo })
}

func (p Plan) NeedsTerminal() bool {
	return slices.ContainsFunc(p.Commands, func(s Step) bool { return s.Terminal })
}

// Step is one exact command line. Sudo and Terminal steps run attached to the owner's terminal, so
// segurata never sees a password, and never run without one, --yes or not.
type Step struct {
	Argv     []string `json:"argv"`
	Sudo     bool     `json:"sudo,omitempty"`
	Terminal bool     `json:"terminal,omitempty"`
}

// String is the command line as the platform's shell takes it: POSIX sh on Unix, PowerShell on
// Windows.
func (s Step) String() string {
	parts := make([]string, 0, len(s.Argv)+1)
	if s.Sudo {
		parts = append(parts, "sudo")
	}
	for _, a := range s.Argv {
		parts = append(parts, shellQuote(a))
	}
	return callOperator(parts) + strings.Join(parts, " ")
}

func (s Step) Equal(o Step) bool {
	return s.Sudo == o.Sudo && s.Terminal == o.Terminal && slices.Equal(s.Argv, o.Argv)
}

// Call is one HTTP request without a body, made with the write credential named Secret.
type Call struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

func (c Call) String() string {
	return fmt.Sprintf("%s %s (with %s)", c.Method, c.URL, c.Secret)
}

// FileChange makes one file private. Mode and Was are exposures as fileacl gives them: the modes on
// Unix, and on Windows what other accounts get from the DACL, with Access the old owner and DACL
// as SDDL, so a plan goes stale whenever the access list changes.
type FileChange struct {
	Path   string      `json:"path"`
	Mode   os.FileMode `json:"mode"`
	Was    os.FileMode `json:"was"`
	Access string      `json:"access,omitempty"`
}

type IO struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}
