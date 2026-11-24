package remediate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// ActionChmod600 makes one file readable and writable by its owner only (700 when the owner could
// execute it, so a script keeps running). Any connector can attach it to a finding by setting
// Remediation.Action and putting the file's path in evidence.path (absolute, or starting with
// ~/). With Remediation.Group, one plan closes every file of the group.
const ActionChmod600 = "file.chmod600"

// Files implements the generic file actions, which belong to the core rather than to a connector.
type Files struct {
	Home func() (string, error) // expands ~/; os.UserHomeDir by default
}

// Handles reports whether the action is one of the generic file actions.
func (Files) Handles(action string) bool { return action == ActionChmod600 }

func (fs Files) Plan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	return fs.PlanGroup(ctx, []finding.Finding{f})
}

func (fs Files) Apply(ctx context.Context, f finding.Finding, p connector.Plan, io connector.IO) error {
	return fs.ApplyGroup(ctx, []finding.Finding{f}, p, io)
}

// PlanGroup reads each file the group names now (several findings may name one file) and plans a
// mode change for those other accounts can still open. A file that cannot be changed is left out
// with the reason; when none can, that is the error.
func (fs Files) PlanGroup(_ context.Context, group []finding.Finding) (connector.Plan, error) {
	p := connector.Plan{Action: ActionChmod600}
	var left []string
	var seen []string
	for _, f := range group {
		if f.Remediation.Action != ActionChmod600 {
			return connector.Plan{}, fmt.Errorf("unknown file action %q", f.Remediation.Action)
		}
		path, err := fs.path(f)
		if err == nil && slices.Contains(seen, path) {
			continue
		}
		seen = append(seen, path)
		var c connector.FileChange
		if err == nil {
			c, err = change(path)
		}
		if err != nil {
			left = append(left, err.Error())
			continue
		}
		p.Files = append(p.Files, c)
		p.Undo = append(p.Undo, connector.Step{Argv: []string{"/bin/chmod", fmt.Sprintf("%o", c.Was), c.Path}})
	}
	switch {
	case len(p.Files) == 0 && len(left) == 1:
		return connector.Plan{}, errors.New(left[0])
	case len(p.Files) == 0:
		return connector.Plan{}, fmt.Errorf("nothing to change in %d files: %s", len(left), strings.Join(left, "; "))
	case len(p.Files) == 1:
		p.Summary = fmt.Sprintf("Make %s readable and writable by its owner only.", p.Files[0].Path)
	default:
		p.Summary = fmt.Sprintf("Make %d files readable and writable by their owner only.", len(p.Files))
	}
	p.SideEffects = []string{
		"Other users and group members of this machine can no longer read the file; a program running as another user that reads it will fail.",
	}
	if len(p.Files) > 1 {
		p.SideEffects[0] = "Other users and group members of this machine can no longer read these files; a program running as another user that reads one will fail."
	}
	for _, why := range left {
		p.SideEffects = append(p.SideEffects, "Left out: "+why+".")
	}
	return p, nil
}

// change is the mode change that closes one file to other accounts: owner read and write, and
// the owner's execute bit as it was.
func change(path string) (connector.FileChange, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return connector.FileChange{}, err
	}
	if !fi.Mode().IsRegular() {
		return connector.FileChange{}, fmt.Errorf("%s is not a regular file (symlinks are not followed)", path)
	}
	was := fi.Mode().Perm()
	if was&0o077 == 0 {
		return connector.FileChange{}, fmt.Errorf("%s is already private (mode %o): nothing to do", path, was)
	}
	return connector.FileChange{Path: path, Mode: 0o600 | was&0o100, Was: was}, nil
}

func (Files) ApplyGroup(_ context.Context, _ []finding.Finding, p connector.Plan, _ connector.IO) error {
	for _, c := range p.Files {
		if err := os.Chmod(c.Path, c.Mode); err != nil {
			return err
		}
	}
	return nil
}

func (fs Files) path(f finding.Finding) (string, error) {
	p, _ := f.Evidence["path"].(string)
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		home := fs.Home
		if home == nil {
			home = os.UserHomeDir
		}
		h, err := home()
		if err != nil {
			return "", err
		}
		p = filepath.Join(h, rest)
	}
	if p == "" || !filepath.IsAbs(p) {
		return "", errors.New("the finding has no absolute evidence.path to change")
	}
	return filepath.Clean(p), nil
}
