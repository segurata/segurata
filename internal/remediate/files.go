package remediate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// ActionChmod600 makes one file readable and writable by its owner only. Any connector can attach
// it to a finding by setting Remediation.Action and putting the file's path in evidence.path
// (absolute, or starting with ~/).
const ActionChmod600 = "file.chmod600"

// Files implements the generic file actions, which belong to the core rather than to a connector.
type Files struct {
	Home func() (string, error) // expands ~/; os.UserHomeDir by default
}

// Handles reports whether the action is one of the generic file actions.
func (Files) Handles(action string) bool { return action == ActionChmod600 }

func (fs Files) Plan(_ context.Context, f finding.Finding) (connector.Plan, error) {
	if f.Remediation.Action != ActionChmod600 {
		return connector.Plan{}, fmt.Errorf("unknown file action %q", f.Remediation.Action)
	}
	path, err := fs.path(f)
	if err != nil {
		return connector.Plan{}, err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return connector.Plan{}, err
	}
	if !fi.Mode().IsRegular() {
		return connector.Plan{}, fmt.Errorf("%s is not a regular file (symlinks are not followed)", path)
	}
	was := fi.Mode().Perm()
	if was&0o077 == 0 {
		return connector.Plan{}, fmt.Errorf("%s is already private (mode %o): nothing to do", path, was)
	}
	return connector.Plan{
		Action:  ActionChmod600,
		Summary: fmt.Sprintf("Make %s readable and writable by its owner only.", path),
		Files:   []connector.FileChange{{Path: path, Mode: 0o600, Was: was}},
		Undo:    []connector.Step{{Argv: []string{"/bin/chmod", fmt.Sprintf("%o", was), path}}},
		SideEffects: []string{
			"Other users and group members of this machine can no longer read the file; a program running as another user that reads it will fail.",
		},
	}, nil
}

func (fs Files) Apply(ctx context.Context, f finding.Finding, p connector.Plan, _ connector.IO) error {
	want, err := fs.Plan(ctx, f)
	if err != nil {
		return err
	}
	if err := SamePlan(want, p); err != nil {
		return err
	}
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
