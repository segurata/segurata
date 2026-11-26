package remediate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/fileacl"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/homepath"
)

// files applies the generic file actions, which belong to the core rather than to a connector.
type files struct {
	home func() (string, error) // nil means os.UserHomeDir
}

func (fs files) Plan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	return fs.PlanGroup(ctx, []finding.Finding{f})
}

func (fs files) Apply(ctx context.Context, f finding.Finding, p connector.Plan, io connector.IO) error {
	return fs.ApplyGroup(ctx, []finding.Finding{f}, p, io)
}

// PlanGroup plans making private each file the group names (once per file) that other accounts
// can still open. A file that cannot be changed is left out with the reason; when none can, that is
// the error.
func (fs files) PlanGroup(_ context.Context, group []finding.Finding) (connector.Plan, error) {
	p := connector.Plan{Action: connector.ActionChmod600}
	var left []string
	seen := map[string]bool{}
	for _, f := range group {
		if f.Remediation.Action != connector.ActionChmod600 {
			return connector.Plan{}, fmt.Errorf("unknown file action %q", f.Remediation.Action)
		}
		path, err := fs.path(f)
		if err == nil {
			if seen[path] {
				continue
			}
			seen[path] = true
		}
		var c connector.FileChange
		var u connector.Step
		if err == nil {
			c, err = change(path)
		}
		if err == nil {
			u, err = undo(c)
		}
		if err != nil {
			left = append(left, err.Error())
			continue
		}
		p.Files = append(p.Files, c)
		p.Undo = append(p.Undo, u)
	}
	switch {
	case len(p.Files) == 0 && len(left) == 1:
		return connector.Plan{}, errors.New(left[0])
	case len(p.Files) == 0:
		return connector.Plan{}, fmt.Errorf("nothing to change in %d files: %s", len(left), strings.Join(left, "; "))
	case len(p.Files) == 1:
		p.Summary = fmt.Sprintf("Make %s readable and writable by its owner only.", p.Files[0].Path)
		p.SideEffects = []string{"Other users and group members of this machine can no longer read the file; a program running as another user that reads it will fail."}
	default:
		p.Summary = fmt.Sprintf("Make %d files readable and writable by their owner only.", len(p.Files))
		p.SideEffects = []string{"Other users and group members of this machine can no longer read these files; a program running as another user that reads one will fail."}
	}
	for _, why := range left {
		p.SideEffects = append(p.SideEffects, "Left out: "+why+".")
	}
	return p, nil
}

// change closes one file to other accounts.
func change(path string) (connector.FileChange, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return connector.FileChange{}, err
	}
	if !fi.Mode().IsRegular() {
		return connector.FileChange{}, fmt.Errorf("%s is not a regular file (symlinks are not followed)", path)
	}
	was, err := fileacl.Exposure(path)
	if err != nil {
		return connector.FileChange{}, err
	}
	if !fileacl.Exposed(was) {
		return connector.FileChange{}, fmt.Errorf("%s is already private (%s): nothing to do", path, describe(was))
	}
	return private(path, fi, was)
}

func (files) ApplyGroup(_ context.Context, _ []finding.Finding, p connector.Plan, _ connector.IO) error {
	for _, c := range p.Files {
		if err := makePrivate(c); err != nil {
			return err
		}
	}
	return nil
}

func (fs files) path(f finding.Finding) (string, error) {
	p, _ := f.Evidence["path"].(string)
	if strings.HasPrefix(p, "~/") {
		home := fs.home
		if home == nil {
			home = os.UserHomeDir
		}
		h, err := home()
		if err != nil {
			return "", err
		}
		p = homepath.Expand(p, h)
	}
	if !filepath.IsAbs(p) {
		return "", errors.New("the finding has no absolute evidence.path to change")
	}
	return filepath.Clean(p), nil
}
