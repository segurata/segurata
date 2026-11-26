//go:build windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/fileacl"
	"github.com/segurata/segurata/internal/fileacl/fileacltest"
	"github.com/segurata/segurata/internal/winsys"
)

// The command segurata prints for an exposed file or folder really closes it when pasted into
// Windows PowerShell: nothing but the user, SYSTEM and Administrators keeps access.
func TestMakePrivateCommandClosesTheFile(t *testing.T) {
	sys, err := winsys.System32()
	if err != nil {
		t.Fatal(err)
	}
	ps := filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	dir := filepath.Join(t.TempDir(), "it's shared")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "x\u2019;exit 7;\u2018credentials")
	if err := os.WriteFile(file, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path string
		dir  bool
	}{{file, false}, {dir, true}} {
		fileacltest.Expose(t, c.path)
		if m, err := fileacl.Exposure(c.path); err != nil || !fileacl.Exposed(m) {
			t.Fatalf("%s not exposed before: %o %v", c.path, m, err)
		}
		cmd := MakePrivateCommand("windows", c.path, c.dir)
		run := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", cmd)
		run.Env = freshPowerShellEnv()
		if out, err := run.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", cmd, err, out)
		}
		if m, err := fileacl.Exposure(c.path); err != nil || fileacl.Exposed(m) {
			t.Errorf("%s still exposed: %o %v", c.path, m, err)
		}
		if c.dir {
			if open, err := fileacl.ChangeableByOthers(c.path); err != nil || open {
				t.Errorf("%s still changeable by others: %v", c.path, err)
			}
		}
	}
}

// freshPowerShellEnv is this process's environment as a newly opened Windows PowerShell gets it:
// without the PSModulePath a PowerShell 7 parent (the CI step's shell) prepends its own modules to,
// which Windows PowerShell cannot load.
func freshPowerShellEnv() []string {
	return slices.DeleteFunc(os.Environ(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return strings.EqualFold(name, "PSModulePath")
	})
}
