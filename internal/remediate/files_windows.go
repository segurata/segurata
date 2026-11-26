//go:build windows

package remediate

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/fileacl"
	"github.com/segurata/segurata/internal/winsys"
)

// plainSDDL is SDDL the undo command can carry in a single-quoted PowerShell string as it is.
// Conditional entries and resource attributes, which need quotes or spaces, fall outside it.
var plainSDDL = regexp.MustCompile(`^[A-Za-z0-9;:()\-]+$`)

func describe(fs.FileMode) string { return "no other account can reach it" }

// private records the old owner and DACL, which the undo restores, and refuses what the undo could
// not restore or MakePrivate would refuse at apply time.
func private(path string, fi fs.FileInfo, was fs.FileMode) (connector.FileChange, error) {
	mine, err := fileacl.OwnedByMe(path, fi)
	if err != nil {
		return connector.FileChange{}, err
	}
	if !mine {
		return connector.FileChange{}, fmt.Errorf("%s is owned by another account", path)
	}
	access, err := fileacl.Fingerprint(path)
	if err != nil {
		return connector.FileChange{}, err
	}
	if !plainSDDL.MatchString(access) {
		return connector.FileChange{}, fmt.Errorf("%s has access entries no undo command could restore; restrict it in its Security settings", path)
	}
	return connector.FileChange{Path: path, Mode: fileacl.Private, Was: was, Access: access}, nil
}

// undo puts the old owner and DACL back with Windows PowerShell from System32, never one earlier in
// PATH, and without a profile that could run first.
func undo(c connector.FileChange) (connector.Step, error) {
	if c.Access == "" || !plainSDDL.MatchString(c.Access) {
		return connector.Step{}, errors.New("no access list to restore")
	}
	sys, err := winsys.System32()
	if err != nil {
		return connector.Step{}, err
	}
	p := connector.PowerShellString(c.Path)
	script := "$a=Get-Acl -LiteralPath " + p + "; $a.SetSecurityDescriptorSddlForm(" + connector.PowerShellString(c.Access) +
		"); Set-Acl -LiteralPath " + p + " -AclObject $a"
	return connector.Step{Argv: []string{filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe"),
		"-NoProfile", "-NonInteractive", "-Command", script}}, nil
}

func makePrivate(c connector.FileChange) error { return fileacl.MakePrivate(c.Path) }
