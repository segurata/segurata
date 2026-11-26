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
// PATH, and without a profile that could run first. The script calls .NET, no cmdlet, so no module
// is loaded and none in PSModulePath can shadow it, and it stops at its first error. The SDDL
// loads as the owner and DACL sections only, and File.SetAccessControl writes just the sections
// loaded. Set-Acl would not do: it writes the SACL too, which takes SeSecurityPrivilege, which a
// standard user never holds, and for an administrator it erases the file's audit entries.
func undo(c connector.FileChange) (connector.Step, error) {
	if c.Access == "" || !plainSDDL.MatchString(c.Access) {
		return connector.Step{}, errors.New("no access list to restore")
	}
	sys, err := winsys.System32()
	if err != nil {
		return connector.Step{}, err
	}
	script := "$ErrorActionPreference='Stop'; $a=[System.Security.AccessControl.FileSecurity]::new(); $a.SetSecurityDescriptorSddlForm(" +
		connector.PowerShellString(c.Access) + ", 'Owner, Access'); [System.IO.File]::SetAccessControl(" + connector.PowerShellString(c.Path) + ", $a)"
	return connector.Step{Argv: []string{filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe"),
		"-NoProfile", "-NonInteractive", "-Command", script}}, nil
}

func makePrivate(c connector.FileChange) error { return fileacl.MakePrivate(c.Path) }
