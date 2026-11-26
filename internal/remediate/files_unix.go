//go:build unix

package remediate

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/segurata/segurata/internal/connector"
)

func describe(mode fs.FileMode) string { return fmt.Sprintf("mode %o", mode) }

// private is mode 600, or 700 when the owner could execute the file.
func private(path string, _ fs.FileInfo, was fs.FileMode) (connector.FileChange, error) {
	return connector.FileChange{Path: path, Mode: 0o600 | was&0o100, Was: was}, nil
}

func undo(c connector.FileChange) (connector.Step, error) {
	return connector.Step{Argv: []string{"/bin/chmod", fmt.Sprintf("%o", c.Was), c.Path}}, nil
}

func makePrivate(c connector.FileChange) error { return os.Chmod(c.Path, c.Mode) }
