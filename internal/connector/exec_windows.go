//go:build windows

package connector

import (
	"fmt"
	"path/filepath"
)

// commandLine refuses a sudo step: Windows has no sudo to prompt on the terminal, and elevation
// is the owner's to grant from an elevated prompt.
func commandLine(s Step) (string, []string, error) {
	if s.Sudo {
		return "", nil, fmt.Errorf("%s needs an elevated prompt; run it by hand: %s", filepath.Base(s.Argv[0]), Step{Argv: s.Argv})
	}
	return s.Argv[0], s.Argv[1:], nil
}
