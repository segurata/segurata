//go:build unix

package connector

// sudoPath is absolute so a sudo earlier in PATH cannot intercept the password prompt.
const sudoPath = "/usr/bin/sudo"

func commandLine(s Step) (string, []string, error) {
	if s.Sudo {
		return sudoPath, s.Argv, nil
	}
	return s.Argv[0], s.Argv[1:], nil
}
