//go:build !(darwin || freebsd || netbsd || openbsd || dragonfly || linux)

package remediate

import "os"

// IsTerminal cannot tell on this platform, so it says no: applying then needs --yes.
func IsTerminal(*os.File) bool { return false }
