// Package homepath writes paths inside the home directory as ~/…, the way findings keep them, and
// back.
package homepath

import (
	"path/filepath"
	"strings"
)

// Expand turns "~" into home and "~/x" into home/x. Any other path, or any path when home is
// unknown (""), is returned unchanged.
func Expand(p, home string) string {
	if home == "" {
		return p
	}
	if p == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return filepath.Join(home, rest)
	}
	return p
}

// Shorten writes home, or a path inside it, as ~ or ~/…. Any other path, or any path when home is
// unknown (""), is returned unchanged.
func Shorten(p, home string) string {
	if home != "" && (p == home || strings.HasPrefix(p, home+string(filepath.Separator))) {
		return "~" + p[len(home):]
	}
	return p
}
