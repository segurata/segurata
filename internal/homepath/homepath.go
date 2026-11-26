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
	if rest, ok := strings.CutPrefix(filepath.ToSlash(p), "~/"); ok {
		return filepath.Join(home, rest)
	}
	return p
}

// Shorten writes home, or a path inside it, as ~ or ~/…. Any other path, or any path when home is
// unknown (""), is returned unchanged.
func Shorten(p, home string) string {
	if home == "" {
		return p
	}
	path, root := filepath.ToSlash(p), filepath.ToSlash(home)
	if path == root {
		return "~"
	}
	if rest, ok := strings.CutPrefix(path, strings.TrimSuffix(root, "/")+"/"); ok {
		return "~/" + rest
	}
	return p
}
