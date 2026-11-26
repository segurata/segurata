// Package homepath writes paths inside the home directory as ~/…, the way findings keep them, and
// back. The ~ form uses forward slashes on every OS, so finding ids and tracker keys are the same
// wherever the scan ran.
package homepath

import (
	"path/filepath"
	"runtime"
	"strings"
)

const windows = runtime.GOOS == "windows"

// Expand turns "~" into home and "~/x" (also "~\x" on Windows) into home/x. Any other path, or any
// path when home is unknown (""), is returned unchanged.
func Expand(p, home string) string { return expand(p, home, windows) }

// Shorten writes home, or a path inside it, as ~ or ~/…. On Windows either separator is accepted and
// the home prefix is compared ignoring case, as the file system does. Any other path, or any path
// when home is unknown (""), is returned unchanged.
func Shorten(p, home string) string { return shorten(p, home, windows) }

func expand(p, home string, win bool) string {
	if home == "" {
		return p
	}
	if p == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(slashed(p, win), "~/"); ok {
		return filepath.Join(home, rest)
	}
	return p
}

func shorten(p, home string, win bool) string {
	if home == "" {
		return p
	}
	same := func(a, b string) bool { return a == b || win && strings.EqualFold(a, b) }
	path, root := slashed(p, win), slashed(home, win)
	if same(path, root) {
		return "~"
	}
	root = strings.TrimSuffix(root, "/")
	if len(path) > len(root) && path[len(root)] == '/' && same(path[:len(root)], root) {
		return "~/" + path[len(root)+1:]
	}
	return p
}

func slashed(p string, win bool) string {
	if win {
		return strings.ReplaceAll(p, `\`, "/")
	}
	return p
}
