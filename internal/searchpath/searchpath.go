// Package searchpath cleans PATH values. Standard library only.
package searchpath

import (
	"os"
	"path/filepath"
	"strings"
)

// Clean keeps the first occurrence of each absolute directory in a PATH value, dropping
// duplicates and entries that depend on where or how a process starts (relative, "~", empty): a
// launchd or systemd environment cannot expand them, and an interactive one would resolve them
// against whatever directory it runs in.
func Clean(path string) string {
	seen := map[string]bool{}
	var out []string
	for _, d := range filepath.SplitList(path) {
		d = filepath.Clean(d)
		if !filepath.IsAbs(d) || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return strings.Join(out, string(os.PathListSeparator))
}
