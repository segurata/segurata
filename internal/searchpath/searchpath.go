// Package searchpath cleans PATH values.
package searchpath

import (
	"os"
	"path/filepath"
	"strings"
)

// Clean keeps the first occurrence of each absolute directory in a PATH value: relative, "~" and
// empty entries would resolve against whatever directory a process starts in.
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
