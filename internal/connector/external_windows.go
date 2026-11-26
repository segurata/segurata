//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// startable are the extensions CreateProcess can start, .cmd and .bat through cmd.exe; PATHEXT
// may list others (.vbs, .js) that it cannot.
var startable = []string{".com", ".exe", ".bat", ".cmd"}

// executableExts are the extensions in PATHEXT that CreateProcess can start, lowercase.
func executableExts() []string {
	pathext := os.Getenv("PATHEXT")
	if pathext == "" {
		pathext = ".COM;.EXE;.BAT;.CMD"
	}
	var exts []string
	for _, e := range filepath.SplitList(strings.ToLower(pathext)) {
		if slices.Contains(startable, e) {
			exts = append(exts, e)
		}
	}
	return exts
}

func executable(p string, _ os.FileInfo) bool {
	return slices.Contains(executableExts(), strings.ToLower(filepath.Ext(p)))
}

func trimExecutableExt(name string) string {
	if ext := filepath.Ext(name); slices.Contains(executableExts(), strings.ToLower(ext)) {
		return name[:len(name)-len(ext)]
	}
	return name
}
