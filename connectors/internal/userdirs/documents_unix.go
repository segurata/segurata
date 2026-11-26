//go:build !windows

package userdirs

import "path/filepath"

// DocumentsFolder is ~/Documents.
func DocumentsFolder(home string) string { return filepath.Join(home, "Documents") }
