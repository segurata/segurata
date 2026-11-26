//go:build unix

package statefile

import "os"

// Rename is os.Rename.
func Rename(src, dst string) error { return os.Rename(src, dst) }

// Open is os.Open.
func Open(name string) (*os.File, error) { return os.Open(name) }

// replaceFile renames src over dst; the temporary file already has dst's mode.
func replaceFile(src, dst string) error { return os.Rename(src, dst) }
