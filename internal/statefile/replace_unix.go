//go:build unix

package statefile

import "os"

func replaceFile(src, dst string) error { return os.Rename(src, dst) }
