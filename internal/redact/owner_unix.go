//go:build unix

package redact

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByMe reports whether the current account owns the file. Rewriting replaces the file with a
// new one owned by whoever writes it, so a file of another account is left alone.
func ownedByMe(st fs.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return !ok || int(s.Uid) == os.Getuid()
}
