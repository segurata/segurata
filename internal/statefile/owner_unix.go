//go:build unix

package statefile

import (
	"io/fs"
	"syscall"
)

// OwnerID is the POSIX owner of a file, when its file information carries one.
func OwnerID(st fs.FileInfo) (int, bool) {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(s.Uid), true
}
