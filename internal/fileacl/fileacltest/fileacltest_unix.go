//go:build unix

package fileacltest

import (
	"fmt"
	"io/fs"
)

func notPrivate(_ string, st fs.FileInfo) string {
	want := fs.FileMode(0o600)
	if st.IsDir() {
		want = 0o700
	}
	if st.Mode().Perm() != want {
		return fmt.Sprintf("mode %04o, want %04o", st.Mode().Perm(), want)
	}
	return ""
}
