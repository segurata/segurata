//go:build unix

package fileacltest

import (
	"fmt"
	"io/fs"
	"os"
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

func expose(path string, dir bool) error {
	if dir {
		return os.Chmod(path, 0o755)
	}
	return os.Chmod(path, 0o644)
}

func access(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%04o", st.Mode().Perm()), nil
}

// giveAway chowns path to nobody's uid. Only root can.
func giveAway(path string) error { return os.Lchown(path, 65534, -1) }
