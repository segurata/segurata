//go:build unix

package fileacl

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// OwnedByMe reports whether fi, the information of path, names the current user as its owner.
func OwnedByMe(path string, fi fs.FileInfo) (bool, error) {
	uid, err := ownerUID(fi)
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return uid == os.Getuid(), nil
}

func ownerUID(fi fs.FileInfo) (int, error) {
	s, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("the file information carries no owner")
	}
	return int(s.Uid), nil
}

// Exposure is the file's own permission bits.
func Exposure(path string) (fs.FileMode, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return st.Mode().Perm(), nil
}

// Effective is the exposure once the folders up to root have had their say: a class reaches the
// file only if every parent lets that class through, so a 644 file in a 700 home is closed. A
// parent that cannot be read is left out.
func Effective(path, root string) (fs.FileMode, error) {
	eff, err := Exposure(path)
	if err != nil {
		return 0, err
	}
	for d := filepath.Dir(path); ; d = filepath.Dir(d) {
		if ds, err := os.Stat(d); err == nil {
			if ds.Mode().Perm()&0o010 == 0 {
				eff &^= 0o070
			}
			if ds.Mode().Perm()&0o001 == 0 {
				eff &^= 0o007
			}
		}
		if d == root || filepath.Dir(d) == d {
			return eff, nil
		}
	}
}

// ChangeableByOthers reports whether another account could rename or replace what dir holds: it
// is owned by someone other than root and the user, or others can write to it without the sticky
// bit, which keeps them to their own entries.
func ChangeableByOthers(dir string) (bool, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return false, err
	}
	uid, err := ownerUID(st)
	if err != nil {
		return false, fmt.Errorf("%s: %w", dir, err)
	}
	return uid != 0 && uid != os.Getuid() || st.Mode().Perm()&0o022 != 0 && st.Mode()&fs.ModeSticky == 0, nil
}

// MakePrivate gives a file mode 0600 and a directory 0700.
func MakePrivate(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := Private
	if st.IsDir() {
		mode = 0o700
	}
	return os.Chmod(path, mode)
}

// CreatePrivate is os.CreateTemp, which already creates with mode 0600.
func CreatePrivate(dir, pattern string) (*os.File, error) { return os.CreateTemp(dir, pattern) }

// CreatePrivateAt exclusively creates path with mode 0600.
func CreatePrivateAt(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, Private)
}

// MkdirPrivate creates dir and any missing parents with mode 0700, leaving existing ones as they
// are.
func MkdirPrivate(dir string) error { return os.MkdirAll(dir, 0o700) }

// Describe is the file's mode, for messages.
func Describe(path string) (string, error) {
	m, err := Exposure(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("mode %04o", m), nil
}

// Fingerprint changes whenever the file's access does: its mode.
func Fingerprint(path string) (string, error) {
	m, err := Exposure(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%04o", m), nil
}
