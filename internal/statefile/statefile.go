// Package statefile reads segurata's JSON state and writes files atomically, so a crash never
// leaves half a file. Segurata's state is private and edits keep the user's permissions.
package statefile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/segurata/segurata/internal/fileacl"
)

// ReadJSON decodes the file at path into v. A missing file is not found, with no error; one that
// cannot be read is not found, with the error; one that cannot be decoded is found, with the error.
func ReadJSON(path string, v any) (found bool, err error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, v)
}

func WriteJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return Write(path, append(raw, '\n'))
}

// Write writes one of segurata's own files with private permissions.
func Write(path string, data []byte) error {
	if err := fileacl.MkdirPrivate(filepath.Dir(path)); err != nil {
		return err
	}
	return write(path, data, fileacl.Private, os.Rename)
}

// Replace writes data with mode to a synced temporary file and renames it over path, which must not
// be a symlink. On Windows it keeps the destination's access list.
func Replace(path string, data []byte, mode fs.FileMode) error {
	return write(path, data, mode, replaceFile)
}

func write(path string, data []byte, mode fs.FileMode, rename func(src, dst string) error) error {
	dir := filepath.Dir(path)
	tmp, err := fileacl.CreatePrivate(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return rename(tmp.Name(), path)
}

// Backup writes data, path's content before an edit, to a new private <path>.segurata-bak-<UTC time>
// (-2, -3… within one second) and returns its name. It never overwrites a file.
func Backup(path string, data []byte, now time.Time) (string, error) {
	base := path + ".segurata-bak-" + now.UTC().Format("20060102T150405Z")
	for i := 1; ; i++ {
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		b, err := fileacl.CreatePrivateAt(name)
		if errors.Is(err, fs.ErrExist) && i < 100 {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := b.Write(data); err != nil {
			b.Close()
			return "", err
		}
		return name, b.Close()
	}
}
