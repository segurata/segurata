// Package statefile reads segurata's JSON state and writes files atomically, so a crash never
// leaves half a file: its own with mode 0600 in a 0700 directory, the user's keeping their mode.
package statefile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
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

// Write writes one of segurata's own files: 0600 in a 0700 directory.
func Write(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return Replace(path, data, 0o600)
}

// Replace writes data with mode to a synced temporary file and renames it over path, which must not
// be a symlink: the rename would replace the link itself.
func Replace(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	return os.Rename(tmp.Name(), path)
}

// Backup writes data, path's content before an edit, to a new 0600 <path>.segurata-bak-<UTC time>
// (-2, -3… within one second) and returns its name. It never overwrites a file.
func Backup(path string, data []byte, now time.Time) (string, error) {
	base := path + ".segurata-bak-" + now.UTC().Format("20060102T150405Z")
	for i := 1; ; i++ {
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		b, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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
