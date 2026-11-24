// Package statefile writes files atomically, so a crash never leaves half a file: segurata's
// own files (rotation ledger, accepted risks, reports) with mode 0600 in a 0700 directory, and the
// user's files that `segurata rotations replace` and `segurata redact` edit, keeping their mode.
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

// WriteJSON writes v as indented JSON to path.
func WriteJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return Write(path, append(raw, '\n'))
}

// Write writes one of segurata's own files: mode 0600, creating its directory with 0700.
func Write(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return Replace(path, data, 0o600)
}

// Replace writes data to a temporary file next to path with the given mode, flushes it to disk and
// renames it over path. path must not be a symlink: the rename would replace the link itself.
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

// Backup writes data, the content of path before an edit, to a new 0600 file next to it named
// <path>.segurata-bak-<UTC timestamp>, adding -2, -3… when a backup from the same second exists,
// and returns that name. It never overwrites a file.
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
