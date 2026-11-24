// Package statefile writes files atomically, so a crash never leaves half a file: securizame's
// own state files (rotation ledger, accepted risks) as JSON, mode 0600, in a 0700 directory, and
// the user's files that `securizame rotations replace` edits, keeping their mode.
package statefile

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteJSON writes v as indented JSON to path.
func WriteJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return Replace(path, append(raw, '\n'), 0o600)
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
