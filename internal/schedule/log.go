package schedule

import (
	"io"
	"os"
	"path/filepath"

	"github.com/segurata/segurata/internal/fileacl"
)

// OpenLog opens a scheduled run's log for appending, private from creation. A log another account
// can reach is made private first: it names findings.
func OpenLog(path string) (*os.File, error) {
	if err := fileacl.MkdirPrivate(filepath.Dir(path)); err != nil {
		return nil, err
	}
	f, err := fileacl.OpenPrivate(path)
	if err != nil {
		return nil, err
	}
	m, err := fileacl.Exposure(path)
	if err == nil && fileacl.Exposed(m) {
		err = fileacl.MakePrivate(path)
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekEnd)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
