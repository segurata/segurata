//go:build unix || windows

package tracker

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/segurata/segurata/internal/fileacl"
)

var lockWait = 2 * time.Minute

// lock exclusively locks <path>.lock. Commands that change the tracker hold it from load to save.
func lock(path string) (func(), error) {
	if err := fileacl.MkdirPrivate(filepath.Dir(path)); err != nil {
		return nil, err
	}
	name := path + ".lock"
	f, err := fileacl.OpenPrivate(name)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lockWait)
	for {
		busy, err := tryLock(f)
		switch {
		case err != nil:
			f.Close()
			return nil, fmt.Errorf("locking %s: %w", name, err)
		case !busy:
			return func() {
				releaseLock(f)
				f.Close()
			}, nil
		case time.Now().After(deadline):
			f.Close()
			return nil, fmt.Errorf("%s is in use by another segurata command (%s held for over %s); try again when it ends", path, name, lockWait)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
