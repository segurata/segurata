//go:build unix

package tracker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var lockWait = 2 * time.Minute

// lock takes an exclusive flock on <path>.lock, released by the system if the process dies.
// Commands that change tracker.json hold it from load to save; read-only views do not.
func lock(path string) (unlock func(), err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	name := path + ".lock"
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lockWait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				f.Close()
			}, nil
		case !errors.Is(err, syscall.EWOULDBLOCK):
			f.Close()
			return nil, fmt.Errorf("locking %s: %w", name, err)
		case time.Now().After(deadline):
			f.Close()
			return nil, fmt.Errorf("%s is in use by another segurata command (%s held for over %s); try again when it ends", path, name, lockWait)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
