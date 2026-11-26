package statefile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"

	"github.com/segurata/segurata/internal/winsys"
)

// retryFor bounds how long a rename waits for another process (Go's own os.Open, an antivirus
// scanner, the indexer) to let go of the file it replaces.
var retryFor = 2 * time.Second

// Rename is os.Rename (MoveFileEx with MOVEFILE_REPLACE_EXISTING), retried while dst is held open
// without FILE_SHARE_DELETE.
func Rename(src, dst string) error {
	return retrying(dst, func() error { return os.Rename(src, dst) })
}

// Open opens name for reading and shares it for deleting too, so a reader never makes a writer's
// rename fail.
func Open(name string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(h), name), nil
}

// replaceFile puts src in place of the user's file dst with ReplaceFileW, which keeps dst's DACL
// (and creation time and streams) where a rename would give the file src's private descriptor.
func replaceFile(src, dst string) error {
	if _, err := os.Lstat(dst); errors.Is(err, fs.ErrNotExist) {
		return Rename(src, dst)
	}
	err := retrying(dst, func() error { return winsys.ReplaceFile(dst, src, winsys.ReplacefileIgnoreMergeErrors) })
	if !errors.Is(err, winsys.ErrorUnableToMoveReplacement) {
		if err != nil {
			return &fs.PathError{Op: "replace", Path: dst, Err: err}
		}
		return nil
	}
	// Without a backup name this error means dst is gone and src still holds the new content under
	// its own name; it takes dst's place with src's private descriptor.
	if err := Rename(src, dst); err != nil {
		return fmt.Errorf("replacing %s: %w; %w at %s", dst, err, errKeptTemp, src)
	}
	return nil
}

// retrying runs op until it succeeds, fails for good, or retryFor passes. Only the errors another
// process's handle on an existing dst causes are retried.
func retrying(dst string, op func() error) error {
	deadline := time.Now().Add(retryFor)
	wait := 10 * time.Millisecond
	for {
		err := op()
		if err == nil || !transient(err) || time.Now().After(deadline) {
			return err
		}
		if _, serr := os.Lstat(dst); serr != nil {
			return err
		}
		time.Sleep(wait)
		wait = min(2*wait, 50*time.Millisecond)
	}
}

func transient(err error) bool {
	for _, e := range []syscall.Errno{syscall.ERROR_ACCESS_DENIED, winsys.ErrorSharingViolation, winsys.ErrorLockViolation, winsys.ErrorUnableToRemoveReplaced} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
