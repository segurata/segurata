package statefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/segurata/segurata/internal/fileacl"
	"github.com/segurata/segurata/internal/winsys"
)

// retryFor bounds how long a rename waits for another process (Go's own os.Open, an antivirus
// scanner, the indexer) to let go of the file it replaces.
var retryFor = 2 * time.Second

// Rename replaces dst in the same directory. Readers that share delete keep their old handles.
func Rename(src, dst string) error {
	abs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	const deleteAccess = 0x10000
	return retrying(dst, func() error {
		f, err := open(src, deleteAccess)
		if err != nil {
			return err
		}
		err = winsys.RenameFile(syscall.Handle(f.Fd()), abs)
		f.Close()
		if errors.Is(err, winsys.ErrorInvalidParameter) || errors.Is(err, winsys.ErrorNotSupported) {
			return os.Rename(src, dst)
		}
		if err != nil {
			return &os.LinkError{Op: "rename", Old: src, New: dst, Err: err}
		}
		return nil
	})
}

// Open opens name for reading and shares it for deleting too, so a reader never makes a writer's
// rename fail.
func Open(name string) (*os.File, error) {
	return open(name, syscall.GENERIC_READ)
}

func open(name string, access uint32) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	h, err := syscall.CreateFile(p, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(h), name), nil
}

// replaceFile preserves the destination DACL and changes the path with a single rename.
func replaceFile(src, dst string) error {
	if err := fileacl.CopyAccess(dst, src); err != nil {
		if pathErr, ok := errors.AsType[*fs.PathError](err); !ok || pathErr.Path != dst || !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return Rename(src, dst)
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
	for _, e := range []syscall.Errno{syscall.ERROR_ACCESS_DENIED, winsys.ErrorSharingViolation, winsys.ErrorLockViolation} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
