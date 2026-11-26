package tracker

import (
	"errors"
	"os"
	"syscall"

	"github.com/segurata/segurata/internal/winsys"
)

func tryLock(f *os.File) (busy bool, err error) {
	const lockViolation = syscall.Errno(33)
	err = winsys.LockFile(syscall.Handle(f.Fd()), winsys.LockfileExclusiveLock|winsys.LockfileFailImmediately)
	if errors.Is(err, lockViolation) {
		return true, nil
	}
	return false, err
}

func releaseLock(f *os.File) { _ = winsys.UnlockFile(syscall.Handle(f.Fd())) }
