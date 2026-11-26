//go:build windows

package winsys

import (
	"syscall"
	"unsafe"
)

// LockFileEx flags.
const (
	LockfileFailImmediately = 0x1
	LockfileExclusiveLock   = 0x2
)

// ReplaceFileW flags.
const ReplacefileIgnoreMergeErrors = 0x2

// File errors the syscall package does not name.
const (
	ErrorSharingViolation        = syscall.Errno(32)
	ErrorLockViolation           = syscall.Errno(33)
	ErrorUnableToRemoveReplaced  = syscall.Errno(1175)
	ErrorUnableToMoveReplacement = syscall.Errno(1176)
)

var (
	procLockFileEx   = newProc(kernel32, "LockFileEx")
	procUnlockFileEx = newProc(kernel32, "UnlockFileEx")
	procReplaceFileW = newProc(kernel32, "ReplaceFileW")
)

// LockFile locks the whole file through h.
func LockFile(h syscall.Handle, flags uint32) error {
	var o syscall.Overlapped
	return procLockFileEx.bool(uintptr(h), uintptr(flags), 0, 0xffffffff, 0xffffffff, uintptr(unsafe.Pointer(&o)))
}

// UnlockFile releases what LockFile took.
func UnlockFile(h syscall.Handle) error {
	var o syscall.Overlapped
	return procUnlockFileEx.bool(uintptr(h), 0, 0xffffffff, 0xffffffff, uintptr(unsafe.Pointer(&o)))
}

// ReplaceFile puts replacement in place of replaced, which keeps its own security descriptor and
// attributes, without a backup.
func ReplaceFile(replaced, replacement string, flags uint32) error {
	a, err := syscall.UTF16PtrFromString(replaced)
	if err != nil {
		return err
	}
	b, err := syscall.UTF16PtrFromString(replacement)
	if err != nil {
		return err
	}
	return procReplaceFileW.bool(uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(b)), 0, uintptr(flags), 0, 0)
}
