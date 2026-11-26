//go:build windows

package winsys

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

// LockFileEx flags.
const (
	LockfileFailImmediately = 0x1
	LockfileExclusiveLock   = 0x2
)

// File errors the syscall package does not name.
const (
	ErrorSharingViolation = syscall.Errno(32)
	ErrorLockViolation    = syscall.Errno(33)
	ErrorNotSupported     = syscall.Errno(50)
	ErrorInvalidParameter = syscall.Errno(87)
)

var (
	procLockFileEx                 = newProc(kernel32, "LockFileEx")
	procUnlockFileEx               = newProc(kernel32, "UnlockFileEx")
	procSetFileInformationByHandle = newProc(kernel32, "SetFileInformationByHandle")
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

// RenameFile atomically renames h to an absolute destination path. Shared readers of the old
// file keep their existing handles. The source handle must have DELETE access.
func RenameFile(h syscall.Handle, destination string) error {
	name, err := syscall.UTF16FromString(destination)
	if err != nil {
		return err
	}
	const (
		fileRenameInfoEx = 22
		replaceIfExists  = 1
		posixSemantics   = 2
	)
	var header struct {
		flags     uint32
		root      syscall.Handle
		nameBytes uint32
		name      uint16
	}
	offset := unsafe.Offsetof(header.name)
	buf := make([]byte, max(unsafe.Sizeof(header), offset+uintptr(2*len(name))))
	binary.LittleEndian.PutUint32(buf, replaceIfExists|posixSemantics)
	binary.LittleEndian.PutUint32(buf[unsafe.Offsetof(header.nameBytes):], uint32(2*(len(name)-1)))
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(&buf[offset])), len(name)), name)
	return procSetFileInformationByHandle.bool(uintptr(h), fileRenameInfoEx, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
}
