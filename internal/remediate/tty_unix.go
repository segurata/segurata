//go:build darwin || freebsd || netbsd || openbsd || dragonfly || linux

package remediate

import (
	"os"
	"syscall"
	"unsafe"
)

// IsTerminal reports whether f is an interactive terminal. A character device is not enough:
// /dev/null is one too, and a confirmation read from it would be an answer nobody gave.
func IsTerminal(f *os.File) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), getTermios, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}
