package prompt

import (
	"os"
	"syscall"
)

// IsTerminal reports whether f is a Windows console handle.
func IsTerminal(f *os.File) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil
}
