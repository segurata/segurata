//go:build unix

package proctest

import (
	"os/exec"
	"syscall"
	"testing"
)

func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// OwnConsole is true on Unix, where signals need no console.
func OwnConsole(testing.TB) bool { return true }
