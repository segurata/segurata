//go:build unix

package proc

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// ownGroup starts cmd as the leader of a new process group, and makes its Cancel end the group:
// SIGTERM now, SIGKILL after WaitDelay for whatever ignored it.
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		pgid := -cmd.Process.Pid
		if err := syscall.Kill(pgid, syscall.SIGTERM); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
		time.AfterFunc(WaitDelay, func() { _ = syscall.Kill(pgid, syscall.SIGKILL) })
		return nil
	}
}
