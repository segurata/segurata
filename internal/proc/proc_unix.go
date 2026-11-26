//go:build unix

package proc

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// sysCmd says whether the process leads a process group of its own.
type sysCmd struct{ group bool }

// prepare makes a Command lead a new process group that Cancel ends: SIGTERM, then SIGKILL after
// WaitDelay. An Interactive command keeps exec's own Cancel.
func (c *Cmd) prepare() {
	if !c.sys.group {
		return
	}
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error {
		pgid := -c.Process.Pid
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

func (c *Cmd) beforeStart() error { return nil }
func (c *Cmd) adopt() error       { return nil }
func (c *Cmd) release()           {}
func (c *Cmd) interrupt() error   { return c.Process.Signal(os.Interrupt) }
