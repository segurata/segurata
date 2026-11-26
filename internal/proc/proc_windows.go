//go:build windows

package proc

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/segurata/segurata/internal/winsys"
)

// sysCmd says whether the process leads a process group of its own, and holds its job.
type sysCmd struct {
	group bool
	job   *job
}

// job is a kill-on-close job object that Cancel, a timer and Wait may reach concurrently.
type job struct {
	mu sync.Mutex
	h  syscall.Handle
}

func (j *job) assign(process syscall.Handle) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return winsys.AssignToJob(j.h, process)
}

func (j *job) terminate() error {
	if j == nil {
		return os.ErrProcessDone
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.h == 0 {
		return os.ErrProcessDone
	}
	return winsys.TerminateJob(j.h, 1)
}

// close ends whatever is still in the job.
func (j *job) close() {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.h != 0 {
		_ = syscall.CloseHandle(j.h)
		j.h = 0
	}
}

// prepare makes Cancel send a Command CTRL_BREAK, then end its job after WaitDelay. An
// Interactive command shares segurata's process group, which a CTRL_BREAK would reach too, so its
// job is ended at once.
func (c *Cmd) prepare() {
	c.Cancel = func() error {
		if c.ctrlBreak() == nil {
			time.AfterFunc(WaitDelay, func() { _ = c.sys.job.terminate() })
			return nil
		}
		return c.sys.job.terminate()
	}
}

func (c *Cmd) ctrlBreak() error {
	if !c.sys.group {
		return errors.New("no process group of its own")
	}
	return winsys.GenerateConsoleCtrlEvent(winsys.CtrlBreakEvent, uint32(c.Process.Pid))
}

func (c *Cmd) interrupt() error {
	if c.ctrlBreak() == nil {
		return nil
	}
	return c.sys.job.terminate()
}

// beforeStart refuses a batch wrapper an argument cmd.exe would interpret, then makes the process
// start suspended, so that it cannot start a child before it is in its job.
func (c *Cmd) beforeStart() error {
	if err := checkBatchArgs(c.resolved(), c.Args[1:]); err != nil {
		return err
	}
	h, err := winsys.NewKillOnCloseJob()
	if err != nil {
		return fmt.Errorf("%s: job object: %w", c.Path, err)
	}
	c.sys.job = &job{h: h}
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	c.SysProcAttr.CreationFlags |= winsys.CreateSuspended
	if c.sys.group {
		c.SysProcAttr.CreationFlags |= syscall.CREATE_NEW_PROCESS_GROUP
	}
	return nil
}

// resolved is the file Start will run: exec adds the PATHEXT extension of a path given without
// one only when it starts it.
func (c *Cmd) resolved() string {
	switch strings.ToLower(filepath.Ext(c.Path)) {
	case ".exe", ".com", ".cmd", ".bat":
		return c.Path
	}
	p := c.Path
	if c.Dir != "" && !filepath.IsAbs(p) {
		p = filepath.Join(c.Dir, p)
	}
	if lp, err := exec.LookPath(p); err == nil {
		return lp
	}
	return c.Path
}

// adopt puts the suspended process in its job and lets it run. Opening it by PID is safe: a
// suspended process cannot exit, so its PID cannot be reused. A process that cannot be put in its
// job is killed before it runs a single instruction.
func (c *Cmd) adopt() error {
	if err := c.resume(uint32(c.Process.Pid)); err != nil {
		_ = c.Process.Kill()
		_ = c.Cmd.Wait()
		c.release()
		return fmt.Errorf("%s: %w", c.Path, err)
	}
	return nil
}

func (c *Cmd) resume(pid uint32) error {
	h, err := winsys.OpenForJob(pid)
	if err != nil {
		return fmt.Errorf("open process: %w", err)
	}
	defer syscall.CloseHandle(h)
	if err := c.sys.job.assign(h); err != nil {
		return fmt.Errorf("job object: %w", err)
	}
	threads, err := winsys.Threads(pid)
	if err != nil {
		return fmt.Errorf("threads: %w", err)
	}
	if len(threads) == 0 {
		return errors.New("threads: none found")
	}
	for _, tid := range threads {
		if err := winsys.ResumeThread(tid); err != nil {
			return fmt.Errorf("resume: %w", err)
		}
	}
	return nil
}

func (c *Cmd) release() { c.sys.job.close() }
