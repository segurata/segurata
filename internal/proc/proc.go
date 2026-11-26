// Package proc starts child processes under a context, so that cancelling ends everything a child
// started. On Unix each runs in a process group of its own that cancelling ends, SIGTERM first so
// a program can clean up (Prowler's temporary directory, the token it was lent), then SIGKILL
// after WaitDelay. On Windows each runs in a job object, started suspended so that no grandchild
// escapes it: cancelling sends CTRL_BREAK, then ends the job after WaitDelay, and Wait ends what
// is left in it.
package proc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// WaitDelay bounds Wait after the child exited or its context ended, and the time between the
// polite signal and the kill.
const WaitDelay = 3 * time.Second

// Cmd is an exec.Cmd whose Start puts the process under segurata's control before it runs. Start,
// Run, Wait, Output and CombinedOutput must be called on the Cmd, never on the embedded exec.Cmd.
type Cmd struct {
	*exec.Cmd
	sys sysCmd
}

// Command is exec.CommandContext with WaitDelay and its own process group (a job on Windows).
// Without WaitDelay a grandchild holding an inherited pipe (Homebrew's az wraps python) would block
// Wait past the timeout. The group is not the terminal's foreground one: a command that reads the
// terminal must use Interactive.
func Command(ctx context.Context, name string, args ...string) *Cmd {
	return newCmd(ctx, true, name, args)
}

// Interactive is Command in segurata's own process group, for a program attached to the terminal,
// so that the owner's Ctrl-C reaches it.
func Interactive(ctx context.Context, name string, args ...string) *Cmd {
	return newCmd(ctx, false, name, args)
}

func newCmd(ctx context.Context, group bool, name string, args []string) *Cmd {
	c := &Cmd{Cmd: exec.CommandContext(ctx, name, args...)}
	c.WaitDelay = WaitDelay
	c.sys.group = group
	c.prepare()
	return c
}

// Interrupt asks the program to stop the way a terminal would: SIGINT on Unix, CTRL_BREAK on
// Windows, which Go programs receive as os.Interrupt. A program without a process group of its own
// on Windows, or when segurata has no console, is ended instead.
func Interrupt(c *Cmd) error { return c.interrupt() }

func (c *Cmd) Start() error {
	if c.Process != nil {
		return errors.New("exec: already started")
	}
	if c.Err == nil {
		c.Err = c.beforeStart() // on the exec.Cmd, so that its Start closes the pipes it made
	}
	if err := c.Cmd.Start(); err != nil {
		c.release()
		return err
	}
	return c.adopt()
}

func (c *Cmd) Wait() error {
	err := c.Cmd.Wait()
	c.release()
	return err
}

func (c *Cmd) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}

// Output is exec.Cmd.Output: stdout, and the start of stderr in an *exec.ExitError when Stderr is
// unset.
func (c *Cmd) Output() ([]byte, error) {
	if c.Stdout != nil {
		return nil, errors.New("exec: Stdout already set")
	}
	var stdout bytes.Buffer
	c.Stdout = &stdout
	var stderr *capped
	if c.Stderr == nil {
		stderr = &capped{n: 64 << 10}
		c.Stderr = stderr
	}
	err := c.Run()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok && stderr != nil {
		ee.Stderr = stderr.Bytes()
	}
	return stdout.Bytes(), err
}

func (c *Cmd) CombinedOutput() ([]byte, error) {
	if c.Stdout != nil || c.Stderr != nil {
		return nil, errors.New("exec: Stdout or Stderr already set")
	}
	var b bytes.Buffer
	c.Stdout, c.Stderr = &b, &b
	err := c.Run()
	return b.Bytes(), err
}

// capped keeps the first n bytes written to it and accepts the rest.
type capped struct {
	bytes.Buffer
	n int
}

func (w *capped) Write(p []byte) (int, error) {
	if room := w.n - w.Len(); room > 0 {
		w.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// ErrBatchArgument is why a batch wrapper is not started: cmd.exe would read an argument as syntax.
var ErrBatchArgument = errors.New("an argument cmd.exe would interpret")

// batchUnsafe are the characters cmd.exe reads as syntax even inside the quotes Go adds: Go
// escapes arguments for CreateProcess, not for the cmd.exe that runs a .cmd or .bat file.
const batchUnsafe = "\r\n%^&|<>!\""

// checkBatchArgs refuses to hand cmd.exe, through the .cmd or .bat file path, an argument it would
// interpret, which would turn a configured value into a command. The error names the argument by
// position, never by value, and is an *exec.Error, like a program that could not start.
func checkBatchArgs(path string, args []string) error {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".cmd" && ext != ".bat" {
		return nil
	}
	for i, a := range args {
		if strings.ContainsAny(a, batchUnsafe) || strings.HasSuffix(a, `\`) {
			return &exec.Error{Name: path, Err: fmt.Errorf("%w: %s is a batch wrapper; segurata will not pass argument %d through cmd.exe",
				ErrBatchArgument, filepath.Base(path), i+1)}
		}
	}
	return nil
}

// Runner runs one external program with stdin and returns its stdout.
type Runner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

// Exec is the real Runner, bounded to 30 seconds. Its error carries stderr, never stdout, which
// may hold a secret value.
func Exec(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := Command(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}
