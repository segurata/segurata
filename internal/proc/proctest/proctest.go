// Package proctest writes fake executables for tests of code that runs child processes. A fake is
// the test binary itself under another name, or a shell script; a test package that uses them
// runs its tests through Main.
package proctest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// sleepEnv marks the child a hung fake starts.
const sleepEnv = "SEGURATA_PROCTEST_SLEEP"

// Main runs the tests, unless this process is one of the fakes Helper made, which then does its
// part and exits.
func Main(m *testing.M) {
	if os.Getenv(sleepEnv) == "1" {
		time.Sleep(60 * time.Second)
		os.Exit(0)
	}
	if exe, err := os.Executable(); err == nil {
		if raw, err := os.ReadFile(base(exe) + ".helper"); err == nil {
			os.Exit(helper(exe, strings.TrimSpace(string(raw))))
		}
	}
	os.Exit(m.Run())
}

// base is a fake's path without the .exe Windows needs.
func base(exe string) string { return strings.TrimSuffix(exe, ".exe") }

func helper(exe, behavior string) int {
	verb, arg, _ := strings.Cut(behavior, " ")
	switch verb {
	case "hung":
		// The way a wrapper that does not exec its program behaves: a child holds stdout. The child
		// is the test binary itself, so that this copy is not held open once killed.
		child := exec.Command(arg)
		child.Env = append(os.Environ(), sleepEnv+"=1")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Run(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("done")
		return 0
	case "trap":
		// A program that cleans up when asked to stop: it marks the file stopped and exits 0.
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		if err := touch(filepath.Join(arg, "ready")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		select {
		case <-stop:
			if err := touch(filepath.Join(arg, "stopped")); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			return 0
		case <-time.After(60 * time.Second):
			return 1
		}
	case "spawn", "orphan":
		// A wrapper that ignores being asked to stop and starts a child outside its process group,
		// then waits for it (spawn) or leaves it behind (orphan). The child's PID goes to dir/pid.
		signal.Notify(make(chan os.Signal, 1), os.Interrupt, syscall.SIGTERM)
		self, dir, _ := strings.Cut(arg, "\t")
		child := exec.Command(self)
		child.Env = append(os.Environ(), sleepEnv+"=1")
		detach(child)
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		tmp := filepath.Join(dir, "pid.tmp")
		if err := os.WriteFile(tmp, []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil || os.Rename(tmp, filepath.Join(dir, "pid")) != nil {
			fmt.Fprintln(os.Stderr, "cannot record the child's pid")
			return 1
		}
		if verb == "orphan" {
			return 0
		}
		_ = child.Wait()
		return 0
	case "sh":
		cmd := exec.Command(arg, append([]string{base(exe) + ".sh"}, os.Args[1:]...)...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		err := cmd.Run()
		var exit *exec.ExitError
		switch {
		case errors.As(err, &exit):
			return exit.ExitCode()
		case err != nil:
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "last-path-error":
		if len(os.Args) > 1 {
			fmt.Fprintf(os.Stderr, "rg: %s: %s\n", os.Args[len(os.Args)-1], arg)
		}
		return 2
	}
	fmt.Fprintf(os.Stderr, "proctest: unknown helper %q\n", behavior)
	return 2
}

// Helper makes the test binary an executable named name in dir (a fresh one when dir is empty),
// with .exe on Windows, that does behavior when started, and returns its path. The test package
// must run its tests through Main.
func Helper(t testing.TB, dir, name, behavior string) string {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		path += ".exe"
	}
	// Windows cannot delete a link to the running test binary, so it gets a copy.
	if runtime.GOOS == "windows" || os.Link(self, path) != nil {
		if err := copyFile(self, path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(base(path)+".helper", []byte(behavior), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Script makes an executable named name in dir (a fresh one when dir is empty) that runs the POSIX
// shell body, and returns its path. On Unix it is a #!/bin/sh script; on Windows a Helper that hands
// body to the sh of Git for Windows, and the test is skipped where there is none.
func Script(t testing.TB, dir, name, body string) string {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	if runtime.GOOS != "windows" {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	sh := Shell(t)
	path := Helper(t, dir, name, "sh "+sh)
	if err := os.WriteFile(base(path)+".sh", []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Shell is the POSIX sh scripts run with, and skips the test where there is none.
func Shell(t testing.TB) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		if pf := os.Getenv("ProgramFiles"); pf != "" {
			if p := filepath.Join(pf, "Git", "bin", "sh.exe"); isFile(p) {
				return p
			}
		}
	}
	p, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX sh on this system")
	}
	return p
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// Hung makes an executable that waits on a child holding its stdout, the way a wrapper that does
// not exec its program behaves, and returns its path. extra shell lines run first (a `describe`
// answer, say); without them the fake is the test binary, so it runs on every platform.
func Hung(t testing.TB, name, extra string) string {
	t.Helper()
	if extra == "" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		return Helper(t, "", name, "hung "+self)
	}
	return Script(t, "", name, extra+"\nsleep 60\necho done\n")
}

// Trap makes an executable that, asked to stop (os.Interrupt, or SIGTERM on Unix), creates
// dir/stopped and exits 0. It creates dir/ready once it listens.
func Trap(t testing.TB, dir string) string {
	t.Helper()
	return Helper(t, "", "trap", "trap "+dir)
}

// Spawn makes an executable that ignores being asked to stop and starts a sleeping child in a
// process group of its own, which a signal to the parent's group misses, and writes the child's
// PID to dir/pid. With orphan it exits at once and leaves the child behind; without, it waits.
func Spawn(t testing.TB, dir string, orphan bool) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	verb := "spawn"
	if orphan {
		verb = "orphan"
	}
	return Helper(t, "", verb, verb+" "+self+"\t"+dir)
}

// PID waits for the PID a Spawn fake wrote to dir/pid.
func PID(t testing.TB, dir string) int {
	t.Helper()
	path := filepath.Join(dir, "pid")
	AwaitFile(t, path)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

func touch(path string) error { return os.WriteFile(path, nil, 0o600) }

// AwaitFile waits until path exists: a script touches it once it is ready (a signal trap
// installed, a child started), so the test cancels a command that can no longer be cut short
// before that point, however loaded the machine.
func AwaitFile(t testing.TB, path string) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared", filepath.Base(path))
		}
	}
}
