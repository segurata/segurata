//go:build windows

package proctest

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"
)

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

const consoleEnv = "SEGURATA_PROCTEST_CONSOLE"

// OwnConsole reports whether the test runs with a console of its own, which CTRL_BREAK needs and
// a CI runner may not give. When it does not, it runs the top-level test again in a new hidden
// console, fails if that run fails, and returns false: the caller then returns.
func OwnConsole(t testing.TB) bool {
	t.Helper()
	if os.Getenv(consoleEnv) == "1" {
		return true
	}
	const createNewConsole = 0x10
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.v")
	cmd.Env = append(os.Environ(), consoleEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewConsole, HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("in a console of its own: %v\n%s", err, out)
	}
	return false
}
