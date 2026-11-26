package schedule

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/segurata/segurata/internal/fileacl/fileacltest"
)

func TestWindowsArgIsSyscallEscapeArg(t *testing.T) {
	for _, s := range []string{"", "plain", `C:\Program Files\x.exe`, `a"b`, `a\"b`, `C:\dir with space\`, "tab\there",
		`say "hi" \\ now`, `trailing\\ space \\`, `C:\a\b\`, `quote at end"`, `\\server\share\segurata x`} {
		if got, want := windowsArg(s), syscall.EscapeArg(s); got != want {
			t.Errorf("windowsArg(%q) = %q, syscall.EscapeArg %q", s, got, want)
		}
	}
}

// Task Scheduler accepts the task segurata writes, registered under a test name and removed again.
func TestTaskSchedulerRegistersQueriesAndDeletesTheTask(t *testing.T) {
	defer func(n string) { taskName = n }(taskName)
	taskName = `segurata\test-` + strconv.Itoa(os.Getpid())
	env, _, out := testEnv(t, "windows")
	local := env.LocalAppData
	if err := env.LoadTaskHost(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(strings.ToLower(env.SchTasks), `\system32\schtasks.exe`) {
		t.Fatalf("schtasks %s", env.SchTasks)
	}
	// The log stays in the test's folder, and the first run is a day away, past the test.
	env.LocalAppData, env.Runner, env.Now = local, System{}, time.Now
	ctx := context.Background()
	t.Cleanup(func() {
		_ = System{}.Run(context.Background(), env.SchTasks, []string{"/Delete", "/TN", taskName, "/F"}, io.Discard, io.Discard)
	})
	if err := env.Install(ctx, Options{Apply: true, Yes: true}); err != nil {
		t.Fatalf("%v\n%s\n%s", err, out, env.IO.Err)
	}
	fileacltest.AssertPrivate(t, env.Paths().Task)
	a, err := env.agent(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !env.loaded(ctx, a) {
		t.Fatal("the task is not registered")
	}
	var xml bytes.Buffer
	if err := (System{}).Run(ctx, env.SchTasks, []string{"/Query", "/TN", taskName, "/XML"}, &xml, io.Discard); err != nil {
		t.Fatal(err)
	}
	registered := text(xml.Bytes())
	for _, want := range []string{"InteractiveToken", "IgnoreNew", "--log", "conhost.exe</Command>", "<Arguments>--headless "} {
		if !strings.Contains(registered, want) {
			t.Errorf("registered task lacks %s:\n%s", want, registered)
		}
	}
	// Task Scheduler leaves the default run level, LeastPrivilege, out of the definition it returns.
	if strings.Contains(registered, "<RunLevel>") && !strings.Contains(registered, "<RunLevel>LeastPrivilege</RunLevel>") {
		t.Errorf("registered task runs above least privilege:\n%s", registered)
	}
	out.Reset()
	if err := env.Status(ctx); err != nil || !strings.Contains(out.String(), "installed, registered") {
		t.Fatalf("status %v\n%s", err, out)
	}
	if err := env.Uninstall(ctx, Options{Apply: true, Yes: true}); err != nil {
		t.Fatal(err)
	}
	if env.loaded(ctx, a) {
		t.Fatal("the task is still registered")
	}
	if _, err := os.Stat(env.Paths().Task); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the task file is still there")
	}
}

// text reads schtasks output, which is UTF-16LE when it holds NUL bytes.
func text(raw []byte) string {
	if !bytes.Contains(raw, []byte{0}) {
		return string(raw)
	}
	raw = bytes.TrimPrefix(raw, []byte{0xFF, 0xFE})
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(units))
}

// The task's windowless console host runs the command it is given, and returns once it ends.
func TestHeadlessConhostRunsTheCommand(t *testing.T) {
	var env Env
	if err := env.LoadTaskHost(); err != nil {
		t.Fatal(err)
	}
	cmdExe := filepath.Join(filepath.Dir(env.SchTasks), "cmd.exe")
	marker := filepath.Join(t.TempDir(), "ran")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, env.Conhost, "--headless", cmdExe, "/d", "/c", "echo x> "+marker).Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("conhost --headless did not run the command: %v", err)
	}
}
