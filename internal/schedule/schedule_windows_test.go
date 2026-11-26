package schedule

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

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
// conhost starts the way Task Scheduler starts the task's action: with no console and no standard
// handles. Started with NUL as input, as exec.Cmd would, a headless conhost reads end of input
// and closes the console, ending the command, at once.
func TestHeadlessConhostRunsTheCommand(t *testing.T) {
	var env Env
	if err := env.LoadTaskHost(); err != nil {
		t.Fatal(err)
	}
	sys := filepath.Dir(env.SchTasks)
	marker := filepath.Join(t.TempDir(), "ran")
	// About two seconds pass before the command leaves its marker.
	script := filepath.Join(sys, "PING.EXE") + " -n 3 127.0.0.1 >nul & echo x> " + marker
	line, err := syscall.UTF16PtrFromString(strings.Join([]string{windowsArg(env.Conhost), "--headless",
		windowsArg(filepath.Join(sys, "cmd.exe")), "/d", "/c", windowsArg(script)}, " "))
	if err != nil {
		t.Fatal(err)
	}
	const detachedProcess = 0x8
	si := syscall.StartupInfo{Cb: uint32(unsafe.Sizeof(syscall.StartupInfo{}))}
	var pi syscall.ProcessInformation
	if err := syscall.CreateProcess(nil, line, nil, nil, false, detachedProcess, nil, nil, &si, &pi); err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(pi.Thread)
	defer syscall.CloseHandle(pi.Process)
	if ev, err := syscall.WaitForSingleObject(pi.Process, 30000); ev != syscall.WAIT_OBJECT_0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		t.Fatalf("conhost --headless did not return: %d %v", ev, err)
	}
	var code uint32
	if err := syscall.GetExitCodeProcess(pi.Process, &code); err != nil || code != 0 {
		t.Fatalf("conhost --headless exited %d %v", code, err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("conhost --headless returned before the command ended: %v", err)
	}
}
