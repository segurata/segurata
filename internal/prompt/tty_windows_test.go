package prompt

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestIsTerminalDetectsWindowsConsole(t *testing.T) {
	const child = "SEGURATA_TEST_CONSOLE_CHILD"
	if os.Getenv(child) == "1" {
		input, err := os.Open("CONIN$")
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		if !IsTerminal(input) {
			t.Fatal("Windows console input was treated as redirected stdin")
		}
		return
	}
	const createNewConsole = 0x00000010
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestIsTerminalDetectsWindowsConsole$")
	cmd.Env = append(os.Environ(), child+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewConsole, HideWindow: true}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("console subprocess: %v\n%s", err, output)
	}
}
