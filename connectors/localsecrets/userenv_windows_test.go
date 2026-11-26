package localsecrets

import (
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/segurata/segurata/internal/winsys"
)

// The registry reader returns string values as stored, expandable ones unexpanded, and nothing
// else. It reads a key of its own, never the user's environment.
func TestRegistryStringsReadsStringValues(t *testing.T) {
	sys, err := winsys.System32()
	if err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(sys, "reg.exe")
	sub := fmt.Sprintf(`Software\segurata-test-%d`, os.Getpid())
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(reg, args...).CombinedOutput(); err != nil {
			t.Fatalf("reg %v: %v: %s", args[0], err, out)
		}
	}
	value := fake("", 30)
	run("add", `HKCU\`+sub, "/v", "SYNTHETIC_TOKEN", "/t", "REG_SZ", "/d", value, "/f")
	t.Cleanup(func() { exec.Command(reg, "delete", `HKCU\`+sub, "/f").Run() })
	run("add", `HKCU\`+sub, "/v", "Expandable", "/t", "REG_EXPAND_SZ", "/d", `%USERPROFILE%\x`, "/f")
	run("add", `HKCU\`+sub, "/v", "Number", "/t", "REG_DWORD", "/d", "7", "/f")
	got, err := registryStrings(syscall.HKEY_CURRENT_USER, sub)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"SYNTHETIC_TOKEN": value, "Expandable": `%USERPROFILE%\x`}; !maps.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if _, err := registryStrings(syscall.HKEY_CURRENT_USER, sub+`\missing`); err == nil {
		t.Error("a missing key is an error, not an empty environment")
	}
}
