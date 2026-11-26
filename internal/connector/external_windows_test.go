package connector_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
)

// On Windows a plugin is executable by its extension: one in PATHEXT that CreateProcess can start,
// .cmd wrappers around a Python script included. The extension is not part of its name.
func TestDiscoverFindsPluginsByPATHEXT(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"segurata-batchy.CMD":  "@echo {\"name\":\"batchy\",\"protocol\":2}\r\n",
		"segurata-scripty.vbs": "WScript.Echo \"never run\"\r\n",
		"segurata-bare":        "#!/bin/sh\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	t.Setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD;.VBS")
	got := connector.Discover()
	if len(got) != 1 || got[0].Describe().Name != "batchy" || !strings.HasSuffix(got[0].Path, ".CMD") {
		t.Fatalf("discovered %+v", got)
	}
}

// The repository's shims never run a py planted in the current directory, even when started by
// hand rather than through the core.
func TestShimsSkipThePlantedPythonLauncher(t *testing.T) {
	for _, shim := range []string{"../../plugins/prowler/segurata-prowler.cmd", "../../examples/hibp/segurata-hibp.cmd"} {
		abs, err := filepath.Abs(shim)
		if err != nil {
			t.Fatal(err)
		}
		cwd := t.TempDir()
		marker := filepath.Join(t.TempDir(), "planted-ran")
		if err := os.WriteFile(filepath.Join(cwd, "py.bat"), []byte("@echo x> \""+marker+"\"\r\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("cmd.exe", "/d", "/c", abs, "describe")
		cmd.Dir = cwd
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(strings.ToLower(kv), "nodefaultcurrentdirectoryinexepath=") {
				cmd.Env = append(cmd.Env, kv)
			}
		}
		_, _ = cmd.CombinedOutput()
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("%s ran the py.bat planted in its working directory", shim)
		}
	}
}
