//go:build windows

package rotation

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/proc"
	"github.com/segurata/segurata/internal/winsys"
)

// languageMode is the language mode a new session of shell ("powershell" from System32, or "pwsh"
// on PATH) runs in, as a profile would; the profile itself is not loaded.
var languageMode = func(ctx context.Context, shell string) (string, error) {
	var exe string
	if shell == "powershell" {
		sys, err := winsys.System32()
		if err != nil {
			return "", err
		}
		exe = filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	} else {
		p, err := exec.LookPath("pwsh.exe")
		if err != nil {
			return "", errNoShell
		}
		exe = p
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := proc.Command(ctx, exe, "-NoProfile", "-NonInteractive", "-Command", "$ExecutionContext.SessionState.LanguageMode").Output()
	return strings.TrimSpace(string(out)), err
}
