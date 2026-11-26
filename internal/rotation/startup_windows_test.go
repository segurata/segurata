//go:build windows

package rotation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/segurata/segurata/internal/keychain"
	"github.com/segurata/segurata/internal/winsys"
)

// The line --to-keychain writes into a PowerShell profile reads back, in Windows PowerShell and in
// PowerShell 7 when installed, exactly the value Credential Manager's Store wrote, without loading
// a profile or a module; a missing item leaves the variable unset.
func TestPowerShellLookupReadsWhatStoreWrote(t *testing.T) {
	if toKeychain != &powerShell {
		t.Fatal("--to-keychain on Windows must rewrite PowerShell profiles")
	}
	target, value := "segurata-test-"+rand.Text(), "synthetic-"+rand.Text()
	t.Cleanup(func() { _ = winsys.CredDelete(target, 1) })
	if err := keychain.Default("tester").Store(context.Background(), target, value); err != nil {
		t.Fatal(err)
	}
	shells := []string{"powershell"}
	if _, err := exec.LookPath("pwsh"); err == nil {
		shells = append(shells, "pwsh")
	}
	for _, shell := range shells {
		for name, c := range map[string]struct{ service, want string }{
			"stored":  {target, value},
			"missing": {target + "-missing", ""},
		} {
			script := "$env:SEGURATA_TEST_VALUE = " + powerShell.lookup(c.service) + "\n" +
				"if ($env:SEGURATA_TEST_VALUE -ceq '" + c.want + "' -or (-not $env:SEGURATA_TEST_VALUE -and -not '" + c.want + "')) { exit 0 }; exit 3"
			// -EncodedCommand keeps the quotes in the lookup away from command-line parsing.
			u := utf16.Encode([]rune(script))
			b := make([]byte, 2*len(u))
			for i, r := range u {
				binary.LittleEndian.PutUint16(b[2*i:], r)
			}
			out, err := exec.Command(shell, "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(b)).CombinedOutput()
			if err != nil {
				t.Errorf("%s, %s item: %v: %s", shell, name, err, strings.ReplaceAll(string(out), value, "[value]"))
			}
		}
	}
}

// The probe reads the language mode a new Windows PowerShell session gets.
func TestLanguageModeOfWindowsPowerShell(t *testing.T) {
	mode, err := languageMode(context.Background(), "powershell")
	if err != nil || mode != "FullLanguage" {
		t.Fatalf("%q %v", mode, err)
	}
	if mode, err := languageMode(context.Background(), "pwsh"); err != nil && !errors.Is(err, errNoShell) || err == nil && mode == "" {
		t.Fatalf("pwsh: %q %v", mode, err)
	}
}
