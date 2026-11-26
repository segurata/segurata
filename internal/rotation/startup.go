package rotation

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"

	"github.com/segurata/segurata/internal/secretrisk"
)

// startup is a kind of shell start-up file whose assignment lines --to-keychain rewrites to read
// the value from the platform's credential store when the shell starts.
type startup struct {
	kind, plural string                 // "shell rc" and "shell rc files", for next and refusals
	is           func(path string) bool // whether a used_in name is one
	files        []string               // listed when no used_in file is one
	// assign is the one line shape rewritten: group 1 the head kept before the lookup, group 2 the
	// value (unquoted afterwards), an optional group 3 the line ending kept after it.
	assign  *regexp.Regexp
	shape   string // assign in words, for refusals
	lookup  func(service string) string
	account *regexp.Regexp // what the store's account must look like; nil takes any
	store   string         // where the value goes, as in "new value in <store> as <service>"
	item    string         // one entry there, as in "<item> <service> does not hold…"
	step    string         // the plan's store step, given the service and the account
	// ready checks that the shells reading these files can run the lookup; nil when any can.
	ready func(ctx context.Context, files []string) error
}

// shellRC reads the macOS login Keychain, as docs/secrets.md recommends.
var shellRC = startup{
	kind: "shell rc", plural: "shell rc files", is: secretrisk.IsShellRC, files: secretrisk.ShellRC,
	assign: regexp.MustCompile(`^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=)(.*?)\s*$`),
	shape:  "`export NAME=value`",
	lookup: func(service string) string {
		return fmt.Sprintf(`"$(security find-generic-password -a "$USER" -s %s -w)"`, service)
	},
	account: regexp.MustCompile(`^[A-Za-z0-9._-]+$`),
	store:   "the Keychain", item: "the Keychain item",
	step: "Keychain: store the new value as service %q, account %q (security -i, value on stdin), then read it back to check.",
}

// credReadType is C# for CredReadW, which PowerShell lacks: Add-Type compiles it once per session.
// The blob is read as UTF-16LE text without a terminator, as keychain.CredentialManager stores it.
// Field offsets follow CREDENTIALW up to CredentialBlob on 32- and 64-bit Windows.
const credReadType = `using System;using System.Runtime.InteropServices;namespace Segurata{public static class Cred{` +
	`[StructLayout(LayoutKind.Sequential)]struct C{public int F,T;public IntPtr N,M;public int W1,W2,S;public IntPtr B;}` +
	`[DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CredReadW(string t,int y,int f,out IntPtr c);` +
	`[DllImport("advapi32.dll")]static extern void CredFree(IntPtr c);` +
	`public static string Read(string t){IntPtr p;if(!CredReadW(t,1,0,out p))return null;` +
	`try{C c=(C)Marshal.PtrToStructure(p,typeof(C));return Marshal.PtrToStringUni(c.B,c.S/2);}finally{CredFree(p);}}}}`

// powerShell reads Windows Credential Manager from the user's PowerShell profiles, with no module
// to install. A double-quoted value may not hold ` or $, which PowerShell would expand, and no value
// a quote PowerShell reads as the one that closes it (’ in '…', ” in "…"). CRLF line
// endings and a UTF-8 BOM on the first line are kept.
var powerShell = startup{
	kind: "PowerShell profile", plural: "PowerShell profiles", is: secretrisk.IsPowerShellProfile, files: secretrisk.PowerShellProfiles,
	assign: regexp.MustCompile("(?i)^(\\x{FEFF}?[ \t]*\\$env:[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*)('[^'\u2018-\u201B\r\n]*'|\"[^\"\u201C-\u201E`$\r\n]*\")[ \t]*(\r?)$"),
	shape:  "`$env:NAME = 'value'`",
	lookup: func(service string) string {
		return fmt.Sprintf(`$(if (-not ('Segurata.Cred' -as [type])) { Add-Type -TypeDefinition '%s' }; [Segurata.Cred]::Read('%s'))`, credReadType, service)
	},
	store: "Credential Manager", item: "the Credential Manager item",
	step:  "Credential Manager: store the new value as generic credential %q for %q (local machine, never roaming), then read it back to check.",
	ready: powerShellReady,
}

// errNoShell is languageMode's answer for a PowerShell that is not installed, which runs no profile.
var errNoShell = errors.New("not installed")

// powerShellReady refuses unless every PowerShell that reads one of files runs in FullLanguage
// mode. Constrained Language Mode, which AppLocker and WDAC enforce, blocks Add-Type and the call
// the lookup makes, so a rewritten profile would leave the variable unset in every new session.
func powerShellReady(ctx context.Context, files []string) error {
	asked := map[string]bool{}
	for _, f := range files {
		shell := "pwsh"
		if windowsPowerShellProfile(f) {
			shell = "powershell"
		}
		if asked[shell] {
			continue
		}
		asked[shell] = true
		mode, err := languageMode(ctx, shell)
		switch {
		case errors.Is(err, errNoShell):
		case err != nil:
			return fmt.Errorf("%s: the language mode of %s could not be read, so the Credential Manager lookup may not run there: %w", f, shell, err)
		case mode != "FullLanguage":
			return fmt.Errorf("%s runs in %s mode (AppLocker or WDAC), where the Credential Manager lookup cannot run; store the key by hand and read it from the script that needs it", shell, mode)
		}
	}
	return nil
}

// windowsPowerShellProfile reports whether path is a profile of Windows PowerShell 5.1, under
// Documents\WindowsPowerShell, rather than of PowerShell 7.
func windowsPowerShellProfile(path string) bool {
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' })
	return len(parts) >= 2 && strings.EqualFold(parts[len(parts)-2], "WindowsPowerShell")
}

// toKeychain is the start-up file --to-keychain rewrites here, or nil where no shell can read a
// supported credential store.
var toKeychain = map[string]*startup{"darwin": &shellRC, "windows": &powerShell}[runtime.GOOS]

const toKeychainUnsupported = "--to-keychain needs the macOS Keychain or Windows Credential Manager; here reference the secret as env: or op:// in segurata config, or edit the rc line by hand"
