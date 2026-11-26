package connector

import (
	"runtime"
	"strings"
)

// Quote quotes s as one word for the shell segurata writes commands for on goos: PowerShell on
// Windows, where a single-quoted string is literal and a quote inside it is doubled, and POSIX sh
// elsewhere.
func Quote(goos, s string) string {
	if goos == "windows" {
		if s != "" && !strings.ContainsAny(s, " \t\n`$;(){}@#&|<>,"+psSingleQuotes+psDoubleQuotes) {
			return s
		}
		return PowerShellString(s)
	}
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`!*?[]{}()<>|&;#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// PowerShell's tokenizer takes the typographic quotes for the ASCII ones, so a ’ in a file name
// closes a single-quoted string as ' does.
const (
	psSingleQuotes = "'\u2018\u2019\u201A\u201B"
	psDoubleQuotes = "\"\u201C\u201D\u201E"
)

// PowerShellString is s as a PowerShell string literal, which expands nothing: every
// single-quote character is doubled, which PowerShell reads as that character once.
func PowerShellString(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		if strings.ContainsRune(psSingleQuotes, r) {
			b.WriteRune(r)
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}

func shellQuote(s string) string { return Quote(runtime.GOOS, s) }

// MakePrivateCommand is the command line that makes path, a file or (dir) a folder, private on
// goos: chmod 600 (700) on Unix; on Windows the protected access list segurata gives its own
// files, full control for the account that runs it and SYSTEM, which names no account itself.
func MakePrivateCommand(goos, path string, dir bool) string {
	if goos != "windows" {
		mode := "600"
		if dir {
			mode = "700"
		}
		return "chmod " + mode + " " + Quote(goos, path)
	}
	inherit := ""
	if dir {
		inherit = "OICI"
	}
	p := Quote(goos, path)
	return "$a=Get-Acl -LiteralPath " + p + "; " +
		`$a.SetSecurityDescriptorSddlForm("D:P(A;` + inherit + `;FA;;;$([Security.Principal.WindowsIdentity]::GetCurrent().User))(A;` + inherit + `;FA;;;SY)", 'Access'); ` +
		"$a.SetAccessRuleProtection($true, $false); Set-Acl -LiteralPath " + p + " -AclObject $a"
}
