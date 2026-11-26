package connector

import (
	"strings"
	"testing"
)

func TestQuoteForEachShell(t *testing.T) {
	for _, c := range []struct{ goos, in, want string }{
		{"darwin", "/h/plain", "/h/plain"},
		{"linux", "/h/it's here", `'/h/it'\''s here'`},
		{"linux", "~/x", "'~/x'"},
		{"windows", `C:\plain\x`, `C:\plain\x`},
		{"windows", `C:\it's here`, `'C:\it''s here'`},
		{"windows", "$env:X", "'$env:X'"},
		{"windows", "", "''"},
		{"windows", "C:\\a\u2019;calc;\u2018.env", "'C:\\a\u2019\u2019;calc;\u2018\u2018.env'"},
		{"windows", "C:\\Bob\u2019s", "'C:\\Bob\u2019\u2019s'"},
		{"windows", "C:\\\u201Bx\u201A", "'C:\\\u201B\u201Bx\u201A\u201A'"},
		{"windows", "C:\\\u201Cx\u201D\u201E", "'C:\\\u201Cx\u201D\u201E'"},
	} {
		if got := Quote(c.goos, c.in); got != c.want {
			t.Errorf("Quote(%s, %q) = %s, want %s", c.goos, c.in, got, c.want)
		}
	}
}

func TestMakePrivateCommand(t *testing.T) {
	if got := MakePrivateCommand("linux", "/h/a b", false); got != "chmod 600 '/h/a b'" {
		t.Errorf("file: %s", got)
	}
	if got := MakePrivateCommand("darwin", "/h/out", true); got != "chmod 700 /h/out" {
		t.Errorf("folder: %s", got)
	}
	win := MakePrivateCommand("windows", `C:\Users\it's\.config`, false)
	for _, want := range []string{"-LiteralPath 'C:\\Users\\it''s\\.config'", "D:P(A;;FA;;;$(", ")(A;;FA;;;SY)", "'Access'",
		"SetAccessRuleProtection($true, $false)"} {
		if !strings.Contains(win, want) {
			t.Errorf("windows file command lacks %q: %s", want, win)
		}
	}
	if dir := MakePrivateCommand("windows", `C:\d`, true); !strings.Contains(dir, "(A;OICI;FA;;;SY)") {
		t.Errorf("a folder passes its access list down: %s", dir)
	}
	for _, leak := range []string{"S-1-5-21", "USERNAME", "icacls"} {
		if strings.Contains(win, leak) {
			t.Errorf("the command must resolve the account when run, never carry it: %s", win)
		}
	}
}
