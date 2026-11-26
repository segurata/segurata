//go:build windows

package connector

import "testing"

// A step is shown as PowerShell runs it: a quoted program behind &, single quotes doubled.
func TestStepShowsAPowerShellCommandLine(t *testing.T) {
	s := Step{Argv: []string{`C:\Program Files\tool.exe`, "-Path", `C:\it's here`, `C:\plain`}}
	if got, want := s.String(), `& 'C:\Program Files\tool.exe' -Path 'C:\it''s here' C:\plain`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if got := (Step{Argv: []string{`C:\Windows\System32\icacls.exe`, "$x"}}).String(); got != `C:\Windows\System32\icacls.exe '$x'` {
		t.Fatalf("got %s", got)
	}
}
