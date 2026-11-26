package proc

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// Go quotes arguments for CreateProcess, but a .cmd or .bat file runs under cmd.exe, which reads
// these characters as syntax even inside those quotes: a configured value would become a command.
func TestBatchWrappersRefuseWhatCmdInterprets(t *testing.T) {
	const secretish = "s3cr3t-value"
	for _, arg := range []string{"a&", "a|b", "a>b", "a<b", "a^b", "%PATH%", "!x!", `a"b`, "a\rb", "a\nb", `C:\dir\`, secretish + "&x"} {
		for _, path := range []string{`C:\sdk\az.cmd`, `C:\sdk\GCLOUD.BAT`} {
			err := checkBatchArgs(path, []string{"account", "list", arg})
			ee, ok := errors.AsType[*exec.Error](err)
			if !ok || !errors.Is(err, ErrBatchArgument) {
				t.Errorf("%s %q: want a refusal, got %v", path, arg, err)
				continue
			}
			if !strings.Contains(ee.Error(), "argument 3") || strings.Contains(ee.Error(), secretish) {
				t.Errorf("the refusal must name the position and never the value: %v", ee)
			}
		}
	}
	for _, c := range []struct {
		path string
		args []string
	}{
		{`C:\sdk\az.cmd`, []string{"account", "list", "--query", "[].name", "-o", "json", "with space", "", `C:\dir\file`}},
		{`C:\bin\gitleaks.exe`, []string{"a&b", `C:\dir\`, "%x%"}},
		{"/usr/local/bin/az", []string{"a&b"}},
	} {
		if err := checkBatchArgs(c.path, c.args); err != nil {
			t.Errorf("%s %q: %v", c.path, c.args, err)
		}
	}
}
