package proctest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/proc"
)

func TestMain(m *testing.M) { Main(m) }

// The shell helper is what Script is on Windows; it runs here too, wherever there is a sh.
func TestShellHelperPassesArgumentsStdioAndExitCode(t *testing.T) {
	path := Helper(t, "", "fake", "sh "+Shell(t))
	if err := os.WriteFile(base(path)+".sh", []byte(`read line; echo "$1 $line"; echo err >&2; exit 3`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "describe")
	cmd.Stdin = strings.NewReader("in\n")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 || out.String() != "describe in\n" || errb.String() != "err\n" {
		t.Fatalf("err %v out %q stderr %q", err, out.String(), errb.String())
	}
}

func TestScriptRunsItsBody(t *testing.T) {
	out, err := exec.Command(Script(t, "", "s", `echo "ran $1"`), "x").Output()
	if err != nil || string(out) != "ran x\n" {
		t.Fatalf("%q %v", out, err)
	}
}

// A hung fake answers nothing while its child holds stdout; proc ends both.
func TestHungHoldsStdout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	out, err := proc.Command(ctx, Hung(t, "hung", "")).Output()
	if err == nil || len(out) != 0 || time.Since(start) < 500*time.Millisecond {
		t.Fatalf("a hung fake returned %q, %v after %s", out, err, time.Since(start))
	}
}
