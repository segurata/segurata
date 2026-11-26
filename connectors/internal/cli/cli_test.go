package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/proc"
	"github.com/segurata/segurata/internal/proc/proctest"
)

func TestExecReturnsStdout(t *testing.T) {
	out, err := Exec{Path: proctest.Shell(t), Timeout: 10 * time.Second}.Run(context.Background(), "-c", "printf hello")
	if err != nil || string(out) != "hello" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestExecAddsEnvToTheInheritedOne(t *testing.T) {
	t.Setenv("CLI_TEST_INHERITED", "kept")
	e := Exec{Path: proctest.Shell(t), Timeout: 10 * time.Second, Env: []string{"CLI_TEST_EXTRA=1"}}
	out, err := e.Run(context.Background(), "-c", `printf "%s %s" "$CLI_TEST_INHERITED" "$CLI_TEST_EXTRA"`)
	if err != nil || string(out) != "kept 1" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestExecFailureKeepsStderr(t *testing.T) {
	sh := proctest.Shell(t)
	_, err := Exec{Path: sh, Timeout: 10 * time.Second}.Run(context.Background(), "-c", "echo 'PERMISSION_DENIED: nope' >&2; exit 3")
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("want *Error, got %T %v", err, err)
	}
	if strings.TrimSpace(ce.Stderr) != "PERMISSION_DENIED: nope" || ce.Cmd != "sh" {
		t.Errorf("error fields: %+v", ce)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Errorf("exit status not wrapped: %v", err)
	}
	if want := "sh: exit status 3: PERMISSION_DENIED: nope"; err.Error() != want {
		t.Errorf("message %q, want %q", err.Error(), want)
	}
}

func TestExecStderrCheckFailsARunThatExitedZero(t *testing.T) {
	broken := errors.New("swallowed failure")
	e := Exec{Path: proctest.Shell(t), Timeout: 10 * time.Second, StderrCheck: func(stderr string) error {
		if strings.Contains(stderr, "fatal") {
			return broken
		}
		return nil
	}}
	out, err := e.Run(context.Background(), "-c", "printf partial; echo 'fatal: x' >&2")
	var ce *Error
	if !errors.As(err, &ce) || !errors.Is(err, broken) || string(out) != "partial" || strings.TrimSpace(ce.Stderr) != "fatal: x" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if out, err := e.Run(context.Background(), "-c", "printf ok; echo 'warning: y' >&2"); err != nil || string(out) != "ok" {
		t.Fatalf("a run the check accepts failed: out=%q err=%v", out, err)
	}
}

func TestExecFailureKeepsPartialStdout(t *testing.T) {
	out, err := Exec{Path: proctest.Shell(t), Timeout: 10 * time.Second}.Run(context.Background(), "-c", "printf partial; exit 2")
	var ce *Error
	if !errors.As(err, &ce) || string(out) != "partial" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestCheckFuncGuard(t *testing.T) {
	refuse := CheckFunc(func(args []string) error {
		if len(args) > 0 && args[0] == "--pre" {
			return ErrRefused
		}
		return nil
	})
	inner := RunnerFunc(func(_ context.Context, args ...string) ([]byte, error) { return []byte("ran"), nil })
	if _, err := Guard(refuse, inner).Run(context.Background(), "--pre", "sh"); !errors.Is(err, ErrRefused) {
		t.Fatalf("want refusal, got %v", err)
	}
	if out, err := Guard(refuse, inner).Run(context.Background(), "-e", "x"); err != nil || string(out) != "ran" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestErrorMessageNamesTheCommandPath(t *testing.T) {
	if got := commandLabel("/opt/sdk/bin/gcloud", []string{"projects", "list"}); got != "gcloud projects list" {
		t.Errorf("label %q", got)
	}
	if got := commandLabel("aws", []string{"iam", "list-access-keys", "--user-name", "bob"}); got != "aws iam list-access-keys" {
		t.Errorf("label %q", got)
	}
	e := &Error{Cmd: "az account show", Err: errors.New("exit status 1")}
	if e.Error() != "az account show: exit status 1" {
		t.Errorf("message without stderr: %q", e.Error())
	}
}

func TestExecTimeout(t *testing.T) {
	_, err := Exec{Path: proctest.Shell(t), Timeout: 50 * time.Millisecond}.Run(context.Background(), "-c", "sleep 5")
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "timed out after 50ms") {
		t.Fatalf("want a timeout error, got %v", err)
	}
	var ce *Error
	if errors.As(err, &ce) {
		t.Errorf("a timeout is not a CLI failure: %v", err)
	}
}

func TestExecMissingBinary(t *testing.T) {
	_, err := Exec{Path: "segurata-no-such-cli", Timeout: time.Second}.Run(context.Background(), "x")
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("want exec.ErrNotFound in the chain, got %v", err)
	}
}

var testList = Allowlist{"projects list", "iam service-accounts keys list", "sts get-caller-identity"}

func TestAllowlistAcceptsReadOnlyPaths(t *testing.T) {
	for _, ok := range []string{
		"projects list",
		"projects list --account=a --format=json",
		"--account=a projects list",
		"projects --account=a list",
		"iam service-accounts keys list --iam-account=x --managed-by user",
		"sts get-caller-identity --profile p --region us-east-1",
		"projects list extra-positional",
	} {
		if err := testList.Check(strings.Fields(ok)); err != nil {
			t.Errorf("read-only command refused: %s: %v", ok, err)
		}
	}
}

func TestAllowlistRefusesEverythingElse(t *testing.T) {
	for _, bad := range []string{
		"",
		"projects delete p",
		"projects",
		"iam service-accounts keys create f --iam-account=x",
		"iam service-accounts list",
		"--account a projects list",        // bare flag before the path may swallow "a"
		"projects --verbosity list delete", // a bare flag inside the path may swallow "list"
		"--profile=p iam delete-access-key --access-key-id k",
		"list projects",
	} {
		err := testList.Check(strings.Fields(bad))
		if !errors.Is(err, ErrRefused) {
			t.Errorf("command allowed: %q (%v)", bad, err)
		}
	}
	if err := (Allowlist{""}).Check([]string{"anything"}); !errors.Is(err, ErrRefused) {
		t.Errorf("an empty entry must not allow every command: %v", err)
	}
}

func TestGuardRefusesBeforeRunning(t *testing.T) {
	var ran [][]string
	inner := RunnerFunc(func(_ context.Context, args ...string) ([]byte, error) {
		ran = append(ran, args)
		return []byte("ok"), nil
	})
	g := testList.Guard(inner)
	if _, err := g.Run(context.Background(), "projects", "delete", "p"); !errors.Is(err, ErrRefused) {
		t.Fatalf("want refusal, got %v", err)
	}
	if len(ran) != 0 {
		t.Fatalf("refused command reached the runner: %v", ran)
	}
	if out, err := g.Run(context.Background(), "projects", "list"); err != nil || string(out) != "ok" || len(ran) != 1 {
		t.Fatalf("allowed command: out=%q err=%v ran=%v", out, err, ran)
	}
}

// Homebrew's az is a bash wrapper that does not exec python: killing bash leaves python holding
// stdout. The timeout must still end the command.
func TestExecTimeoutEndsAWrapperThatDoesNotExec(t *testing.T) {
	start := time.Now()
	_, err := Exec{Path: proctest.Hung(t, "az", ""), Timeout: 100 * time.Millisecond}.Run(context.Background(), "account", "list")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if took := time.Since(start); took > proc.WaitDelay+5*time.Second {
		t.Fatalf("took %s", took)
	}
}

func TestStderrFallsBackToTheError(t *testing.T) {
	printed := fmt.Errorf("wrapped: %w", &Error{Cmd: "gcloud x", Stderr: "ERROR: denied\n", Err: errors.New("exit status 1")})
	silent := &Error{Cmd: "gcloud x", Stderr: " \n", Err: errors.New("exit status 1")}
	for err, want := range map[error]string{printed: "ERROR: denied\n", silent: "gcloud x: exit status 1", context.DeadlineExceeded: "context deadline exceeded"} {
		if got := Stderr(err); got != want {
			t.Errorf("Stderr(%v) = %q, want %q", err, got, want)
		}
	}
}
