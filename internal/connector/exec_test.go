package connector_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
)

var enable = connector.Step{Argv: []string{"/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"}, Sudo: true}

type recordingExec struct{ ran []connector.Step }

func (r *recordingExec) Run(_ context.Context, s connector.Step, _ connector.IO) error {
	r.ran = append(r.ran, s)
	return nil
}

func quietIO() connector.IO {
	return connector.IO{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
}

func TestAllowlistMatchesExactArgvAndSudo(t *testing.T) {
	allow := connector.Allowlist{"a": {enable}}
	if err := allow.Check("a", enable); err != nil {
		t.Fatal(err)
	}
	refused := []connector.Step{
		{Argv: enable.Argv},                          // same argv without sudo
		{Argv: append(enable.Argv, "x"), Sudo: true}, // extra argument
		{Argv: []string{"/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "off"}, Sudo: true},
		{Argv: []string{"/bin/sh", "-c", "id"}, Sudo: true},
	}
	for _, s := range refused {
		if err := allow.Check("a", s); !errors.Is(err, connector.ErrRefused) {
			t.Errorf("%s: want refusal, got %v", s, err)
		}
	}
	if err := allow.Check("other", enable); !errors.Is(err, connector.ErrRefused) {
		t.Errorf("a step allowed for one action must not run for another: %v", err)
	}
}

func TestRunChecksEveryStepBeforeRunningAny(t *testing.T) {
	ex := &recordingExec{}
	p := connector.Plan{Action: "a", Commands: []connector.Step{enable, {Argv: []string{"/bin/rm", "-rf", "/"}, Sudo: true}}}
	allow := connector.Allowlist{"a": {enable}}
	if err := allow.Run(context.Background(), p, ex, quietIO()); !errors.Is(err, connector.ErrRefused) {
		t.Fatalf("want refusal, got %v", err)
	}
	if len(ex.ran) != 0 {
		t.Fatalf("ran %v before refusing the plan", ex.ran)
	}
	if err := allow.Run(context.Background(), connector.Plan{Action: "a", Commands: []connector.Step{enable}}, ex, quietIO()); err != nil || len(ex.ran) != 1 {
		t.Fatalf("err=%v ran=%v", err, ex.ran)
	}
}

func TestStepStringQuotesLikeAShell(t *testing.T) {
	s := connector.Step{Argv: []string{"/bin/chmod", "644", "/tmp/my file's"}, Sudo: true}
	if got, want := s.String(), `sudo /bin/chmod 644 '/tmp/my file'\''s'`; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
