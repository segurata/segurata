package localsecrets

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
)

func TestDoctor(t *testing.T) {
	replies := func(out string) *fakeTool {
		return &fakeTool{reply: func([]string) ([]byte, error) { return []byte(out), nil }}
	}
	rg, gl := replies("ripgrep 14.1.1\nfeatures:+pcre2\n"), replies("8.21.2\n")
	installed := map[string]bool{"rg": true, "gitleaks": true, "git": true, "ssh-keygen": true}
	c := &Connector{RG: rg, Gitleaks: gl, LookPath: func(n string) (string, error) {
		if installed[n] {
			return "/usr/bin/" + n, nil
		}
		return "", exec.ErrNotFound
	}}
	levels := func(checks []connector.Check) string {
		var s []string
		for _, ch := range checks {
			s = append(s, ch.What+"="+string(ch.Level))
		}
		return strings.Join(s, " ")
	}

	checks := c.Doctor(context.Background(), connector.Request{})
	if got := levels(checks); got != "rg=OK gitleaks=OK git=OK ssh-keygen=OK" {
		t.Fatalf("all present: %s", got)
	}
	if checks[0].Detail != "/usr/bin/rg (ripgrep 14.1.1)" || checks[1].Detail != "/usr/bin/gitleaks (8.21.2)" {
		t.Errorf("versions: %+v", checks[:2])
	}
	if rg.calls[0][0] != "--version" || gl.calls[0][0] != "version" {
		t.Errorf("version commands: %v %v", rg.calls, gl.calls)
	}

	installed["gitleaks"], installed["rg"] = false, false
	missing := c.Doctor(context.Background(), connector.Request{})
	if got := levels(missing); got != "rg=FAIL gitleaks=WARN git=OK ssh-keygen=OK" {
		t.Errorf("missing tools: %s", got)
	}
	if missing[0].Fix != "install ripgrep (https://github.com/BurntSushi/ripgrep#installation)" ||
		missing[1].Fix != "install gitleaks (https://github.com/gitleaks/gitleaks#installing)" {
		t.Errorf("fixes name the tool and its install page, nothing else: %q, %q", missing[0].Fix, missing[1].Fix)
	}
	if got := levels(c.Doctor(context.Background(), connector.Request{Config: map[string]any{"skip_git_history": true}})); got != "rg=FAIL gitleaks=OK git=OK ssh-keygen=OK" {
		t.Errorf("skip_git_history: %s", got)
	}

	if checks := c.Doctor(context.Background(), connector.Request{Config: map[string]any{"skip_git_history": "yes"}}); len(checks) != 1 ||
		checks[0].Level != connector.Fail || checks[0].Detail != `local-secrets config: "skip_git_history" must be true or false` {
		t.Errorf("malformed config: %+v", checks)
	}

	installed["rg"] = true
	c.RG = &fakeTool{reply: func([]string) ([]byte, error) { return nil, errors.New("boom") }}
	if ch := c.Doctor(context.Background(), connector.Request{})[0]; ch.Level != connector.OK || !strings.Contains(ch.Detail, "version unknown") {
		t.Errorf("version failure: %+v", ch)
	}
}
