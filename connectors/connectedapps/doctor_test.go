package connectedapps

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
)

func TestDoctorGh(t *testing.T) {
	status := func(scopes string) string {
		return `{"hosts":{"github.com":[{"state":"success","active":false,"login":"old","scopes":""},` +
			`{"state":"success","active":true,"login":"octocat","scopes":"` + scopes + `"}]}}`
	}
	cases := []struct {
		name   string
		reply  any
		levels []connector.Level
		want   string
	}{
		{"all scopes", status("admin:public_key, admin:ssh_signing_key, admin:gpg_key, repo"), []connector.Level{connector.OK, connector.OK}, "octocat"},
		{"missing scopes", status("admin:public_key, repo"), []connector.Level{connector.OK, connector.Warn}, "gh auth refresh -h github.com -s admin:ssh_signing_key,admin:gpg_key"},
		{"signed out", &cli.Error{Cmd: "gh auth status", Stderr: "You are not logged into any GitHub hosts. To log in, run: gh auth login", Err: errors.New("exit status 1")}, []connector.Level{connector.Fail}, "gh auth login"},
		{"old gh", &cli.Error{Cmd: "gh auth status", Stderr: "unknown flag: --json", Err: errors.New("exit status 1")}, []connector.Level{connector.Warn}, "upgrade"},
		{"not installed", fmt.Errorf("gh: %w", exec.ErrNotFound), []connector.Level{connector.Fail}, "cli.github.com"},
		{"invalid token", `{"hosts":{"github.com":[{"state":"error","active":true,"login":"octocat"}]}}`, []connector.Level{connector.Fail}, "not valid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checks := (&Connector{gh: ghFake{"hosts": tc.reply}}).Doctor(context.Background(), connector.Request{})
			if len(checks) != len(tc.levels) {
				t.Fatalf("%+v", checks)
			}
			text := ""
			for i, ch := range checks {
				if ch.Level != tc.levels[i] {
					t.Errorf("check %d: %+v", i, ch)
				}
				text += ch.Detail + " " + ch.Fix + " "
			}
			if !strings.Contains(text, tc.want) {
				t.Errorf("want %q in %q", tc.want, text)
			}
		})
	}
}

func TestGhAllowlistAcceptsOnlyTheJSONStatus(t *testing.T) {
	if err := ghAllowlist.Check([]string{"auth", "status", "--json", "hosts"}); err != nil {
		t.Error(err)
	}
	for _, args := range [][]string{{"auth", "status", "--show-token"}, {"auth", "status"}, {"auth", "token"}, {"auth", "refresh"}} {
		if err := ghAllowlist.Check(args); !errors.Is(err, cli.ErrRefused) {
			t.Errorf("%v allowed", args)
		}
	}
}
