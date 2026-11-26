package connectedapps

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

type recordingExec struct{ ran []connector.Step }

func (r *recordingExec) Run(_ context.Context, s connector.Step, _ connector.IO) error {
	r.ran = append(r.ran, s)
	return nil
}

// ghStatus answers `gh auth status --json hosts` with one active account, and nothing else.
func ghStatus(scopes, source string) cli.Runner {
	return cli.RunnerFunc(func(_ context.Context, args ...string) ([]byte, error) {
		if !slices.Equal(args, ghAuthStatus) {
			return nil, fmt.Errorf("unexpected gh %v", args)
		}
		return []byte(fmt.Sprintf(`{"hosts":{"github.com":[{"login":"octo","active":false,"scopes":"delete_repo","tokenSource":"keyring"},`+
			`{"login":"octo","active":true,"state":"success","scopes":%q,"tokenSource":%q}]}}`, scopes, source)), nil
	})
}

var ghCLI = finding.Finding{ID: "gh1", Connector: name, Title: "GitHub CLI can delete your repositories (segurata depends on it)",
	Remediation: finding.Remediation{Action: actionGHDropScopes}}

func TestGitHubCLIDependencyOffersTheScopeDrop(t *testing.T) {
	e := &env{service: "github", emit: &recorder{}, now: now, seen: map[string]int{}}
	e.report(grant{who: "octo", resType: "github_oauth_app", name: "GitHub CLI", scopes: []string{"Delete repositories", "Full control of private repositories"}})
	e.report(grant{who: "octo", resType: "github_oauth_app", name: "GitHub CLI", scopes: []string{"Full control of private repositories"}})
	fs := e.emit.(*recorder).findings
	if fs[0].Remediation.Action != actionGHDropScopes || fs[1].Remediation.Action != "" {
		t.Fatalf("actions %q %q: only a token holding a removable scope gets one", fs[0].Remediation.Action, fs[1].Remediation.Action)
	}
}

func TestDropScopesPlansFromTheLiveTokenInTheTerminal(t *testing.T) {
	c := &Connector{gh: ghStatus("admin:org, admin:public_key, delete_repo, gist, repo, workflow", "keyring")}
	p, err := c.Plan(context.Background(), ghCLI)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Commands) != 1 || p.Commands[0].String() != "gh auth refresh -h github.com -r delete_repo,admin:org" || !p.Commands[0].Terminal {
		t.Fatalf("commands %+v", p.Commands)
	}
	if len(p.Undo) != 1 || p.Undo[0].String() != "gh auth refresh -h github.com -s delete_repo,admin:org" {
		t.Fatalf("undo %+v", p.Undo)
	}
	if !p.NeedsTerminal() || !strings.Contains(strings.Join(p.SideEffects, " "), "noscope") {
		t.Fatalf("plan must say it is interactive and what admin:org costs: %+v", p)
	}
}

func TestDropScopesRefusesWhatItCannotChange(t *testing.T) {
	reply := func(out string, err error) cli.Runner {
		return cli.RunnerFunc(func(context.Context, ...string) ([]byte, error) { return []byte(out), err })
	}
	for name, c := range map[string]struct {
		gh   cli.Runner
		want string
	}{
		"token from the environment": {ghStatus("admin:org, delete_repo, repo", "GH_TOKEN"), "token in GH_TOKEN"},
		"nothing to drop":            {ghStatus("gist, read:org, repo", "keyring"), "already lacks delete_repo, admin:org, admin:enterprise"},
		"gh fails":                   {reply("", errors.New("exit status 1")), "gh auth status: exit status 1"},
		"unreadable status":          {reply("not json", nil), "unexpected output"},
		"no active account":          {reply(`{"hosts":{"github.com":[{"login":"octo","active":false}]}}`, nil), "no active github.com account"},
	} {
		if _, err := (&Connector{gh: c.gh}).Plan(context.Background(), ghCLI); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}

func TestDropScopesAppliesOnlyTheLiveCommand(t *testing.T) {
	ex := &recordingExec{}
	c := &Connector{gh: ghStatus("delete_repo, repo", "keyring"), exec: ex}
	p, err := c.Plan(context.Background(), ghCLI)
	if err != nil {
		t.Fatal(err)
	}
	io := connector.IO{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	if err := c.Apply(context.Background(), ghCLI, p, io); err != nil {
		t.Fatal(err)
	}
	if len(ex.ran) != 1 || !ex.ran[0].Equal(refreshStep("-r", []string{"delete_repo"})) {
		t.Fatalf("ran %v", ex.ran)
	}
	wider := p
	wider.Commands = []connector.Step{refreshStep("-r", []string{"delete_repo", "repo"})}
	ex.ran = nil
	if err := c.Apply(context.Background(), ghCLI, wider, io); err == nil || len(ex.ran) != 0 {
		t.Fatalf("a plan other than the live one must be refused: %v %v", err, ex.ran)
	}
	if err := c.Apply(context.Background(), finding.Finding{Remediation: finding.Remediation{Action: "connected-apps.other"}}, p, io); err == nil {
		t.Fatal("an unknown action must be refused")
	}
}
