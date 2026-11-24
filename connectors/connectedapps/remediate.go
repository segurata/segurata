package connectedapps

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
)

// ActionGHDropScopes removes from gh's token the scopes segurata does not need (ghRemovable).
const ActionGHDropScopes = "connected-apps.gh.drop-scopes"

// envTokenSources are where gh reads a token it cannot refresh: one set in the environment.
var envTokenSources = []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"}

// ghAccount is the active github.com account in `gh auth status --json hosts`.
type ghAccount struct {
	Login       string `json:"login"`
	Active      bool   `json:"active"`
	State       string `json:"state"`
	Scopes      string `json:"scopes"`
	TokenSource string `json:"tokenSource"`
}

// ghActive reads the signed-in github.com account now, with its token's scopes.
func (c *Connector) ghActive(ctx context.Context) (ghAccount, error) {
	out, err := c.ghRunner().Run(ctx, ghAuthStatus...)
	if err != nil {
		return ghAccount{}, fmt.Errorf("gh auth status: %w", err)
	}
	var st struct {
		Hosts map[string][]ghAccount `json:"hosts"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return ghAccount{}, fmt.Errorf("gh auth status: unexpected output: %w", err)
	}
	for _, a := range st.Hosts["github.com"] {
		if a.Active {
			return a, nil
		}
	}
	return ghAccount{}, fmt.Errorf("gh has no active github.com account: run `gh auth login -h github.com`")
}

// removable are the scopes of ghRemovable the token holds now, in ghRemovable's order.
func (a ghAccount) removable() []string {
	have := strings.Split(strings.ReplaceAll(a.Scopes, " ", ""), ",")
	var out []string
	for _, r := range ghRemovable {
		if slices.Contains(have, r.scope) {
			out = append(out, r.scope)
		}
	}
	return out
}

// refreshStep is `gh auth refresh` removing (-r) or adding back (-s) scopes. It opens a browser
// sign-in, so it runs in the owner's terminal.
func refreshStep(flag string, scopes []string) connector.Step {
	return connector.Step{Argv: []string{"gh", "auth", "refresh", "-h", "github.com", flag, strings.Join(scopes, ",")}, Terminal: true}
}

func (c *Connector) Plan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	p, _, err := c.planNow(ctx, f)
	return p, err
}

// planNow plans from gh's token as it is now and returns the scopes it read.
func (c *Connector) planNow(ctx context.Context, f finding.Finding) (connector.Plan, []string, error) {
	if f.Remediation.Action != ActionGHDropScopes {
		return connector.Plan{}, nil, fmt.Errorf("connected-apps has no remediation %q", f.Remediation.Action)
	}
	a, err := c.ghActive(ctx)
	if err != nil {
		return connector.Plan{}, nil, err
	}
	if slices.Contains(envTokenSources, a.TokenSource) {
		return connector.Plan{}, nil, fmt.Errorf("gh uses the token in %s, which `gh auth refresh` cannot change: replace that token with a narrower one by hand", a.TokenSource)
	}
	remove := a.removable()
	if len(remove) == 0 {
		return connector.Plan{}, nil, fmt.Errorf("gh's token for %s already lacks %s: nothing to do; run the inventory again", a.Login, strings.Join(scopeNames(), ", "))
	}
	p := connector.Plan{
		Action: ActionGHDropScopes,
		Summary: fmt.Sprintf("Remove %s from the GitHub CLI token of %s, keeping every other scope. gh asks you to confirm in the browser.",
			strings.Join(remove, ", "), a.Login),
		Commands: []connector.Step{refreshStep("-r", remove)},
		Undo:     []connector.Step{refreshStep("-s", remove)},
		SideEffects: []string{
			"gh prints a one-time code and opens github.com in the browser; the new token replaces the old one only after you approve there.",
			"Commands that need the removed scopes stop working with this token: `gh repo delete` (delete_repo), organization administration (admin:org), enterprise administration (admin:enterprise).",
			"segurata keeps reading GitHub through gh, but without admin:org its github connector reports each organization's settings as noscope (\"organization settings need admin:org\"), and github.workflow-token.read can no longer change an organization's default.",
			"Only this machine's gh token changes. Give segurata a read-only fine-grained token in GH_TOKEN for its runs if you want it to hold no write scope at all.",
		},
	}
	return p, remove, nil
}

func (c *Connector) Apply(ctx context.Context, f finding.Finding, p connector.Plan, io connector.IO) error {
	_, remove, err := c.planNow(ctx, f)
	if err != nil {
		return err
	}
	// The one command line allowed: removing exactly the scopes the token holds now.
	allow := remediate.Allowlist{ActionGHDropScopes: {refreshStep("-r", remove)}}
	return remediate.Run(ctx, p, allow, c.exec, io)
}

func scopeNames() []string {
	out := make([]string, len(ghRemovable))
	for i, r := range ghRemovable {
		out[i] = r.scope
	}
	return out
}
