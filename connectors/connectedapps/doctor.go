package connectedapps

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"slices"
	"strings"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
)

// Doctor checks the gh sign-in and the scopes the GitHub key lists need. The browser side (CDP)
// is checked by the core for every connector that needs it.
func (c *Connector) Doctor(ctx context.Context, _ connector.Request) []connector.Check {
	const what, login = "gh", "gh auth login -h github.com"
	one := func(level connector.Level, detail, fix string) []connector.Check {
		return []connector.Check{{Level: level, What: what, Detail: detail, Fix: fix}}
	}
	out, err := c.ghRunner().Run(ctx, ghAuthStatus...)
	if err != nil {
		msg := err.Error()
		var ce *cli.Error
		if errors.As(err, &ce) {
			msg = ce.Stderr
		}
		switch {
		case errors.Is(err, exec.ErrNotFound):
			return one(connector.Fail, "the gh CLI is not installed", "install it: https://cli.github.com")
		case strings.Contains(msg, "unknown flag"):
			return one(connector.Warn, "gh is too old for `gh auth status --json`", "upgrade gh")
		case ghSignedOffRE.MatchString(msg):
			return one(connector.Fail, "gh is not signed in", login)
		}
		return one(connector.Fail, strings.TrimSpace(msg), "gh auth status")
	}
	var status struct {
		Hosts map[string][]struct {
			State  string `json:"state"`
			Active bool   `json:"active"`
			Login  string `json:"login"`
			Scopes string `json:"scopes"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(out, &status); err != nil {
		return one(connector.Fail, "unreadable gh auth status: "+err.Error(), "gh auth status")
	}
	for _, acct := range status.Hosts["github.com"] {
		if !acct.Active {
			continue
		}
		if acct.State != "success" {
			return one(connector.Fail, "the token of "+acct.Login+" is not valid ("+acct.State+")", login)
		}
		checks := []connector.Check{{Level: connector.OK, What: what, Detail: "signed in to github.com as " + acct.Login}}
		if missing := missingScopes(acct.Scopes); len(missing) > 0 {
			checks = append(checks, connector.Check{Level: connector.Warn, What: "gh scopes",
				Detail: "missing " + strings.Join(missing, ", ") + ": those GitHub key lists are skipped",
				Fix:    "gh auth refresh -h github.com -s " + strings.Join(missing, ",")})
		} else {
			checks = append(checks, connector.Check{Level: connector.OK, What: "gh scopes", Detail: "every scope the key lists need"})
		}
		return checks
	}
	return one(connector.Fail, "no active github.com account in gh", login)
}

// missingScopes lists the scopes of ghKeyEndpoints that a comma-separated grant lacks.
func missingScopes(granted string) []string {
	have := strings.Split(strings.ReplaceAll(granted, " ", ""), ",")
	var missing []string
	for _, ep := range ghKeyEndpoints {
		if !slices.Contains(have, ep.scope) && !slices.Contains(missing, ep.scope) {
			missing = append(missing, ep.scope)
		}
	}
	return missing
}
