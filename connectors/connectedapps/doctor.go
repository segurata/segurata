package connectedapps

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
)

// Doctor checks the gh sign-in and the scopes the GitHub key lists need; the core checks CDP.
func (c *Connector) Doctor(ctx context.Context, _ connector.Request) []connector.Check {
	const what, login = "gh", "gh auth login -h github.com"
	one := func(level connector.Level, detail, fix string) []connector.Check {
		return []connector.Check{{Level: level, What: what, Detail: detail, Fix: fix}}
	}
	out, err := c.ghRunner().Run(ctx, ghAuthStatus...)
	if err != nil {
		msg := cli.Stderr(err)
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
	acct, found, err := parseGhStatus(out)
	switch {
	case err != nil:
		return one(connector.Fail, "unreadable gh auth status: "+err.Error(), "gh auth status")
	case !found:
		return one(connector.Fail, "no active github.com account in gh", login)
	case acct.State != "success":
		return one(connector.Fail, "the token of "+acct.Login+" is not valid ("+acct.State+")", login)
	}
	checks := []connector.Check{{Level: connector.OK, What: what, Detail: "signed in to github.com as " + acct.Login}}
	var missing []string
	for _, ep := range ghKeyEndpoints {
		if !acct.has(ep.scope) {
			missing = append(missing, ep.scope)
		}
	}
	if len(missing) > 0 {
		return append(checks, connector.Check{Level: connector.Warn, What: "gh scopes",
			Detail: "missing " + strings.Join(missing, ", ") + ": those GitHub key lists are skipped",
			Fix:    "gh auth refresh -h github.com -s " + strings.Join(missing, ",")})
	}
	return append(checks, connector.Check{Level: connector.OK, What: "gh scopes", Detail: "every scope the key lists need"})
}
