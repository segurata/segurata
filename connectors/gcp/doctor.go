package gcp

import (
	"context"
	"errors"
	"fmt"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// Doctor finds gcloud as the inventory does, lists its credentialed accounts and asks each for one
// project, through the same read-only allowlist, to tell which accounts' credentials expired.
func (c *Connector) Doctor(ctx context.Context, req connector.Request) []connector.Check {
	cfg, err := parseSettings(req.Config)
	if err != nil {
		return []connector.Check{{Level: connector.Fail, What: "config", Detail: err.Error(), Fix: "fix the gcp section of the config"}}
	}
	g, err := c.gcloud(cfg)
	if err != nil {
		return []connector.Check{{Level: connector.Fail, What: "gcloud", Detail: err.Error(),
			Fix: "install the Google Cloud SDK (https://cloud.google.com/sdk/docs/install) or set gcloud_path"}}
	}
	accounts, _, err := c.accounts(ctx, g, cfg)
	if err != nil {
		_, why := classify(err)
		return []connector.Check{{Level: connector.Fail, What: "gcloud auth list", Detail: why, Fix: "gcloud auth login"}}
	}
	if len(accounts) == 0 {
		return []connector.Check{{Level: connector.Fail, What: "gcloud accounts", Detail: "gcloud has no credentialed accounts", Fix: "gcloud auth login"}}
	}
	checks := []connector.Check{{Level: connector.OK, What: "gcloud", Detail: fmt.Sprintf("%d credentialed account(s)", len(accounts))}}
	for _, a := range accounts {
		var projects []struct{}
		err := g.json(ctx, &projects, "projects", "list", "--account="+a, "--limit=1")
		what := "gcloud account " + a
		if err == nil {
			checks = append(checks, connector.Check{Level: connector.OK, What: what, Detail: "token valid"})
			continue
		}
		switch state, why := classify(err); {
		case state == finding.StateReauth:
			checks = append(checks, connector.Check{Level: connector.Fail, What: what, Detail: "token expired", Fix: "gcloud auth login " + a})
		case errors.Is(err, context.DeadlineExceeded):
			checks = append(checks, connector.Check{Level: connector.Warn, What: what, Detail: "timed out listing projects", Fix: "run again; check the network"})
		default:
			checks = append(checks, connector.Check{Level: connector.Warn, What: what, Detail: why,
				Fix: "check the account's access with: gcloud projects list --account=" + a})
		}
	}
	return checks
}
