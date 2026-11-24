package workspace

import (
	"context"
	"strings"

	"github.com/segurata/segurata/internal/connector"
)

// Doctor obtains the tenant's access token exactly as the inventory does (the secret, or gcloud
// with the tenant's own CLOUDSDK_CONFIG) and asks tokeninfo for its scopes and account. The token
// is discarded; nothing is printed but the outcome.
func (c *Connector) Doctor(ctx context.Context, req connector.Request) []connector.Check {
	cfg, err := parseSettings(req.Config, c.home)
	if err != nil {
		return []connector.Check{{Level: connector.Fail, What: "config", Detail: err.Error(), Fix: "fix this workspace instance in the config"}}
	}
	if cfg.domain == "" {
		return []connector.Check{{Level: connector.Warn, What: "tenant", Detail: "no tenant configured", Fix: noTenantHint}}
	}
	what := "token for " + cfg.domain
	source := "from the " + secretName + " secret"
	if req.Secrets[secretName] == "" {
		source = "from CLOUDSDK_CONFIG=" + cfg.cloudsdkConfig
	}
	fail := func(why string) []connector.Check {
		detail, fix := splitHelp(why)
		return []connector.Check{{Level: connector.Fail, What: what, Detail: detail, Fix: fix}}
	}
	token, state, why := c.token(ctx, cfg, req.Secrets[secretName])
	if state != "" {
		return fail(why)
	}
	info, state, why := c.checkToken(ctx, cfg, token)
	if state != "" {
		return fail(why)
	}
	detail := "obtained " + source
	if info.email != "" {
		detail += ", signed in as " + info.email
	}
	checks := []connector.Check{{Level: connector.OK, What: what, Detail: detail}}
	if !info.reports {
		checks = append(checks, connector.Check{Level: connector.Warn, What: "reports scope", Detail: "the token lacks " + reportsScope + ": token activity is skipped",
			Fix: loginHelp(cfg)})
	}
	return checks
}

// splitHelp separates a token problem from the sign-in steps that follow it.
func splitHelp(why string) (string, string) {
	if detail, help, ok := strings.Cut(why, "\n\n"); ok {
		return detail, help
	}
	detail, help, _ := strings.Cut(why, "\n")
	return detail, help
}
