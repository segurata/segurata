package aws

import (
	"context"
	"fmt"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// Doctor asks STS who each profile is, through the same read-only allowlist as the inventory.
func (c *Connector) Doctor(ctx context.Context, req connector.Request) []connector.Check {
	profiles, err := c.profiles(ctx, req.Config)
	if err != nil {
		return []connector.Check{failure("aws CLI", "", err)}
	}
	if len(profiles) == 0 {
		return []connector.Check{{Level: connector.Fail, What: "aws profiles", Detail: "no AWS CLI profiles",
			Fix: "aws configure sso, or set connectors.aws.config.profiles"}}
	}
	var checks []connector.Check
	for _, p := range profiles {
		var id struct{ Account, Arn string }
		if err := c.call(ctx, p, &id, "sts", "get-caller-identity"); err != nil {
			checks = append(checks, failure("profile "+p, p, err))
			continue
		}
		checks = append(checks, connector.Check{Level: connector.OK, What: "profile " + p, Detail: fmt.Sprintf("account %s as %s", id.Account, id.Arn)})
	}
	return checks
}

// failure turns an aws CLI error into a check with the command that fixes it.
func failure(what, profile string, err error) connector.Check {
	ch := connector.Check{Level: connector.Fail, What: what, Detail: err.Error()}
	switch classify(err) {
	case finding.StateUnsupported:
		ch.Detail, ch.Fix = "the aws CLI is not installed", "install it: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
	case finding.StateMissingCredentials:
		ch.Fix = "aws configure sso --profile " + profile
	case finding.StateReauth:
		ch.Fix = "aws sso login --profile " + profile
		if !containsAny(err.Error(), "sso", "SSO") {
			ch.Fix = "the profile's access key is invalid or deactivated: put a working one in with aws configure --profile " + profile +
				", or remove the profile from ~/.aws/credentials and ~/.aws/config"
		}
	default:
		ch.Fix = "aws sts get-caller-identity --profile " + profile + " (to see the full error)"
	}
	return ch
}
