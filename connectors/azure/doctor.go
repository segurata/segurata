package azure

import (
	"context"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

func (c *Connector) Doctor(ctx context.Context, _ connector.Request) []connector.Check {
	var current account
	err := c.call(ctx, &current, "account", "show")
	if err == nil {
		return []connector.Check{{Level: connector.OK, What: "az account", Detail: "subscription " + current.Name + " in " + current.tenantLabel()}}
	}
	ch := connector.Check{Level: connector.Fail, What: "az account", Detail: err.Error(), Fix: "az login"}
	switch classify(err) {
	case finding.StateUnsupported:
		ch.Detail, ch.Fix = "the az CLI is not installed", "install it: https://learn.microsoft.com/cli/azure/install-azure-cli"
	case finding.StateSignedOut:
		ch.Detail = "az is not signed in"
	case finding.StateReauth:
		ch.Detail = "az credentials expired"
	}
	return []connector.Check{ch}
}
