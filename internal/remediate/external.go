package remediate

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// errPluginSudo: the core runs sudo only for argv on its own allowlist, and a plugin's argv is
// unknown until the plan arrives, so running it as root would hand the plugin root.
var errPluginSudo = errors.New("external connectors cannot run commands as root (protocol 2 has no sudo): fix this one by hand")

// external remediates through an external connector's `plan` and `apply` (protocol 2). The
// connector runs the plan itself, as the owner.
type external struct {
	conn *connector.External
	req  connector.Request // the finding's instance: config and resolved secrets
}

func (x external) Plan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	reply, err := x.conn.RequestPlan(ctx, connector.RemediationRequest{Request: x.req, Finding: f})
	if err != nil {
		return connector.Plan{}, err
	}
	return vetPlugin(x.conn.Describe().Name, f, reply)
}

func (x external) Apply(ctx context.Context, f finding.Finding, p connector.Plan, io connector.IO) error {
	return x.conn.RequestApply(ctx, connector.RemediationRequest{Request: x.req, Finding: f, Plan: &p}, io.Out, io.Err)
}

// vetPlugin refuses a plan the core cannot show honestly or must not run.
func vetPlugin(name string, f finding.Finding, reply connector.PlanReply) (connector.Plan, error) {
	p := reply.Plan
	if reply.SudoRequested || p.NeedsSudo() {
		return connector.Plan{}, fmt.Errorf("%s: %w", name, errPluginSudo)
	}
	if p.Action != f.Remediation.Action {
		return connector.Plan{}, fmt.Errorf("%s planned action %q for a finding whose action is %q", name, p.Action, f.Remediation.Action)
	}
	if strings.TrimSpace(p.Summary) == "" {
		return connector.Plan{}, fmt.Errorf("%s returned a plan without a summary", name)
	}
	for _, s := range append(append([]connector.Step{}, p.Commands...), p.Undo...) {
		if len(s.Argv) == 0 || s.Argv[0] == "" {
			return connector.Plan{}, fmt.Errorf("%s returned a plan with an empty command", name)
		}
	}
	return p, nil
}
