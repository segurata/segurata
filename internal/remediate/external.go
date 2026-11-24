package remediate

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// ErrPluginSudo refuses a plan from an external connector that needs root. The core runs a sudo
// step itself, with the owner's terminal attached, and only when the step is on a hand-written
// allowlist of exact argument lists. A plugin's argv cannot be on that list: the core has never
// seen it before the plan arrives, so it cannot vet it, and running it as root would hand the
// plugin root on the owner's say-so alone.
var ErrPluginSudo = errors.New("external connectors cannot run commands as root (protocol 2 has no sudo): fix this one by hand")

// External remediates through an external connector's `plan` and `apply` subcommands (protocol 2).
// Execute shows the plan and asks for confirmation exactly as for a built-in. The connector runs
// the plan itself, as the owner; the core vets what it can: the action, the absence of sudo, and
// that the plan it applies is the one that was shown.
type External struct {
	Conn *connector.External
	Req  connector.Request // the finding's instance: config and resolved secrets
}

func (x External) Plan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	reply, err := x.Conn.RequestPlan(ctx, connector.RemediationRequest{Request: x.Req, Finding: f})
	if err != nil {
		return connector.Plan{}, err
	}
	return vetPlugin(x.Conn.Describe().Name, f, reply)
}

// Apply asks the connector for the plan again and refuses to go on when it differs from p, the
// plan the owner confirmed; only then does it run `apply` with p.
func (x External) Apply(ctx context.Context, f finding.Finding, p connector.Plan, io connector.IO) error {
	want, err := x.Plan(ctx, f)
	if err != nil {
		return err
	}
	if err := SamePlan(want, p); err != nil {
		return err
	}
	return x.Conn.RequestApply(ctx, connector.RemediationRequest{Request: x.Req, Finding: f, Plan: &p}, io.Out, io.Err)
}

// vetPlugin refuses a plan the core cannot show honestly or must not run.
func vetPlugin(name string, f finding.Finding, reply connector.PlanReply) (connector.Plan, error) {
	p := reply.Plan
	if reply.SudoRequested || p.NeedsSudo() {
		return connector.Plan{}, fmt.Errorf("%s: %w", name, ErrPluginSudo)
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
