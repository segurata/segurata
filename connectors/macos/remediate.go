package macos

import (
	"context"
	"fmt"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
)

// Remediation actions this connector can apply.
const (
	ActionFirewallEnable  = "macos.firewall.enable"
	ActionFirewallStealth = "macos.firewall.stealth"
	ActionShareRemove     = "macos.smb.share-remove"
	ActionShareGuestOff   = "macos.smb.guest-off"
)

// allowed is every fixed command line a remediation may run, exactly, sudo included. It is written
// out by hand rather than derived from the plans, so a wrong plan is refused instead of run. The
// share point actions take a share name, so their entries are added at apply time from a fresh
// read of the share points (shareAllowlist), never from the finding.
var allowed = remediate.Allowlist{
	ActionFirewallEnable: {
		{Argv: []string{socketfilterfw, "--setglobalstate", "on"}, Sudo: true},
	},
	ActionFirewallStealth: {
		{Argv: []string{socketfilterfw, "--setstealthmode", "on"}, Sudo: true},
	},
}

func firewallStep(flag, value string) connector.Step {
	return connector.Step{Argv: []string{socketfilterfw, flag, value}, Sudo: true}
}

func (c *Connector) Plan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	switch f.Remediation.Action {
	case ActionShareRemove, ActionShareGuestOff:
		return c.sharePlan(ctx, f)
	case ActionFirewallEnable:
		return connector.Plan{
			Action:   ActionFirewallEnable,
			Summary:  "Turn on the macOS application firewall, which then asks before an app accepts incoming connections.",
			Commands: []connector.Step{firewallStep("--setglobalstate", "on")},
			Undo:     []connector.Step{firewallStep("--setglobalstate", "off")},
			SideEffects: []string{
				"The first time an unsigned app (a dev server, a local tool) accepts a connection from another device, macOS shows an Allow/Deny prompt; until you allow it, other devices cannot reach it. Signed apps are allowed automatically by default.",
				"Connections from this Mac to localhost are not affected.",
			},
		}, nil
	case ActionFirewallStealth:
		return connector.Plan{
			Action:   ActionFirewallStealth,
			Summary:  "Turn on firewall stealth mode: the Mac stops answering pings and probes of closed ports.",
			Commands: []connector.Step{firewallStep("--setstealthmode", "on")},
			Undo:     []connector.Step{firewallStep("--setstealthmode", "off")},
			SideEffects: []string{
				"Ping and network scanners on the LAN no longer see this Mac; tools that check reachability by ping will report it as down.",
				"It takes effect while the firewall is on.",
			},
		}, nil
	}
	return connector.Plan{}, fmt.Errorf("macos has no remediation %q", f.Remediation.Action)
}

func (c *Connector) Apply(ctx context.Context, f finding.Finding, p connector.Plan, io connector.IO) error {
	want, err := c.Plan(ctx, f)
	if err != nil {
		return err
	}
	if err := remediate.SamePlan(want, p); err != nil {
		return err
	}
	allow := allowed
	if p.Action == ActionShareRemove || p.Action == ActionShareGuestOff {
		if allow, err = c.shareAllowlist(ctx); err != nil {
			return err
		}
	}
	return remediate.Run(ctx, p, allow, c.Exec, io)
}
