package macos

import (
	"context"
	"fmt"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const (
	actionFirewallEnable  = "macos.firewall.enable"
	actionFirewallStealth = "macos.firewall.stealth"
	actionShareRemove     = "macos.smb.share-remove"
	actionShareGuestOff   = "macos.smb.guest-off"
	actionHomePrivate     = "macos.home.private"
)

// allowed is written out by hand rather than derived from the plans, so a wrong plan is refused.
// Actions on a share or the home folder build theirs at apply time from what exists then.
var allowed = connector.Allowlist{
	actionFirewallEnable: {
		{Argv: []string{socketfilterfw, "--setglobalstate", "on"}, Sudo: true},
	},
	actionFirewallStealth: {
		{Argv: []string{socketfilterfw, "--setstealthmode", "on"}, Sudo: true},
	},
}

func firewallStep(flag, value string) connector.Step {
	return connector.Step{Argv: []string{socketfilterfw, flag, value}, Sudo: true}
}

func (c *Connector) Plan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	switch f.Remediation.Action {
	case actionShareRemove, actionShareGuestOff:
		return c.sharePlan(ctx, f)
	case actionHomePrivate:
		return c.homePlan()
	case actionFirewallEnable:
		return connector.Plan{
			Action:   actionFirewallEnable,
			Summary:  "Turn on the macOS application firewall, which then asks before an app accepts incoming connections.",
			Commands: []connector.Step{firewallStep("--setglobalstate", "on")},
			Undo:     []connector.Step{firewallStep("--setglobalstate", "off")},
			SideEffects: []string{
				"The first time an unsigned app (a dev server, a local tool) accepts a connection from another device, macOS shows an Allow/Deny prompt; until you allow it, other devices cannot reach it. Signed apps are allowed automatically by default.",
				"Connections from this Mac to localhost are not affected.",
			},
		}, nil
	case actionFirewallStealth:
		return connector.Plan{
			Action:   actionFirewallStealth,
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
	allow, err := c.allowlistFor(ctx, p.Action)
	if err != nil {
		return err
	}
	return allow.Run(ctx, p, c.Exec, io)
}

func (c *Connector) allowlistFor(ctx context.Context, action string) (connector.Allowlist, error) {
	switch action {
	case actionShareRemove, actionShareGuestOff:
		return c.shareAllowlist(ctx)
	case actionHomePrivate:
		return c.homeAllowlist()
	}
	return allowed, nil
}
