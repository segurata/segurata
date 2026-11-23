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
	ActionAirPlayDisable  = "macos.airplay-receiver.disable"
)

const killall = "/usr/bin/killall"

// allowed is every command line a remediation may run, exactly, sudo included. It is written out
// by hand rather than derived from the plans, so a wrong plan is refused instead of run.
var allowed = remediate.Allowlist{
	ActionFirewallEnable: {
		{Argv: []string{socketfilterfw, "--setglobalstate", "on"}, Sudo: true},
	},
	ActionFirewallStealth: {
		{Argv: []string{socketfilterfw, "--setstealthmode", "on"}, Sudo: true},
	},
	ActionAirPlayDisable: {
		{Argv: []string{defaultsBin, "-currentHost", "write", controlCenterPrefs, airPlayReceiverKey, "-bool", "false"}},
		{Argv: []string{killall, "ControlCenter"}},
	},
}

func firewallStep(flag, value string) connector.Step {
	return connector.Step{Argv: []string{socketfilterfw, flag, value}, Sudo: true}
}

// airPlayPref writes the per-host Control Center key that System Settings > General > AirDrop &
// Handoff > AirPlay Receiver toggles. The CIS macOS benchmarks give this same command as the
// Terminal remediation.
func airPlayPref(value string) connector.Step {
	return connector.Step{Argv: []string{defaultsBin, "-currentHost", "write", controlCenterPrefs, airPlayReceiverKey, "-bool", value}}
}

var restartControlCenter = connector.Step{Argv: []string{killall, "ControlCenter"}}

func (c *Connector) Plan(_ context.Context, f finding.Finding) (connector.Plan, error) {
	switch f.Remediation.Action {
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
	case ActionAirPlayDisable:
		return connector.Plan{
			Action: ActionAirPlayDisable,
			Summary: "Turn off AirPlay Receiver, which closes TCP ports 5000 and 7000. If the check afterwards still sees them open, " +
				"turn it off in System Settings > General > AirDrop & Handoff > AirPlay Receiver.",
			Commands: []connector.Step{airPlayPref("false"), restartControlCenter},
			Undo:     []connector.Step{airPlayPref("true"), restartControlCenter},
			SideEffects: []string{
				"iPhones, iPads and other Macs can no longer AirPlay or mirror their screen to this Mac.",
				"Control Center and the menu bar extras restart, which takes a second.",
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
	return remediate.Run(ctx, p, allowed, c.Exec, io)
}
