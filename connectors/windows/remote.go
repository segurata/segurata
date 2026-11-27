package windows

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/segurata/segurata/connectors/internal/posture"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// effective is a setting a policy key can override: the policy's value when set, else the local
// one, else def.
func effective(policy, local regKey, name, def string) string {
	if v, ok := policy.text(name); ok {
		return v
	}
	if v, ok := local.text(name); ok {
		return v
	}
	return def
}

// Remote access: Remote Desktop and Network Level Authentication, SMBv1, shared folders.
func (c *Connector) remoteChecks(p probe) []check {
	out := c.rdpChecks()
	out = append(out, c.smb1Check(p))
	return append(out, shareChecks(p)...)
}

// rdpChecks: fDenyTSConnections=0 lets Remote Desktop in; UserAuthentication=1 requires Network
// Level Authentication. The Remote Desktop Services policy key, when set, overrides both.
func (c *Connector) rdpChecks() []check {
	ts := c.key(HKLM, tsKey, "fDenyTSConnections")
	rdp := c.key(HKLM, rdpTCPKey, "UserAuthentication", "PortNumber")
	pol := c.key(HKLM, tsPolicyKey, "fDenyTSConnections", "UserAuthentication")
	for _, k := range []regKey{ts, rdp, pol} {
		if why, st, bad := k.unreadable(); bad {
			return []check{skipped("remote-desktop", "remote-desktop", why, st)}
		}
	}
	deny := effective(pol, ts, "fDenyTSConnections", "1")
	nla := effective(pol, rdp, "UserAuthentication", "1")
	port, _ := rdp.num("PortNumber")
	if port == 0 {
		port = 3389
	}
	on := deny == "0"
	ev := map[string]any{"port": port}
	return []check{
		{ID: "remote-desktop", Area: "remote-desktop", OK: !on, Sev: finding.SevMedium, Detail: "fDenyTSConnections=" + deny, Evidence: ev,
			Title: fmt.Sprintf("Remote Desktop is on: this PC accepts remote sign-ins on port %d", port),
			Rem:   posture.Manual(fmt.Sprintf("Unless you sign in to this PC from another one, turn off Settings > System > Remote Desktop, or run `Set-ItemProperty -Path %s -Name fDenyTSConnections -Value 1` in an elevated PowerShell.", connector.PowerShellString(ts.psPath())))},
		{ID: "remote-desktop-nla", Area: "remote-desktop", OK: !on || nla != "0", Sev: finding.SevHigh, Detail: "UserAuthentication=" + nla, Evidence: ev,
			Title: "Remote Desktop is on without Network Level Authentication: anyone on the network reaches the sign-in screen",
			Rem:   posture.Manual(fmt.Sprintf("Turn on Settings > System > Remote Desktop > Require devices to use Network Level Authentication to connect, or run `Set-ItemProperty -Path %s -Name UserAuthentication -Value 1` in an elevated PowerShell.", connector.PowerShellString(rdp.psPath())))},
	}
}

// smb1Check: the SMB1Protocol optional feature (Win32_OptionalFeature, InstallState 1 is enabled)
// and the server's SMB1 registry switch, which older systems use instead.
func (c *Connector) smb1Check(p probe) check {
	ch := check{ID: "smb1", Sev: finding.SevHigh, Title: "SMBv1, the file-sharing protocol WannaCry spread through, is enabled",
		Rem: posture.Manual("Run `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` in an elevated PowerShell and restart.")}
	if why, st, bad := p.unread("feature", "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"); bad {
		ch.Skip, ch.SkipState = why, st
		return ch
	}
	lm := c.key(HKLM, lanmanKey, "SMB1")
	if why, st, bad := lm.unreadable(); bad {
		ch.Skip, ch.SkipState = why, st
		return ch
	}
	feature := "not present"
	if f, ok := p.one("feature"); ok {
		feature = map[string]string{"1": "enabled", "2": "disabled", "3": "absent"}[f.get("state")]
	}
	reg, set := lm.text("SMB1")
	ch.Detail = "SMB1Protocol feature " + cmp.Or(feature, "?") + ", LanmanServer SMB1=" + cmp.Or(reg, "?")
	ch.OK = feature != "enabled" && !(set && reg == "1")
	return ch
}

// Allow entries for these SIDs open a share to anyone: Everyone, Anonymous Logon, Guests.
var openSIDs = []string{"S-1-1-0", "S-1-5-7", "S-1-5-32-546"}

// shareChecks: every shared disk folder but the administrative ones (a $ at the end), from
// Win32_Share, with its share permissions from Win32_LogicalShareSecuritySetting where readable.
func shareChecks(p probe) []check {
	if why, st, bad := p.unread("share", ""); bad {
		return []check{skipped("shares", "shares", why, st)}
	}
	aces := map[string][]record{}
	for _, a := range p.all("shareace") {
		aces[a.get("name")] = append(aces[a.get("name")], a)
	}
	denied := map[string]bool{}
	for _, a := range p.all("shareacl") {
		denied[a.get("name")] = true
	}
	var out []check
	for _, s := range p.all("share") {
		n := s.get("name")
		if strings.HasSuffix(n, "$") || s.get("type") != "0" {
			continue
		}
		ch := check{ID: "share:" + n, Area: "shares", Resource: "share", Name: n, Sev: finding.SevMedium,
			Detail: fmt.Sprintf("%s shares %s", n, s.get("path")), Evidence: map[string]any{"name": n, "path": s.get("path")},
			Title: fmt.Sprintf("Folder %s is shared on the network as %s", s.get("path"), n),
			Rem:   posture.Manual(fmt.Sprintf("If no other device needs it, stop sharing it (the folder's Properties > Sharing > Advanced Sharing > clear Share this folder), or run `Remove-SmbShare -Name %s` in an elevated PowerShell.", connector.PowerShellString(n)))}
		_, aclFailed := p.failure("shareacl:" + n)
		switch {
		case denied[n] || aclFailed:
			ch.Detail += "; its share permissions are unreadable"
			out = append(out, skipped("share-access:"+n, "share-access", needsAdmin("Get-SmbShareAccess -Name "+connector.PowerShellString(n)), finding.StateUnsupported))
		default:
			var open []string
			for _, a := range aces[n] {
				if a.get("type") == "0" && slices.Contains(openSIDs, a.get("sid")) && !slices.Contains(open, a.get("sid")) {
					open = append(open, a.get("sid"))
				}
			}
			if len(open) > 0 {
				ch.Sev = finding.SevHigh
				ch.Title = fmt.Sprintf("Folder %s is shared on the network with everyone, as %s", s.get("path"), n)
				ch.Detail += "; allowed to " + strings.Join(open, ", ")
				ch.Evidence["open_to"] = open
				ch.Rem.Summary += " To keep it shared, remove Everyone (and Guests, Anonymous) from Advanced Sharing > Permissions."
			}
		}
		out = append(out, ch)
	}
	return out
}
