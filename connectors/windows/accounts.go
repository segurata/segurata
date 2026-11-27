package windows

import (
	"fmt"
	"strings"

	"github.com/segurata/segurata/connectors/internal/posture"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// Well-known SIDs and RIDs.
const (
	administratorsSID = "S-1-5-32-544"
	guestRID          = "-501"
)

// Local accounts from Win32_UserAccount, and the members of Administrators through ADSI, named by
// SID so a localised group name does not matter.
func (c *Connector) accountChecks(p probe) []check {
	var out []check
	self, _ := p.one("self")
	selfSID := self.get("sid")
	users := map[string]record{}
	why, st, usersUnread := p.unread("user", "")
	if usersUnread {
		out = append(out, skipped("local-accounts", "local-accounts", why, st))
	}
	for _, u := range p.all("user") {
		users[u.get("sid")] = u
		if u.is("disabled") {
			continue
		}
		name := u.get("name")
		if !strings.HasSuffix(u.get("sid"), guestRID) && !u.is("pwreq") && u.get("pwreq") != "" {
			out = append(out, check{ID: "password-not-required:" + name, Area: "local-accounts", Resource: "local_account", Name: name, Sev: finding.SevMedium,
				Detail:   name + ": PasswordRequired=False",
				Evidence: map[string]any{"account": name, "sid": u.get("sid")},
				Title:    "Account " + name + " is allowed an empty password",
				Rem:      posture.Manual(fmt.Sprintf("Run `net user %s /passwordreq:yes` in an elevated PowerShell, and make sure the account has a password (Settings > Accounts > Sign-in options for your own).", connector.PowerShellString(name)))})
		}
	}
	if !usersUnread {
		out = append(out, guestCheck(p))
	}

	if why, st, bad := p.unread("admin", ""); bad {
		return append(out, skipped("local-admins", "local-accounts", why, st))
	}
	host, _ := c.Host()
	for _, m := range p.all("admin") {
		sid := m.get("sid")
		if sid == selfSID {
			continue
		}
		where, who := adsName(m.get("path"))
		if u, local := users[sid]; local {
			if u.is("disabled") {
				continue
			}
			name := u.get("name")
			out = append(out, check{ID: "local-admin:" + name, Area: "local-accounts", Resource: "local_account", Name: name, Sev: finding.SevHigh,
				Detail:   name + " is a member of Administrators",
				Evidence: map[string]any{"account": name, "sid": sid},
				Title:    "Account " + name + " is an administrator of this PC",
				Rem:      posture.Manual(fmt.Sprintf("If %[1]s does not need to install software or change settings for everyone, make it a standard user in Settings > Accounts > Other users > %[1]s > Change account type, or run `Remove-LocalGroupMember -SID %[2]s -Member %[3]s` in an elevated PowerShell; delete it if nobody uses it.", name, administratorsSID, connector.PowerShellString(name)))})
			continue
		}
		label := who
		if where != "" && !strings.EqualFold(where, host) {
			label = where + `\` + who
		}
		out = append(out, check{ID: "local-admin:" + label, Area: "local-accounts", Resource: "local_account", Name: label, Sev: finding.SevInfo,
			Detail:   fmt.Sprintf("%s (%s, %s) is a member of Administrators", label, strings.ToLower(m.get("class")), sid),
			Evidence: map[string]any{"account": label, "sid": sid, "class": m.get("class")},
			Title:    label + " is an administrator of this PC",
			Rem:      posture.Manual("A domain or Microsoft Entra account or group is usually there because your organisation manages this PC; if it is not, remove it with `Remove-LocalGroupMember -SID " + administratorsSID + " -Member " + connector.PowerShellString(label) + "` in an elevated PowerShell.")})
	}
	return out
}

func guestCheck(p probe) check {
	ch := check{ID: "guest-account", Area: "local-accounts", OK: true, Sev: finding.SevMedium, Detail: "no Guest account",
		Title: "The Guest account is enabled"}
	for _, u := range p.all("user") {
		if strings.HasSuffix(u.get("sid"), guestRID) {
			ch.OK, ch.Detail = u.is("disabled"), u.get("name")+": Disabled="+u.get("disabled")
			ch.Rem = posture.Manual(fmt.Sprintf("Run `Disable-LocalUser -SID %s` in an elevated PowerShell.", u.get("sid")))
		}
	}
	return ch
}

// adsName splits an ADsPath, WinNT://DOMAIN/name or WinNT://DOMAIN/COMPUTER/name, into where the
// account lives and its name. An account whose SID no longer resolves is WinNT://S-1-5-….
func adsName(path string) (string, string) {
	parts := strings.Split(strings.TrimPrefix(path, "WinNT://"), "/")
	if len(parts) == 1 {
		return "", parts[0]
	}
	return parts[len(parts)-2], parts[len(parts)-1]
}
