package windows

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/posture"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// skipped is a check that could not run, in area.
func skipped(id, area, why string, state finding.State) check {
	return check{ID: id, Area: area, Skip: why, SkipState: state}
}

// Disk encryption. Win32_EncryptableVolume is the documented source, readable by administrators
// only; for a standard user Windows exposes the state through the shell property Explorer uses,
// which Microsoft does not document, so only its values for on (1) and off (2) are trusted.
func diskChecks(p probe) []check {
	if why, st, bad := p.unread("vol", ""); bad {
		return []check{skipped("bitlocker", "bitlocker", why, st)}
	}
	bde := map[string]string{}
	for _, r := range p.all("bde") {
		bde[strings.ToUpper(r.get("letter"))] = r.get("protection")
	}
	var out []check
	for _, v := range p.all("vol") {
		letter := strings.ToUpper(v.get("letter"))
		ch := check{ID: "bitlocker-" + strings.ToLower(strings.TrimSuffix(letter, ":")), Area: "bitlocker", Name: "BitLocker " + letter,
			Sev: finding.SevMedium, Title: fmt.Sprintf("Fixed drive %s is not encrypted (BitLocker is off)", letter),
			Rem: posture.Manual(fmt.Sprintf("Turn on BitLocker for %s in Control Panel > System and Security > BitLocker Drive Encryption, or run `manage-bde -on %s -RecoveryPassword` in an elevated PowerShell. Keep the recovery password somewhere other than this PC.", letter, letter))}
		if v.is("system") {
			ch.Sev = finding.SevHigh
			ch.Title = fmt.Sprintf("The system drive %s is not encrypted (BitLocker is off)", letter)
			ch.Rem = posture.Manual(fmt.Sprintf("Turn on Device encryption in Settings > Privacy & security > Device encryption, or BitLocker in Control Panel > System and Security > BitLocker Drive Encryption; or run `manage-bde -on %s -RecoveryPassword` in an elevated PowerShell. Keep the recovery password somewhere other than this PC.", letter))
		}
		source, on, known := "", false, false
		if prot, ok := bde[letter]; ok {
			// ProtectionStatus: 0 off, 1 on, 2 unknown, which a locked, so encrypted, volume reports.
			source, on, known = "Win32_EncryptableVolume ProtectionStatus="+prot, prot != "0", prot == "0" || prot == "1" || prot == "2"
		} else {
			s := v.get("shell")
			source, on, known = "shell property System.Volume.BitLockerProtection="+cmp.Or(s, "?"), s == "1", s == "1" || s == "2"
		}
		ch.Detail = letter + ": " + source
		ch.Evidence = map[string]any{"drive": letter, "system": v.is("system"), "source": source}
		switch {
		case !known:
			ch.Skip, ch.SkipState = fmt.Sprintf("%s (no documented answer for a standard user); %s", ch.Detail, needsAdmin("manage-bde -status "+letter)), finding.StateUnsupported
		case on:
			ch.OK = true
		}
		out = append(out, ch)
	}
	if len(out) == 0 {
		return []check{skipped("bitlocker", "bitlocker", "no fixed drive found", finding.StateError)}
	}
	return out
}

// firewallProfiles are NET_FW_PROFILE_TYPE2 values.
var firewallProfiles = []struct {
	bit  string
	name string
}{{"1", "Domain"}, {"2", "Private"}, {"4", "Public"}}

// isMicrosoft tells Microsoft's own products from others in Windows Security Center lists.
func isMicrosoft(product string) bool {
	p := strings.ToLower(product)
	return strings.Contains(p, "windows defender") || strings.Contains(p, "microsoft defender") || strings.Contains(p, "windows firewall")
}

func otherProducts(p probe, sec string) []string {
	var out []string
	for _, r := range p.all(sec) {
		if n := r.get("name"); n != "" && !isMicrosoft(n) && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// Microsoft Defender Firewall, from INetFwPolicy2 (HNetCfg.FwPolicy2): enabled and default
// inbound action per profile.
func firewallChecks(p probe) []check {
	if why, st, bad := p.unread("fw", ""); bad {
		return []check{skipped("firewall", "firewall", why, st)}
	}
	byBit := map[string]record{}
	for _, r := range p.all("fw") {
		byBit[r.get("profile")] = r
	}
	cur, _ := p.one("fwcur")
	active, _ := strconv.Atoi(cur.get("types"))
	others := otherProducts(p, "fwp")
	var out []check
	for _, prof := range firewallProfiles {
		r, ok := byBit[prof.bit]
		id := "firewall-" + strings.ToLower(prof.name)
		if !ok {
			out = append(out, skipped(id, "firewall", "INetFwPolicy2 did not report the "+prof.name+" profile", finding.StateError))
			continue
		}
		bit, _ := strconv.Atoi(prof.bit)
		isActive := active&bit != 0
		on := check{ID: id, Area: "firewall", Name: prof.name + " firewall", OK: r.is("enabled"), Sev: finding.SevHigh,
			Detail:   fmt.Sprintf("%s profile: enabled=%s, active=%t", prof.name, r.get("enabled"), isActive),
			Evidence: map[string]any{"profile": prof.name, "active": isActive},
			Title:    fmt.Sprintf("Microsoft Defender Firewall is off for %s networks", strings.ToLower(prof.name)),
			Rem:      posture.Manual(fmt.Sprintf("Turn it on in Windows Security > Firewall & network protection > %s network, or run `Set-NetFirewallProfile -Profile %s -Enabled True` in an elevated PowerShell.", prof.name, prof.name))}
		switch {
		case len(others) > 0:
			on.Sev = finding.SevInfo
			on.Title += "; Windows Security Center lists " + strings.Join(others, ", ") + " as the firewall"
			on.Evidence["firewall_products"] = others
		case prof.name == "Domain" && !isActive:
			on.Sev = finding.SevLow
			on.Title += " (it applies only on a work domain network)"
		}
		out = append(out, on)
		out = append(out, check{ID: id + "-inbound", Area: "firewall", Name: prof.name + " firewall inbound", OK: r.get("inbound") != "1", Sev: finding.SevMedium,
			Detail: fmt.Sprintf("%s profile: default inbound action %s", prof.name, map[string]string{"0": "block", "1": "allow"}[r.get("inbound")]),
			Title:  fmt.Sprintf("Microsoft Defender Firewall lets in every incoming connection on %s networks by default", strings.ToLower(prof.name)),
			Rem:    posture.Manual(fmt.Sprintf("Run `Set-NetFirewallProfile -Profile %s -DefaultInboundAction Block` in an elevated PowerShell; apps you allowed keep their rules.", prof.name))})
	}
	return out
}

const maxSignatureAge = 7 // days

// Antivirus: Microsoft Defender from MSFT_MpComputerStatus (what Get-MpComputerStatus reads), and
// other products registered in Windows Security Center (root\SecurityCenter2, client editions
// only). Security Center's productState is undocumented, so another product is listed, not judged.
func antivirusChecks(p probe) []check {
	av := check{ID: "antivirus", Area: "antivirus", Name: "Antivirus", Sev: finding.SevHigh,
		Title: "No antivirus is on: Microsoft Defender real-time protection is off",
		Rem:   posture.Manual("Turn on Real-time protection in Windows Security > Virus & threat protection > Manage settings, or run `Set-MpPreference -DisableRealtimeMonitoring $false` in an elevated PowerShell.")}
	mp, mpOK := p.one("mp")
	mpFail, mpFailed := p.failure("mp")
	others := otherProducts(p, "av")
	_, scFailed := p.failure("av")
	mode := mp.get("mode")
	defenderOn := mpOK && mp.is("rtp") && mp.is("av") && (mode == "" || mode == "Normal")
	if mpOK {
		av.Evidence = map[string]any{"defender_running_mode": mode, "defender_real_time": mp.get("rtp")}
	}
	switch {
	case defenderOn:
		av.OK, av.Detail = true, "Microsoft Defender real-time protection is on"
	case len(others) > 0:
		av.Sev = finding.SevInfo
		av.Detail = "Windows Security Center lists " + strings.Join(others, ", ") + "; Microsoft Defender is not the active antivirus (" + cmp.Or(mode, "?") + ")"
		av.Title = "The antivirus is " + strings.Join(others, ", ") + ": check in Windows Security that it is on and up to date"
		av.Rem = posture.Manual("Open Windows Security > Virus & threat protection: it names the active antivirus and whether it is on. segurata cannot read another product's state.")
		av.Evidence = map[string]any{"products": others}
	case mpFailed && !absent(mpFail):
		why, st, _ := p.unread("mp", "Get-MpComputerStatus")
		return []check{skipped("antivirus", "antivirus", why, st)}
	default:
		av.Detail = "Microsoft Defender: " + defenderState(mp, mpOK)
		if scFailed {
			av.Detail += "; Windows Security Center is not available here (Windows Server), so no other antivirus could be listed"
		} else {
			av.Detail += "; Windows Security Center lists no other antivirus"
		}
	}
	out := []check{av}
	if !defenderOn {
		return out
	}
	age, err := strconv.Atoi(mp.get("sigage"))
	out = append(out, check{ID: "defender-signatures", Area: "antivirus", OK: err == nil && age <= maxSignatureAge, Sev: finding.SevMedium,
		Detail: "signature age " + cmp.Or(mp.get("sigage"), "?") + " days", Evidence: map[string]any{"days": age},
		Title: fmt.Sprintf("Microsoft Defender's virus definitions are %d days old", age),
		Rem:   posture.Manual("Update them in Windows Security > Virus & threat protection > Protection updates > Check for updates, or run `Update-MpSignature` in an elevated PowerShell.")})
	if t := mp.get("tamper"); t != "" {
		out = append(out, check{ID: "defender-tamper", Area: "antivirus", OK: mp.is("tamper"), Sev: finding.SevLow, Detail: "IsTamperProtected=" + t,
			Title: "Microsoft Defender Tamper Protection is off: a program running as administrator can turn Defender off",
			Rem:   posture.Manual("Turn on Windows Security > Virus & threat protection > Manage settings > Tamper Protection.")})
	}
	return out
}

func defenderState(mp record, ok bool) string {
	if !ok {
		return "not installed"
	}
	return fmt.Sprintf("real-time protection %s, antivirus %s, mode %s", cmp.Or(mp.get("rtp"), "?"), cmp.Or(mp.get("av"), "?"), cmp.Or(mp.get("mode"), "?"))
}

// Registry keys the checks read, under HKLM unless the name says HKCU.
const (
	desktopKey       = `Control Panel\Desktop`
	desktopPolicyKey = `Software\Policies\Microsoft\Windows\Control Panel\Desktop`
	userWinlogonKey  = `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
	systemPolicyKey  = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	winlogonKey      = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	tsKey            = `SYSTEM\CurrentControlSet\Control\Terminal Server`
	rdpTCPKey        = tsKey + `\WinStations\RDP-Tcp`
	tsPolicyKey      = `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
	lanmanKey        = `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
	secureBootKey    = `SYSTEM\CurrentControlSet\Control\SecureBoot\State`
	wuauservKey      = `SYSTEM\CurrentControlSet\Services\wuauserv`
	auPolicyKey      = `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`
)

const maxUpdateAge = 30 // days

// Updates: the Windows Update service's start type and the automatic-update policy from the
// registry; the last successful installation (IAutomaticUpdatesResults) and a pending restart
// (ISystemInformation) from the Windows Update Agent.
func (c *Connector) updateChecks(p probe) []check {
	var out []check
	svc := c.key(HKLM, wuauservKey, "Start")
	if why, st, bad := svc.unreadable(); bad {
		out = append(out, skipped("update-service", "updates", why, st))
	} else {
		start, _ := svc.text("Start")
		out = append(out, check{ID: "update-service", Area: "updates", OK: start != "4", Sev: finding.SevMedium, Detail: "wuauserv Start=" + cmp.Or(start, "?"),
			Title: "The Windows Update service is disabled",
			Rem:   posture.Manual("Run `Set-Service -Name wuauserv -StartupType Manual; Start-Service wuauserv` in an elevated PowerShell (Manual is its default: Windows starts it when needed).")})
	}
	pol := c.key(HKLM, auPolicyKey, "NoAutoUpdate")
	if why, st, bad := pol.unreadable(); bad {
		out = append(out, skipped("update-policy", "updates", why, st))
	} else {
		v, _ := pol.text("NoAutoUpdate")
		out = append(out, check{ID: "update-policy", Area: "updates", OK: v != "1", Sev: finding.SevMedium, Detail: "NoAutoUpdate=" + cmp.Or(v, "?"),
			Title: "A policy turns off automatic Windows updates",
			Rem:   posture.Manual(fmt.Sprintf("Unless your organisation manages updates another way, set Configure Automatic Updates to Not Configured in gpedit.msc (Computer Configuration > Administrative Templates > Windows Components > Windows Update), or run `Remove-ItemProperty -Path %s -Name NoAutoUpdate` in an elevated PowerShell.", connector.PowerShellString(pol.psPath())))})
	}
	if why, st, bad := p.unread("wu", ""); bad {
		out = append(out, skipped("updates-stale", "updates", why, st))
	} else {
		wu, _ := p.one("wu")
		ch := check{ID: "updates-stale", Area: "updates", Sev: finding.SevMedium,
			Rem: posture.Manual("Open Settings > Windows Update and select Check for updates; install what it offers and restart.")}
		at, ok := parseWUDate(wu.get("installed"))
		if !ok {
			ch.Skip, ch.SkipState = "Windows Update reports no successful installation (last search "+cmp.Or(wu.get("searched"), "?")+"); see Settings > Windows Update > Update history", finding.StateUnsupported
		} else {
			days := int(c.Now().Sub(at).Hours() / 24)
			ch.OK = days <= maxUpdateAge
			ch.Detail = fmt.Sprintf("last successful installation %s (%d days ago)", at.Format(time.DateOnly), days)
			ch.Evidence = map[string]any{"last_installed": at.Format(time.RFC3339), "days": days}
			ch.Title = fmt.Sprintf("No Windows update was installed in the last %d days", days)
		}
		out = append(out, ch)
	}
	if why, st, bad := p.unread("reboot", ""); bad {
		out = append(out, skipped("updates-restart", "updates", why, st))
	} else {
		rb, _ := p.one("reboot")
		out = append(out, check{ID: "updates-restart", Area: "updates", OK: !rb.is("required"), Sev: finding.SevMedium, Detail: "RebootRequired=" + cmp.Or(rb.get("required"), "?"),
			Title: "Windows updates are waiting for a restart to finish installing",
			Rem:   posture.Manual("Restart the PC (Start > Power > Update and restart).")})
	}
	return out
}

// parseWUDate reads the probe's date: UTC with a Z, or without a zone, which the Windows Update
// Agent gives in UTC.
func parseWUDate(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02T15:04:05Z", "2006-01-02T15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil && t.Year() > 1601 {
			return t, true
		}
	}
	return time.Time{}, false
}

// System settings read from the registry: auto-logon, UAC, Secure Boot.
func (c *Connector) systemChecks() []check {
	out := []check{c.autoLogonCheck()}
	out = append(out, c.uacChecks()...)
	return append(out, c.secureBootCheck())
}

func (c *Connector) autoLogonCheck() check {
	wl := c.key(HKLM, winlogonKey, "AutoAdminLogon", "DefaultUserName")
	if why, st, bad := wl.unreadable(); bad {
		return skipped("auto-logon", "", why, st)
	}
	auto, _ := wl.text("AutoAdminLogon")
	user, _ := wl.text("DefaultUserName")
	stored, err := c.Reg.Has(HKLM, winlogonKey, "DefaultPassword")
	ch := check{ID: "auto-logon", OK: auto != "1", Sev: finding.SevHigh, Detail: "AutoAdminLogon=" + cmp.Or(auto, "?"),
		Evidence: map[string]any{"user": user, "password_in_registry": stored},
		Title:    "Windows signs in automatically as " + cmp.Or(user, "?") + ", without a password",
		Rem:      posture.Manual(fmt.Sprintf("Turn off automatic sign-in: run `Set-ItemProperty -Path %[1]s -Name AutoAdminLogon -Value 0; Remove-ItemProperty -Path %[1]s -Name DefaultPassword -ErrorAction SilentlyContinue` in an elevated PowerShell, then restart.", connector.PowerShellString(wl.psPath())))}
	if err != nil {
		ch.Detail += "; whether DefaultPassword is stored could not be read: " + err.Error()
	}
	if stored {
		ch.Title = "Windows signs in automatically as " + cmp.Or(user, "?") + ", and the password is stored in plain text in the registry"
		ch.Rem.Summary += " Every account on this PC could read that password: change it."
	}
	return ch
}

func (c *Connector) uacChecks() []check {
	uac := c.key(HKLM, systemPolicyKey, "EnableLUA", "ConsentPromptBehaviorAdmin")
	if why, st, bad := uac.unreadable(); bad {
		return []check{skipped("uac", "uac", why, st)}
	}
	lua, _ := uac.text("EnableLUA")
	prompt, _ := uac.text("ConsentPromptBehaviorAdmin")
	return []check{
		{ID: "uac", Area: "uac", OK: lua != "0", Sev: finding.SevHigh, Detail: "EnableLUA=" + cmp.Or(lua, "?"),
			Title: "User Account Control is off: every program an administrator starts runs with full rights",
			Rem:   posture.Manual(fmt.Sprintf("Run `Set-ItemProperty -Path %s -Name EnableLUA -Value 1` in an elevated PowerShell and restart; then check Control Panel > User Accounts > Change User Account Control settings.", connector.PowerShellString(uac.psPath())))},
		{ID: "uac-prompt", Area: "uac", OK: prompt != "0", Sev: finding.SevHigh, Detail: "ConsentPromptBehaviorAdmin=" + cmp.Or(prompt, "?"),
			Title: "User Account Control raises administrators to full rights without asking",
			Rem:   posture.Manual(fmt.Sprintf("Move the slider in Control Panel > User Accounts > Change User Account Control settings to its default, or run `Set-ItemProperty -Path %s -Name ConsentPromptBehaviorAdmin -Value 5` in an elevated PowerShell.", connector.PowerShellString(uac.psPath())))},
	}
}

func (c *Connector) secureBootCheck() check {
	sb := c.key(HKLM, secureBootKey, "UEFISecureBootEnabled")
	ch := check{ID: "secure-boot", Sev: finding.SevMedium, Title: "Secure Boot is off: the PC would start a tampered boot loader",
		Rem: posture.Manual("Turn on Secure Boot in the PC's UEFI firmware settings (Settings > System > Recovery > Advanced startup > Restart now > Troubleshoot > Advanced options > UEFI Firmware Settings), then check System Information (msinfo32) > Secure Boot State.")}
	v, set := sb.text("UEFISecureBootEnabled")
	switch why, st, bad := sb.unreadable(); {
	case bad:
		ch.Skip, ch.SkipState = why, st
	case !set:
		ch.Skip = "this PC does not report a Secure Boot state (it starts in legacy BIOS mode, or the firmware has none); System Information (msinfo32) > Secure Boot State says which"
	default:
		ch.OK, ch.Detail = v == "1", "UEFISecureBootEnabled="+v
	}
	return ch
}
