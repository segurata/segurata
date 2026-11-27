package windows

import (
	"context"
	"fmt"

	"github.com/segurata/segurata/internal/connector"
)

// doctorSections are the probe's sections, with the command that reads the same as an
// administrator when a standard user is refused.
var doctorSections = []struct{ sec, what, elevated string }{
	{"vol", "BitLocker (shell property)", ""},
	{"bde", "BitLocker (Win32_EncryptableVolume)", "manage-bde -status"},
	{"fw", "Defender Firewall (INetFwPolicy2)", ""},
	{"mp", "Microsoft Defender (MSFT_MpComputerStatus)", "Get-MpComputerStatus"},
	{"av", "Windows Security Center", ""},
	{"wu", "Windows Update Agent", ""},
	{"tcp", "listening ports (MSFT_NetTCPConnection)", ""},
	{"browser", "browser command lines (Win32_Process)", ""},
	{"user", "local accounts (Win32_UserAccount)", ""},
	{"admin", "Administrators members (ADSI)", ""},
	{"share", "shared folders (Win32_Share)", ""},
	{"feature", "SMB1Protocol feature (Win32_OptionalFeature)", "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"},
}

// Doctor runs the inventory's probe and registry reads and says which a standard user is refused.
func (c *Connector) Doctor(ctx context.Context, req connector.Request) []connector.Check {
	if c.OS != "windows" {
		return nil
	}
	var checks []connector.Check
	if _, err := lockLimit(req.Config); err != nil {
		checks = append(checks, connector.Check{Level: connector.Fail, What: "config", Detail: err.Error(), Fix: "set connectors.windows.config." + lockLimitKey + " to a number of seconds, such as 600"})
	}
	p := c.readProbe(ctx)
	if p.whole != "" {
		return append(checks, connector.Check{Level: connector.Fail, What: "Windows PowerShell", Detail: p.whole,
			Fix: "run `powershell -NoProfile -Command $ExecutionContext.SessionState.LanguageMode` from System32: it must start and say FullLanguage (an AppLocker or WDAC policy that constrains PowerShell blocks the probe)"})
	}
	for _, s := range doctorSections {
		f, failed := p.failure(s.sec)
		switch {
		case !failed:
			checks = append(checks, connector.Check{Level: connector.OK, What: s.what, Detail: fmt.Sprintf("%d records", len(p.all(s.sec)))})
		case absent(f):
			checks = append(checks, connector.Check{Level: connector.OK, What: s.what, Detail: "not on this edition of Windows"})
		case s.sec == "bde" && !p.elevated():
			checks = append(checks, connector.Check{Level: connector.OK, What: s.what, Detail: "administrators only; the shell property answers for a standard user"})
		default:
			why, _, _ := p.unread(s.sec, s.elevated)
			fix := "the checks that read it are skipped until it answers"
			if s.elevated != "" && f.is("denied") {
				fix = "run `" + s.elevated + "` in an elevated PowerShell to see it; segurata never elevates"
			}
			checks = append(checks, connector.Check{Level: connector.Warn, What: s.what, Detail: why, Fix: fix})
		}
	}
	if why, _, bad := c.readScreen().unreadable(); bad {
		checks = append(checks, connector.Check{Level: connector.Warn, What: "registry", Detail: why, Fix: "the screen lock check is skipped until it is readable"})
	} else {
		checks = append(checks, connector.Check{Level: connector.OK, What: "registry", Detail: "the screen saver settings are readable"})
	}
	return checks
}
