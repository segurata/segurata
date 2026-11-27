package windows

import (
	"cmp"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/segurata/segurata/connectors/internal/posture"
	"github.com/segurata/segurata/internal/finding"
)

// The screen saver values of HKCU\Control Panel\Desktop; the same names under the Group Policy key
// override them.
var screenNames = []string{"ScreenSaveActive", "ScreenSaverIsSecure", "ScreenSaveTimeOut", "SCRNSAVE.EXE"}

type screen struct {
	user, policy, machine, goodbye regKey
}

func (c *Connector) readScreen() screen {
	return screen{
		user:    c.key(HKCU, c.DesktopKey, screenNames...),
		policy:  c.key(HKCU, desktopPolicyKey, screenNames...),
		machine: c.key(HKLM, systemPolicyKey, "InactivityTimeoutSecs"),
		goodbye: c.key(HKCU, userWinlogonKey, "EnableGoodbye"),
	}
}

func (s screen) unreadable() (string, finding.State, bool) {
	for _, k := range []regKey{s.user, s.policy, s.machine} {
		if why, st, bad := k.unreadable(); bad {
			return why, st, true
		}
	}
	return "", "", false
}

func (s screen) value(name string) string { return effective(s.policy, s.user, name, "") }

// byPolicy names the screen saver values a policy sets, which a change of the user's own values
// would not override.
func (s screen) byPolicy() []string {
	var out []string
	for _, n := range screenNames {
		if _, ok := s.policy.text(n); ok {
			out = append(out, n)
		}
	}
	return out
}

var envVar = regexp.MustCompile(`%([^%]+)%`)

// expand replaces %NAME% with the environment variable, as REG_EXPAND_SZ data is read.
func expand(s string) string {
	return envVar.ReplaceAllStringFunc(s, func(m string) string {
		if v, ok := os.LookupEnv(m[1 : len(m)-1]); ok {
			return v
		}
		return m
	})
}

// lock is when the screen locks on its own, in seconds, 0 for never: the screen saver when it is
// on, password-protected and a screen saver file exists (Windows starts none otherwise), and the
// machine inactivity limit.
func (c *Connector) lock(s screen) (secs int, saver string) {
	timeout, _ := strconv.Atoi(s.value("ScreenSaveTimeOut"))
	exe := s.value("SCRNSAVE.EXE")
	switch {
	case s.value("ScreenSaveActive") != "1":
		saver = "screen saver off"
	case exe == "" || !c.Exists(expand(exe)):
		saver = "no screen saver picked"
	case s.value("ScreenSaverIsSecure") != "1":
		saver = fmt.Sprintf("screen saver after %d s without asking for a password", timeout)
	case timeout <= 0:
		saver = "screen saver never starts"
	default:
		secs, saver = timeout, fmt.Sprintf("screen saver after %d s, then the sign-in screen", timeout)
	}
	if n, ok := s.machine.num("InactivityTimeoutSecs"); ok && n > 0 && (secs == 0 || int(n) < secs) {
		secs = int(n)
	}
	return secs, saver
}

func (c *Connector) screenLockCheck(limit int) check {
	ch := check{ID: "screen-lock", Rem: finding.Remediation{Action: actionScreenLock,
		Summary: fmt.Sprintf("In Settings > Personalization > Lock screen > Screen saver, pick a screen saver, set Wait to %d minutes or less and tick On resume, display logon screen; or run `segurata remediate <id> --apply`.", max(limit/60, 1))}}
	s := c.readScreen()
	if why, st, bad := s.unreadable(); bad {
		ch.Skip, ch.SkipState = why, st
		return ch
	}
	secs, saver := c.lock(s)
	inactivity, _ := s.machine.text("InactivityTimeoutSecs")
	goodbye, _ := s.goodbye.text("EnableGoodbye")
	ch.Detail = fmt.Sprintf("%s; machine inactivity limit %s", saver, cmp.Or(inactivity, "unset"))
	ch.Evidence = map[string]any{"effective_seconds": secs, "max_seconds": limit, "dynamic_lock": goodbye == "1"}
	if p := s.byPolicy(); len(p) > 0 {
		ch.Evidence["set_by_policy"] = p
		ch.Rem = posture.Manual("Your organisation's policy sets the screen saver (" + fmt.Sprint(p) + "): ask whoever manages this PC to make it lock within the limit.")
	}
	switch {
	case secs == 0:
		ch.Sev = finding.SevMedium
		ch.Title = "The screen never locks on its own"
	case secs > limit:
		ch.Sev = finding.SevLow
		ch.Title = fmt.Sprintf("The screen locks only after %d minutes idle (more than %d)", secs/60, limit/60)
	default:
		ch.OK = true
	}
	return ch
}
