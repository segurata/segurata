package windows

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// actionScreenLock is the one remediation: the user's own screen saver settings, under HKCU.
// Machine-wide fixes (firewall, BitLocker, UAC, Remote Desktop, SMBv1) need an administrator and
// stay commands in the finding's text.
const actionScreenLock = "windows.screen-lock.set"

var regTypes = map[uint32]string{regSZ: "REG_SZ", regExpandSZ: "REG_EXPAND_SZ", regDWORD: "REG_DWORD", regQWORD: "REG_QWORD"}

// WithCredentials binds the instance's config: the plan reads screen_lock_seconds.
func (c *Connector) WithCredentials(cs connector.Credentials) connector.Remediator {
	return &remediator{c: c, req: cs.Request}
}

type remediator struct {
	c   *Connector
	req connector.Request
}

// Plan reads the screen saver values as they are now and sets only those that keep the screen
// from locking within the limit; the undo puts each back, or deletes it when it was not set.
func (r *remediator) Plan(_ context.Context, f finding.Finding) (connector.Plan, error) {
	c := r.c
	if f.Remediation.Action != actionScreenLock {
		return connector.Plan{}, fmt.Errorf("windows has no remediation %q", f.Remediation.Action)
	}
	if c.OS != "windows" {
		return connector.Plan{}, errors.New("the windows connector only remediates on Windows")
	}
	limit, err := lockLimit(r.req.Config)
	if err != nil {
		return connector.Plan{}, err
	}
	s := c.readScreen()
	if why, _, bad := s.unreadable(); bad {
		return connector.Plan{}, errors.New(why)
	}
	if p := s.byPolicy(); len(p) > 0 {
		return connector.Plan{}, fmt.Errorf("a policy sets %v under HKCU\\%s, which would override your own settings: ask whoever manages this PC", p, desktopPolicyKey)
	}
	if secs, _ := c.lock(s); secs > 0 && secs <= limit {
		return connector.Plan{}, fmt.Errorf("the screen already locks after %d s idle", secs)
	}
	sys, err := c.System32()
	if err != nil {
		return connector.Plan{}, err
	}
	blank := filepath.Join(sys, "scrnsave.scr")
	want := map[string]string{"ScreenSaveActive": "1", "ScreenSaverIsSecure": "1"}
	if t, _ := strconv.Atoi(s.value("ScreenSaveTimeOut")); t <= 0 || t > limit {
		want["ScreenSaveTimeOut"] = strconv.Itoa(limit)
	}
	var effects []string
	if exe := s.value("SCRNSAVE.EXE"); exe == "" || !c.Exists(expand(exe)) {
		if !c.Exists(blank) {
			return connector.Plan{}, fmt.Errorf("no screen saver is picked and %s, the blank one, does not exist: pick one in Settings > Personalization > Lock screen > Screen saver", blank)
		}
		want["SCRNSAVE.EXE"] = blank
		effects = append(effects, "No screen saver was picked: the blank one (scrnsave.scr) is set; pick another in Settings > Personalization > Lock screen > Screen saver.")
	}
	reg := filepath.Join(sys, "reg.exe")
	key := `HKCU\` + c.DesktopKey
	p := connector.Plan{Action: actionScreenLock,
		Summary: fmt.Sprintf("Lock the screen after %d minutes idle: start the screen saver then, and show the sign-in screen when it ends.", max(limit/60, 1)),
		SideEffects: append(effects,
			"Windows reads these settings when you sign in: sign out and back in, or restart, for them to take effect.",
			"After that idle time the screen saver starts, and getting back in takes your password, PIN or Windows Hello.")}
	for _, n := range screenNames {
		v, ok := want[n]
		if !ok {
			continue
		}
		old, set := s.user.vals[n]
		if set && old.Text == v {
			continue
		}
		p.Commands = append(p.Commands, connector.Step{Argv: []string{reg, "add", key, "/v", n, "/t", "REG_SZ", "/d", v, "/f"}})
		if set {
			typ := regTypes[old.Type]
			if typ == "" {
				return connector.Plan{}, fmt.Errorf("%s\\%s has registry type %d, which segurata would not restore", key, n, old.Type)
			}
			p.Undo = append(p.Undo, connector.Step{Argv: []string{reg, "add", key, "/v", n, "/t", typ, "/d", old.Text, "/f"}})
		} else {
			p.Undo = append(p.Undo, connector.Step{Argv: []string{reg, "delete", key, "/v", n, "/f"}})
		}
	}
	return p, nil
}

// Apply runs only the commands a fresh read plans now: they are the whole allowlist.
func (r *remediator) Apply(ctx context.Context, f finding.Finding, p connector.Plan, io connector.IO) error {
	fresh, err := r.Plan(ctx, f)
	if err != nil {
		return err
	}
	return connector.Allowlist{fresh.Action: fresh.Commands}.Run(ctx, p, r.c.Exec, io)
}
