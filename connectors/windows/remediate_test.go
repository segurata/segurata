package windows

import (
	"bytes"
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

func screenFinding() finding.Finding {
	return finding.Finding{Connector: "windows", Resource: finding.Resource{ID: "screen-lock"}, Remediation: finding.Remediation{Action: actionScreenLock}}
}

func screenCheck(t *testing.T, reg *fakeRegistry, limit int) check {
	t.Helper()
	c, _, _ := newTest(t, "", reg)
	return c.screenLockCheck(limit)
}

func TestScreenLockSeverity(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*fakeRegistry)
		ok   bool
		sev  finding.Severity
	}{
		"saver locks in 5 min":       {func(*fakeRegistry) {}, true, ""},
		"saver off":                  {func(r *fakeRegistry) { r.set(HKCU, desktopKey, "ScreenSaveActive", sz("0")) }, false, finding.SevMedium},
		"saver does not ask":         {func(r *fakeRegistry) { r.set(HKCU, desktopKey, "ScreenSaverIsSecure", sz("0")) }, false, finding.SevMedium},
		"no saver file":              {func(r *fakeRegistry) { delete(r.keys[regPath(HKCU, desktopKey)], "SCRNSAVE.EXE") }, false, finding.SevMedium},
		"saver file missing on disk": {func(r *fakeRegistry) { r.set(HKCU, desktopKey, "SCRNSAVE.EXE", sz(`C:\gone.scr`)) }, false, finding.SevMedium},
		"saver after 30 min":         {func(r *fakeRegistry) { r.set(HKCU, desktopKey, "ScreenSaveTimeOut", sz("1800")) }, false, finding.SevLow},
		"policy turns the saver off": {func(r *fakeRegistry) { r.set(HKCU, desktopPolicyKey, "ScreenSaveActive", sz("0")) }, false, finding.SevMedium},
		"inactivity limit locks": {func(r *fakeRegistry) {
			r.set(HKCU, desktopKey, "ScreenSaveActive", sz("0"))
			r.set(HKLM, systemPolicyKey, "InactivityTimeoutSecs", dword("600"))
		}, true, ""},
		"inactivity limit shorter than the saver": {func(r *fakeRegistry) {
			r.set(HKCU, desktopKey, "ScreenSaveTimeOut", sz("3600"))
			r.set(HKLM, systemPolicyKey, "InactivityTimeoutSecs", dword("300"))
		}, true, ""},
	} {
		reg := healthyRegistry()
		tc.edit(reg)
		ch := screenCheck(t, reg, defaultLockLimit)
		if ch.Skip != "" || ch.OK != tc.ok || (!tc.ok && ch.Sev != tc.sev) {
			t.Errorf("%s: ok=%t sev=%s skip=%q (%s)", name, ch.OK, ch.Sev, ch.Skip, ch.Detail)
		}
	}
}

func TestScreenLockUnderPolicyIsNotAutomatable(t *testing.T) {
	reg := healthyRegistry()
	reg.set(HKCU, desktopPolicyKey, "ScreenSaveTimeOut", sz("3600"))
	ch := screenCheck(t, reg, defaultLockLimit)
	if ch.OK || ch.Rem.Action != "" || !strings.Contains(ch.Rem.Summary, "policy") {
		t.Fatalf("%+v", ch)
	}
	c, _, _ := newTest(t, "", reg)
	if _, err := c.WithCredentials(connector.Credentials{}).Plan(context.Background(), screenFinding()); err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("planned over a policy: %v", err)
	}
}

func reg(args ...string) []string {
	return append([]string{filepath.Join(testSys32, "reg.exe")}, args...)
}

const desktop = `HKCU\Control Panel\Desktop`

func argvs(steps []connector.Step) [][]string {
	var out [][]string
	for _, s := range steps {
		out = append(out, s.Argv)
	}
	return out
}

func TestScreenLockPlanSetsOnlyWhatIsMissingAndUndoesEachValue(t *testing.T) {
	r := healthyRegistry()
	r.set(HKCU, desktopKey, "ScreenSaverIsSecure", sz("0"))
	r.set(HKCU, desktopKey, "ScreenSaveTimeOut", sz("1800"))
	delete(r.keys[regPath(HKCU, desktopKey)], "SCRNSAVE.EXE")
	c, _, ex := newTest(t, "", r)
	rem := c.WithCredentials(connector.Credentials{Request: connector.Request{Config: map[string]any{lockLimitKey: float64(300)}}})
	p, err := rem.Plan(context.Background(), screenFinding())
	if err != nil {
		t.Fatal(err)
	}
	wantDo := [][]string{
		reg("add", desktop, "/v", "ScreenSaverIsSecure", "/t", "REG_SZ", "/d", "1", "/f"),
		reg("add", desktop, "/v", "ScreenSaveTimeOut", "/t", "REG_SZ", "/d", "300", "/f"),
		reg("add", desktop, "/v", "SCRNSAVE.EXE", "/t", "REG_SZ", "/d", testSys32+`/scrnsave.scr`, "/f"),
	}
	wantDo[2][8] = filepath.Join(testSys32, "scrnsave.scr")
	wantUndo := [][]string{
		reg("add", desktop, "/v", "ScreenSaverIsSecure", "/t", "REG_SZ", "/d", "0", "/f"),
		reg("add", desktop, "/v", "ScreenSaveTimeOut", "/t", "REG_SZ", "/d", "1800", "/f"),
		reg("delete", desktop, "/v", "SCRNSAVE.EXE", "/f"),
	}
	if !slices.EqualFunc(argvs(p.Commands), wantDo, slices.Equal) || !slices.EqualFunc(argvs(p.Undo), wantUndo, slices.Equal) {
		t.Fatalf("commands %q\nundo %q", argvs(p.Commands), argvs(p.Undo))
	}
	if p.NeedsSudo() || !strings.Contains(p.Summary, "5 minutes") || len(p.SideEffects) != 3 {
		t.Errorf("%+v", p)
	}
	var out bytes.Buffer
	if err := rem.Apply(context.Background(), screenFinding(), p, connector.IO{Err: &out}); err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(ex.steps, wantDo, slices.Equal) {
		t.Errorf("ran %q", ex.steps)
	}

	// A plan that no longer matches what a fresh read plans is refused before anything runs.
	ex.steps = nil
	r.set(HKCU, desktopKey, "ScreenSaverIsSecure", sz("1"))
	if err := rem.Apply(context.Background(), screenFinding(), p, connector.IO{Err: &out}); err == nil || len(ex.steps) != 0 {
		t.Fatalf("applied a stale plan: %v %q", err, ex.steps)
	}
}

func TestScreenLockPlanRefusesWhatHasNothingToDo(t *testing.T) {
	c, _, _ := newTest(t, "", healthyRegistry())
	if _, err := c.WithCredentials(connector.Credentials{}).Plan(context.Background(), screenFinding()); err == nil || !strings.Contains(err.Error(), "already locks") {
		t.Fatalf("%v", err)
	}
	if _, err := c.WithCredentials(connector.Credentials{}).Plan(context.Background(), finding.Finding{Remediation: finding.Remediation{Action: "windows.other"}}); err == nil {
		t.Fatal("planned an unknown action")
	}
	r := healthyRegistry()
	delete(r.keys[regPath(HKCU, desktopKey)], "SCRNSAVE.EXE")
	c, _, _ = newTest(t, "", r)
	c.Exists = func(string) bool { return false }
	if _, err := c.WithCredentials(connector.Credentials{}).Plan(context.Background(), screenFinding()); err == nil || !strings.Contains(err.Error(), "scrnsave.scr") {
		t.Fatalf("%v", err)
	}
}

// The inventory's screen-lock finding carries the action the plan takes.
func TestScreenLockFindingIsAutomatable(t *testing.T) {
	r := healthyRegistry()
	r.set(HKCU, desktopKey, "ScreenSaveActive", sz("0"))
	c, _, _ := newTest(t, probeFile(t, "probe-healthy.txt"), r)
	f := inventory(t, c, connector.Request{}).ByResource(t, "windows_setting", "screen-lock")
	if f.Remediation.Action != actionScreenLock || !strings.Contains(f.Remediation.Summary, "Settings > Personalization > Lock screen") {
		t.Fatalf("%+v", f.Remediation)
	}
	if _, err := c.WithCredentials(connector.Credentials{}).Plan(context.Background(), f); err != nil {
		t.Fatal(err)
	}
}
