//go:build windows

package windows

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/winsys"
)

// TestLiveInventory runs the real probe and registry reads on this PC and logs every result, so
// CI shows what each check found on the runner, as an administrator and as a standard user.
func TestLiveInventory(t *testing.T) {
	c := New()
	p := c.readProbe(context.Background())
	if p.whole != "" {
		t.Fatal(p.whole)
	}
	self, ok := p.one("self")
	sid, err := winsys.CurrentUserSID()
	if !ok || err != nil || self.get("sid") != sid {
		t.Fatalf("probe self %+v, token %s %v", self, sid, err)
	}
	t.Logf("elevated: %t", p.elevated())
	for _, sec := range []string{"os", "vol", "bde", "fw", "mp", "av", "fwp", "wu", "reboot", "user", "admin", "share", "feature"} {
		if f, failed := p.failure(sec); failed {
			t.Logf("section %s failed: %v", sec, f.fields)
			continue
		}
		for _, r := range p.all(sec) {
			t.Logf("section %s: %v", sec, r.fields)
		}
	}
	t.Logf("section tcp: %d listeners", len(p.all("tcp")))

	rec := inventory(t, c, connector.Request{})
	for _, f := range rec.Findings {
		t.Logf("finding %s %s: %s | %v", f.Severity, f.Resource.ID, f.Title, f.Evidence["detail"])
		if f.Remediation.Summary == "" {
			t.Errorf("%s has no remediation text", f.Resource.ID)
		}
	}
	for _, s := range rec.Statuses {
		t.Logf("status %s %s: %s", s.State, s.Scope, s.Detail)
		if s.State == finding.StateError {
			t.Errorf("a check failed on this runner: %s %s", s.Scope, s.Detail)
		}
	}
	for _, l := range rec.Logs {
		t.Log(l)
	}
	for _, ch := range c.Doctor(context.Background(), connector.Request{}) {
		t.Logf("doctor %s %s: %s %s", ch.Level, ch.What, ch.Detail, ch.Fix)
	}
}

// The screen lock remediation, applied and undone with reg.exe on a key of the test's own under
// HKCU, which it deletes at the end.
func TestScreenLockRoundTripOnTheRealRegistry(t *testing.T) {
	sys, err := winsys.System32()
	if err != nil {
		t.Fatal(err)
	}
	regExe := filepath.Join(sys, "reg.exe")
	root := `Software\segurata-test-` + strconv.Itoa(os.Getpid())
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(regExe, args...).CombinedOutput(); err != nil {
			t.Fatalf("reg %v: %v %s", args, err, out)
		}
	}
	t.Cleanup(func() { _ = exec.Command(regExe, "delete", `HKCU\`+root, "/f").Run() })
	c := New()
	c.DesktopKey = root + `\Desktop`
	key := `HKCU\` + c.DesktopKey
	run("add", key, "/v", "ScreenSaveActive", "/t", "REG_SZ", "/d", "0", "/f")
	run("add", key, "/v", "ScreenSaveTimeOut", "/t", "REG_SZ", "/d", "1800", "/f")
	s := c.readScreen()
	if p := s.byPolicy(); len(p) > 0 {
		t.Skipf("a policy sets %v on this runner", p)
	}
	if n, ok := s.machine.num("InactivityTimeoutSecs"); ok && n > 0 && n <= 300 {
		t.Skipf("the machine inactivity limit (%d s) already locks this runner", n)
	}
	if ch := c.screenLockCheck(300); ch.OK || ch.Rem.Action != actionScreenLock {
		t.Fatalf("before: %+v", ch)
	}
	rem := c.WithCredentials(connector.Credentials{Request: connector.Request{Config: map[string]any{lockLimitKey: float64(300)}}})
	plan, err := rem.Plan(context.Background(), screenFinding())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	io := connector.IO{Out: &out, Err: &out}
	if err := rem.Apply(context.Background(), screenFinding(), plan, io); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	got, err := c.Reg.Read(HKCU, c.DesktopKey, screenNames...)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"ScreenSaveActive": "1", "ScreenSaverIsSecure": "1", "ScreenSaveTimeOut": "300", "SCRNSAVE.EXE": filepath.Join(sys, "scrnsave.scr")}
	for n, v := range want {
		if got[n].Text != v || got[n].Type != regSZ {
			t.Errorf("after apply %s = %+v, want %q", n, got[n], v)
		}
	}
	if ch := c.screenLockCheck(300); !ch.OK {
		t.Errorf("after apply the check still fails: %s", ch.Detail)
	}
	for _, step := range plan.Undo {
		if err := (connector.System{}).Run(context.Background(), step, io); err != nil {
			t.Fatalf("undo %s: %v\n%s", step, err, out.String())
		}
	}
	got, err = c.Reg.Read(HKCU, c.DesktopKey, screenNames...)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["ScreenSaveActive"].Text != "0" || got["ScreenSaveTimeOut"].Text != "1800" {
		t.Errorf("undo left %+v", got)
	}
	if strings.Contains(out.String(), "ERROR") {
		t.Errorf("reg.exe said: %s", out.String())
	}
}
