package macos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const everyoneDenyDelete = " 0: group:everyone deny delete"

// homeTest is a connector whose home folder has the given mode and the ACL macOS puts on homes.
func homeTest(t *testing.T, mode os.FileMode) (*Connector, string, *recordingExec) {
	t.Helper()
	c, fr, ex := newTest(t, healthy())
	home, _ := c.Home()
	if err := os.Chmod(home, mode); err != nil {
		t.Fatal(err)
	}
	fr.replies[strings.Join([]string{lsBin, "-led", home}, " ")] = fmt.Sprintf("drwxr-xr-x+ 3 me staff 96 24 nov 00:40 %s\n%s\n", home, everyoneDenyDelete)
	return c, home, ex
}

func TestHomeFolderReadableByOthers(t *testing.T) {
	c, home, _ := homeTest(t, 0o755)
	f := inventory(t, c).ByResource(t, "macos_setting", "home-private")
	if f.Severity != finding.SevMedium || f.Remediation.Action != actionHomePrivate {
		t.Fatalf("%s %q", f.Severity, f.Remediation.Action)
	}
	if f.Evidence["path"] != home || f.Evidence["mode"] != "755" || f.Evidence["acl"] != true ||
		fmt.Sprint(f.Evidence["acl_entries"]) != "[0: group:everyone deny delete]" {
		t.Fatalf("evidence %v", f.Evidence)
	}
	for _, m := range []os.FileMode{0o750, 0o705, 0o770} {
		if !homeReadable(m) {
			t.Errorf("mode %o should count as readable by others (every user is in staff)", m)
		}
	}
}

func TestPrivateOrTraversableHomeIsOK(t *testing.T) {
	for _, mode := range []os.FileMode{0o700, 0o711} {
		c, _, _ := homeTest(t, mode)
		rec := inventory(t, c)
		for _, f := range rec.Findings {
			if f.Resource.ID == "home-private" {
				t.Errorf("mode %o reported: %v", mode, f.Evidence["detail"])
			}
		}
	}
}

func TestHomePrivatePlanAndApply(t *testing.T) {
	c, home, ex := homeTest(t, 0o755)
	// Whatever path a finding claims, the plan acts on the home folder the OS reports.
	f := finding.Finding{Connector: "macos", Evidence: map[string]any{"path": "/etc"}, Remediation: finding.Remediation{Action: actionHomePrivate}}
	p, err := c.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if got := stepStrings(p.Commands); fmt.Sprint(got) != fmt.Sprint([]string{"/bin/chmod 700 " + home}) || p.NeedsSudo() {
		t.Fatalf("commands %q", got)
	}
	if got := stepStrings(p.Undo); fmt.Sprint(got) != fmt.Sprint([]string{"/bin/chmod 755 " + home}) {
		t.Fatalf("undo %q", got)
	}
	if err := c.Apply(context.Background(), f, p, termIO()); err != nil {
		t.Fatal(err)
	}
	// Only the octal chmod runs: no -N (strip ACL) or -a/-E, so the ACL entries stay.
	want := connector.Step{Argv: []string{chmodBin, "700", home}}
	if len(ex.ran) != 1 || !ex.ran[0].Equal(want) {
		t.Fatalf("ran %v", ex.ran)
	}
	allow, err := c.homeAllowlist()
	if err != nil {
		t.Fatal(err)
	}
	other := connector.Plan{Action: actionHomePrivate, Commands: []connector.Step{{Argv: []string{chmodBin, "700", "/Users/someone-else"}}}}
	if err := allow.Run(context.Background(), other, ex, termIO()); !errors.Is(err, connector.ErrRefused) {
		t.Fatalf("chmod of another folder allowed: %v", err)
	}
	if err := os.Chmod(home, 0o711); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Plan(context.Background(), f); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("planned on a private home: %v", err)
	}
}

// On a real Mac, the planned chmod keeps the ACL macOS puts on home folders.
func TestHomePrivateKeepsACLsOnARealFolder(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("ACLs via chmod +a are macOS only")
	}
	c, home, _ := homeTest(t, 0o755)
	if out, err := exec.Command(chmodBin, "+a", "group:everyone deny delete", home).CombinedOutput(); err != nil {
		t.Skipf("cannot add an ACL here: %v %s", err, out)
	}
	// The deny-delete entry would stop TempDir from cleaning up; this cleanup runs before it.
	t.Cleanup(func() { _ = exec.Command(chmodBin, "-N", home).Run() })
	p, err := c.homePlan()
	if err != nil {
		t.Fatal(err)
	}
	allow := connector.Allowlist{actionHomePrivate: p.Commands}
	if err := allow.Run(context.Background(), p, connector.System{}, termIO()); err != nil {
		t.Fatal(err)
	}
	out, _ := exec.Command(lsBin, "-led", home).Output()
	if fi, _ := os.Stat(home); fi.Mode().Perm() != 0o700 || !strings.Contains(string(out), "group:everyone deny delete") {
		t.Fatalf("after chmod: %o\n%s", fi.Mode().Perm(), out)
	}
}
