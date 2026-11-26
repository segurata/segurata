//go:build windows

package rotation

import (
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/fileacl/fileacltest"
	"github.com/segurata/segurata/internal/tracker"
)

// A destination whose DACL lets BUILTIN\Users read it would hand the new value to every account on
// the machine, and no parent folder closes it on Windows: replace refuses it before reading the
// clipboard.
func TestReplaceRefusesADestinationOtherAccountsCanRead(t *testing.T) {
	fx := newReplaceFixture(t)
	fileacltest.Expose(t, fx.env)
	before := read(t, fx.env)
	_, e, code := fx.run(t, "y\n", true, "replace", fx.id(), "--apply")
	if code != 1 || !strings.Contains(e, "can be accessed by other users") {
		t.Fatalf("exit %d: %s", code, e)
	}
	if read(t, fx.env) != before || fx.item(t).Status != tracker.Open {
		t.Error("an exposed destination was written")
	}
	for _, c := range fx.os.calls {
		if c.name == "paste" {
			t.Fatal("the clipboard was read for a plan that could never apply")
		}
	}
}

// The plan and the rewrite run on a real Windows DACL: ownership comes from the owner SID, and the
// rewritten file keeps the private descriptor it had.
func TestReplaceAppliesToAPrivateDestinationAndKeepsItsDACL(t *testing.T) {
	fx := newReplaceFixture(t)
	if _, e, code := fx.run(t, "y\n", true, "replace", fx.id(), "--apply"); code != 0 {
		t.Fatalf("exit %d: %s", code, e)
	}
	for _, p := range []string{fx.zshrc, fx.env} {
		if strings.Contains(read(t, p), fx.old) {
			t.Errorf("%s still holds the old value", p)
		}
		fileacltest.AssertPrivate(t, p)
	}
}
