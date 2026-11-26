//go:build windows

package remediate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/connector/connectortest"
	"github.com/segurata/segurata/internal/fileacl"
	"github.com/segurata/segurata/internal/fileacl/fileacltest"
	"github.com/segurata/segurata/internal/finding"
)

func exposedFile(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("X=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileacltest.Expose(t, p)
	return p
}

func chmodFinding(path string) finding.Finding {
	return finding.Finding{Evidence: map[string]any{"path": path}, Remediation: finding.Remediation{Action: connector.ActionChmod600}}
}

// A file BUILTIN\Users can read gets the private descriptor, and the undo step puts back exactly
// the owner and DACL it had. A name holding any of PowerShell's single quotes stays one literal in
// the undo script: the exit hidden in it would end the script before Set-Acl.
func TestMakePrivateClosesAWindowsFileAndUndoRestoresItsDACL(t *testing.T) {
	for _, name := range []string{".env", "it's.env", "x\u2019;exit 7;\u2018.env", "x\u201A;exit 7;\u201B.env"} {
		t.Run(name, func(t *testing.T) { closeAndUndo(t, name) })
	}
}

func closeAndUndo(t *testing.T, name string) {
	path := exposedFile(t, name)
	before, err := fileacl.Fingerprint(path)
	if err != nil {
		t.Fatal(err)
	}
	f := chmodFinding(path)
	p, err := files{}.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Files) != 1 || p.Files[0].Access != before || !fileacl.Exposed(p.Files[0].Was) || fileacl.Exposed(p.Files[0].Mode) {
		t.Fatalf("plan %+v", p)
	}
	if s := p.Files[0].String(); !strings.Contains(s, "readable by other accounts") || strings.Contains(s, "S-1-") {
		t.Fatalf("change shown as %q", s)
	}
	if err := (files{}).Apply(context.Background(), f, p, connectortest.QuietIO()); err != nil {
		t.Fatal(err)
	}
	fileacltest.AssertPrivate(t, path)
	if _, err := (files{}).Plan(context.Background(), f); err == nil || !strings.Contains(err.Error(), "already private") {
		t.Fatalf("a private file planned again: %v", err)
	}

	if len(p.Undo) != 1 {
		t.Fatalf("undo %v", p.Undo)
	}
	if err := (connector.System{}).Run(context.Background(), p.Undo[0], connectortest.QuietIO()); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if after, err := fileacl.Fingerprint(path); err != nil || after != before {
		t.Fatalf("undo left %q, want %q (%v)", after, before, err)
	}
}

// A plan confirmed for another access list than the file has now never runs.
func TestMakePrivateRefusesAPlanWhoseDACLChanged(t *testing.T) {
	path := exposedFile(t, "key")
	f := chmodFinding(path)
	p, err := files{}.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	p.Files[0].Access += "(A;;FR;;;WD)"
	shown := &connectortest.ShownOnce{Remediator: files{}, Shown: &p}
	if err := Execute(context.Background(), f, shown, Options{Apply: true, Yes: true, IO: connectortest.QuietIO()}, neverReinventory(t)); err == nil {
		t.Fatal("applied a plan for another access list")
	}
	if ok, err := fileacl.HasPrivateDescriptor(path); err != nil || ok {
		t.Fatalf("the stale plan changed the file: %v %v", ok, err)
	}
}

func TestMakePrivateLeavesOutWhatItCannotOwn(t *testing.T) {
	theirs := exposedFile(t, "theirs.env")
	fileacltest.GiveAway(t, theirs)
	if _, err := (files{}).Plan(context.Background(), chmodFinding(theirs)); err == nil || !strings.Contains(err.Error(), "another account") {
		t.Fatalf("file of another account: %v", err)
	}
}
