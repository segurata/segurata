//go:build windows

package fileacl

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/segurata/segurata/internal/winsys"
)

func currentUser(t *testing.T) string {
	t.Helper()
	user, err := winsys.CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	return user
}

// setDACL replaces path's DACL, unprotected, as a user's own icacls change would.
func setDACL(t *testing.T, path, dacl string) {
	t.Helper()
	h, err := open(path, true, readControl|winsys.WriteDAC)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(h)
	if err := winsys.SetSecurityDescriptor(h, "D:"+dacl, winsys.DaclSecurityInformation); err != nil {
		t.Fatal(err)
	}
}

func assertPrivate(t *testing.T, path string) {
	t.Helper()
	if ok, err := HasPrivateDescriptor(path); err != nil || !ok {
		s, _ := Fingerprint(path)
		t.Fatalf("%s is not private (%v): %s", filepath.Base(path), err, s)
	}
	st, _ := os.Lstat(path)
	if mine, err := OwnedByMe(path, st); err != nil || !mine {
		t.Fatalf("%s: OwnedByMe = %v %v", filepath.Base(path), mine, err)
	}
	if m, err := Exposure(path); err != nil || m != Private {
		t.Fatalf("%s: Exposure = %o %v", filepath.Base(path), m, err)
	}
}

func TestCreatedPrivateFromTheStart(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "a", "b")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	assertPrivate(t, filepath.Join(root, "a"))
	assertPrivate(t, dir)
	f, err := CreatePrivate(dir, "t-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("synthetic"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if !strings.HasSuffix(f.Name(), ".tmp") {
		t.Errorf("name %s", f.Name())
	}
	assertPrivate(t, f.Name())
	if err := MkdirPrivate(dir); err != nil {
		t.Errorf("an existing folder: %v", err)
	}
	if _, err := CreatePrivate(dir, `x\*`); err == nil {
		t.Error("a pattern with a separator was accepted")
	}
}

func TestAnExtraGrantIsExposureAndMakePrivateClosesIt(t *testing.T) {
	user := currentUser(t)
	path := filepath.Join(t.TempDir(), "f")
	f, err := CreatePrivateAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	setDACL(t, path, "(A;;FA;;;"+user+")(A;;FR;;;BU)")
	if m, err := Exposure(path); err != nil || m != 0o644 {
		t.Fatalf("Users may read: Exposure = %o %v", m, err)
	}
	if d, _ := Describe(path); d != `readable by BUILTIN\Users` {
		t.Errorf("Describe = %q", d)
	}
	if err := MakePrivate(path); err != nil {
		t.Fatal(err)
	}
	assertPrivate(t, path)
}

func TestAdministratorsAndSystemAreTolerated(t *testing.T) {
	user := currentUser(t)
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	setDACL(t, path, "(A;;FA;;;"+user+")(A;;FA;;;SY)(A;;FA;;;BA)")
	if m, err := Exposure(path); err != nil || m != Private {
		t.Fatalf("Exposure = %o %v", m, err)
	}
	if ok, _ := HasPrivateDescriptor(path); ok {
		t.Error("an inheriting DACL with Administrators is tolerated, but it is not what segurata writes")
	}
}

func TestChangeableByOthersOnWindows(t *testing.T) {
	user := currentUser(t)
	dir := filepath.Join(t.TempDir(), "private")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	if got, err := ChangeableByOthers(dir); err != nil || got {
		t.Fatalf("a private folder: %v %v", got, err)
	}
	setDACL(t, dir, "(A;OICI;FA;;;"+user+")(A;;0x40;;;BU)")
	if got, err := ChangeableByOthers(dir); err != nil || !got {
		t.Fatalf("Users may delete entries: %v %v", got, err)
	}
}

// A group owner's grants count as exposure: only a user account owns with owner bits.
func TestUserAccountTellsUsersFromGroups(t *testing.T) {
	if !userAccount(currentUser(t)) {
		t.Error("the current user is not a user account")
	}
	for _, sid := range []string{"S-1-5-32-545", "S-1-5-11", "S-1-1-0"} {
		if userAccount(sid) {
			t.Errorf("%s counted as a user account", sid)
		}
	}
}

// On Windows only the file's own access list decides whether others can reach it.
func TestClosedToOthersReadsTheDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	user := currentUser(t)
	setDACL(t, path, "(A;;FA;;;"+user+")(A;;FA;;;SY)(A;;FA;;;BA)")
	if closed, err := ClosedToOthers(path, ""); err != nil || !closed {
		t.Fatalf("a file of the user, SYSTEM and Administrators: %v %v", closed, err)
	}
	setDACL(t, path, "(A;;FA;;;"+user+")(A;;FR;;;BU)")
	if closed, err := ClosedToOthers(path, ""); err != nil || closed {
		t.Fatalf("a file BUILTIN\\Users can read: %v %v", closed, err)
	}
}
