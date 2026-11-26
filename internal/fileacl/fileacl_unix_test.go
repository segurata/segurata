//go:build unix

package fileacl

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnedByMeOnUnix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if mine, err := OwnedByMe(path, st); err != nil || !mine {
		t.Fatalf("OwnedByMe = %v %v", mine, err)
	}
	if _, err := OwnedByMe(path, fakeInfo{st}); err == nil {
		t.Error("file information without an owner must be an error, never a pass")
	}
}

type fakeInfo struct{ fs.FileInfo }

func (fakeInfo) Sys() any { return nil }

func TestExposureAndEffectiveOnUnix(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "d")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if m, err := Exposure(path); err != nil || m != 0o644 {
		t.Fatalf("Exposure = %o %v", m, err)
	}
	if m, err := Effective(path, root); err != nil || m != 0o600 {
		t.Fatalf("a 644 file in a 700 folder: Effective = %o %v", m, err)
	}
	if err := os.Chmod(dir, 0o701); err != nil {
		t.Fatal(err)
	}
	if m, _ := Effective(path, root); m != 0o604 {
		t.Fatalf("a 701 folder lets others through but not the group: %o", m)
	}
	if d, _ := Describe(path); d != "mode 0644" {
		t.Errorf("Describe = %q", d)
	}
	if f, _ := Fingerprint(path); f != "0644" {
		t.Errorf("Fingerprint = %q", f)
	}
	if !Exposed(0o604) || Exposed(Private) || Exposed(0o700) {
		t.Error("Exposed")
	}
}

func TestChangeableByOthersOnUnix(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		mode fs.FileMode
		want bool
	}{{0o700, false}, {0o755, false}, {0o775, true}, {0o777, true}, {0o777 | fs.ModeSticky, false}} {
		if err := os.Chmod(dir, c.mode); err != nil {
			t.Fatal(err)
		}
		if got, err := ChangeableByOthers(dir); err != nil || got != c.want {
			t.Errorf("mode %v: changeable = %v %v, want %v", c.mode, got, err, c.want)
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, _ := ChangeableByOthers("/"); got {
		t.Error("a root-owned, unwritable / is not changeable by others")
	}
}

func TestPrivateCreationOnUnix(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "a", "b")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(root, "a"), dir} {
		if st, _ := os.Stat(d); st.Mode().Perm() != 0o700 {
			t.Errorf("%s mode %o", d, st.Mode().Perm())
		}
	}
	f, err := CreatePrivate(dir, "t-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if st, _ := os.Stat(f.Name()); st.Mode().Perm() != 0o600 || !strings.HasSuffix(f.Name(), ".tmp") {
		t.Errorf("%s mode %o", f.Name(), st.Mode().Perm())
	}
	if err := os.Chmod(f.Name(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]fs.FileMode{f.Name(): 0o600, dir: 0o700} {
		if err := MakePrivate(path); err != nil {
			t.Fatal(err)
		}
		if st, _ := os.Stat(path); st.Mode().Perm() != want {
			t.Errorf("%s mode %o after MakePrivate", path, st.Mode().Perm())
		}
	}
}
