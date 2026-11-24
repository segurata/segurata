package fingerprint

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func fakeSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "fake_" + hex.EncodeToString(b)
}

func TestKeyIsCreatedPrivateAndStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conf", "fingerprint.key")
	a, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v err %v", st.Mode().Perm(), err)
	}
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	secret := fakeSecret(t)
	fa, fb := a.Of(secret), b.Of(secret)
	if fa != fb || !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(fa) {
		t.Errorf("fingerprints %q %q", fa, fb)
	}
	if a.Of("") != "" {
		t.Error("empty secret has a fingerprint")
	}
	other, _ := Load(filepath.Join(t.TempDir(), "k"))
	if other.Of(secret) == fa {
		t.Error("two keys gave the same fingerprint")
	}
	if err := os.WriteFile(path, []byte("not hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("corrupt key accepted")
	}
}

func TestOpenNeverCreates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fingerprint.key")
	if _, err := Open(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("want not-exist, got %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("Open created a key")
	}
}
