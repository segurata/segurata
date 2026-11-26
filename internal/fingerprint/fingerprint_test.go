package fingerprint

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// A run that starts while another is creating the key must read the whole key, never a file that
// exists but is still empty.
func TestCreateNeverExposesAHalfWrittenKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fingerprint.key")
	first, err := create(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := create(path) // lost the race: the key is already there
	if err != nil || second.Of("x") != first.Of("x") {
		t.Fatalf("second create: %v, same key %v", err, second.Of("x") == first.Of("x"))
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("left %d files behind, want only the key", len(entries))
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

func TestFindLocatesAValueByItsFingerprint(t *testing.T) {
	k := FromBytes([]byte("a fixed test key, not a secret!!"))
	value := "tok_" + strings.Repeat("Ab3", 8)
	line := `KEY="` + value + `" # other tok_` + strings.Repeat("Zz9", 8)
	fits := func(w string) bool { return strings.HasPrefix(w, "tok_") }
	if got := k.Find(line, len(value), k.Of(value), fits); got != value {
		t.Errorf("found %q", got)
	}
	if got := k.Find(line, len(value), k.Of("tok_"+strings.Repeat("x", 24)), fits); got != "" {
		t.Errorf("found %q for a value that is not there", got)
	}
	if got := k.Find(line, 0, k.Of(value), fits); got != "" {
		t.Error("a zero length finds nothing")
	}
}
