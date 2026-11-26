//go:build windows

package keychain

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"

	"github.com/segurata/segurata/internal/winsys"
)

// testTarget is a synthetic target name, deleted when the test ends.
func testTarget(t *testing.T) string {
	t.Helper()
	target := "segurata-test-" + rand.Text()
	t.Cleanup(func() {
		if err := winsys.CredDelete(target, credTypeGeneric); err != nil && !errors.Is(winError(err), ErrNotFound) {
			t.Errorf("deleting %s: %v", target, err)
		}
	})
	return target
}

func TestCredentialManagerRoundTripStaysOnThisMachine(t *testing.T) {
	target, value := testTarget(t), "synthetic-v4lue-ñ-€-"+rand.Text()
	s := Default("tester")
	if err := s.Store(context.Background(), target, value); err != nil {
		t.Fatal(err)
	}
	got, err := s.Read(context.Background(), target)
	if err != nil || got != value {
		t.Fatalf("read back %q, %v", got, err)
	}
	c, err := readCredential(target)
	if err != nil {
		t.Fatal(err)
	}
	if c.typ != credTypeGeneric || c.persist != credPersistLocalMachine || c.user != "tester" {
		t.Errorf("type %d persist %d user %q: want a generic, local-machine (never roaming) item for tester", c.typ, c.persist, c.user)
	}
	if err := s.Store(context.Background(), target, "second-"+value); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Read(context.Background(), target); got != "second-"+value {
		t.Error("Store did not update the item in place")
	}
}

// cmdkey /generic and PowerShell store UTF-16LE text without a terminator.
func TestCredentialManagerReadsACmdkeyStyleBlob(t *testing.T) {
	target, value := testTarget(t), "cmdkey-ßtyle-"+rand.Text()
	if err := writeBlob(target, "", utf16le(value)); err != nil {
		t.Fatal(err)
	}
	if got, err := Default("").Read(context.Background(), target); err != nil || got != value {
		t.Fatalf("read %q, %v", got, err)
	}
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func TestDecodeBlobReadsUTF16AndRefusesWhatItWouldGarble(t *testing.T) {
	for _, c := range []struct {
		name, want, err string
		blob            []byte
	}{
		{"cmdkey text", "k3y-ñ-€-😀", "", utf16le("k3y-ñ-€-😀")},
		{"with a terminator", "synthetic-token", "", utf16le("synthetic-token\x00")},
		{"UTF-8 ASCII from a Go keyring", "", "looks like UTF-8", []byte("gho_synthetic012345678")},
		{"UTF-8 with a non-ASCII letter", "", "looks like UTF-8", []byte("synthetic-ñ-token")},
		{"odd length", "", "odd length", []byte{'a', 0, 'b'}},
		{"unpaired high surrogate", "", "unpaired surrogate", []byte{0x3d, 0xd8}},
		{"lone surrogate", "", "unpaired surrogate", []byte{'a', 0, 0x00, 0xd8, 'b', 0}},
		{"reversed pair", "", "unpaired surrogate", []byte{0x00, 0xdc, 0x00, 0xd8}},
		{"NUL inside", "", "control characters", utf16le("ab\x00cd")},
		{"newline", "", "control characters", utf16le("ab\ncd")},
	} {
		got, err := decodeBlob(c.blob)
		if c.err == "" && (err != nil || got != c.want) || c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err) || got != "") {
			t.Errorf("%s: %q, %v", c.name, got, err)
		}
	}
}

// cmdkey writes generic credentials with enterprise persistence, which roams with a roaming profile
// or credential roaming: docs/secrets.md says so, and segurata's own Store writes local-machine items.
func TestCmdkeyItemsUseEnterprisePersistence(t *testing.T) {
	cmdkey, err := exec.LookPath("cmdkey")
	if err != nil {
		t.Fatal(err)
	}
	target, value := testTarget(t), "synthetic-"+rand.Text()
	if out, err := exec.Command(cmdkey, "/generic:"+target, "/user:tester", "/pass:"+value).CombinedOutput(); err != nil {
		t.Fatalf("cmdkey: %v: %s", err, strings.ReplaceAll(string(out), value, "[value]"))
	}
	c, err := readCredential(target)
	if err != nil {
		t.Fatal(err)
	}
	if c.persist != credPersistEnterprise {
		t.Errorf("cmdkey persistence %d, want %d (enterprise): fix docs/secrets.md", c.persist, credPersistEnterprise)
	}
	if got, err := Default("").Read(context.Background(), target); err != nil || got != value {
		t.Errorf("read back %v", err)
	}
}

func TestCredentialManagerRefusals(t *testing.T) {
	ctx := context.Background()
	if _, err := Default("").Read(ctx, "segurata-test-missing-"+rand.Text()); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing item: %v", err)
	}
	odd := testTarget(t)
	if err := writeBlob(odd, "", []byte{'a', 0, 'b'}); err != nil {
		t.Fatal(err)
	}
	if _, err := Default("").Read(ctx, odd); err == nil || !strings.Contains(err.Error(), "odd length") {
		t.Errorf("odd blob: %v", err)
	}
	utf8Item, utf8Value := testTarget(t), "gho_synthetic"+rand.Text()[:11]
	if err := writeBlob(utf8Item, "", []byte(utf8Value)); err != nil {
		t.Fatal(err)
	}
	if got, err := Default("").Read(ctx, utf8Item); err == nil || got != "" || !strings.Contains(err.Error(), "looks like UTF-8") || strings.Contains(err.Error(), utf8Value) {
		t.Errorf("UTF-8 blob: %q, %v", got, err)
	}
	long, value := testTarget(t), strings.Repeat("x", maxBlob/2+1)
	if err := Default("").Store(ctx, long, value); err == nil || strings.Contains(err.Error(), value) {
		t.Errorf("oversized value: %v", err)
	}
	if _, err := Default("").Read(ctx, long); !errors.Is(err, ErrNotFound) {
		t.Errorf("an oversized value left an item: %v", err)
	}
	if err := Default("").Store(ctx, long, ""); err == nil {
		t.Error("an empty value was stored")
	}
}

func TestCredentialManagerHintPrompts(t *testing.T) {
	if got := Default("").Hint("svc"); !strings.Contains(got, "cmdkey /generic:svc /user:%USERNAME% /pass") {
		t.Errorf("hint %q", got)
	}
}

func TestWinErrorMapsTheFailuresWithTheirOwnFix(t *testing.T) {
	if !errors.Is(winError(errorNotFound), ErrNotFound) || winError(errorNoSuchLogonSession) != errNoLogonSession ||
		winError(syscall.Errno(0)) != syscall.EINVAL {
		t.Error("errno mapping")
	}
}
