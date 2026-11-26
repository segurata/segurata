//go:build windows

package keychain

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"
)

var credDelete = advapi32.NewProc("CredDeleteW")

// testTarget is a synthetic target name, deleted when the test ends.
func testTarget(t *testing.T) string {
	t.Helper()
	target := "segurata-test-" + rand.Text()
	t.Cleanup(func() {
		p, err := syscall.UTF16PtrFromString(target)
		if err != nil {
			t.Fatal(err)
		}
		if r, _, e := credDelete.Call(uintptr(unsafe.Pointer(p)), credTypeGeneric, 0); r == 0 && !errors.Is(winError(e), ErrNotFound) {
			t.Errorf("deleting %s: %v", target, e)
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
	u := utf16.Encode([]rune(value))
	blob := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(blob[2*i:], c)
	}
	if err := writeBlob(target, "", blob); err != nil {
		t.Fatal(err)
	}
	if got, err := Default("").Read(context.Background(), target); err != nil || got != value {
		t.Fatalf("read %q, %v", got, err)
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
