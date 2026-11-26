package secrets

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/keychain"
)

type ctxKey struct{}

// stubRun makes run answer the one command want with out and err, and checks that the caller's
// context reached it.
func stubRun(t *testing.T, want string, out string, err error) context.Context {
	t.Helper()
	ctx := context.WithValue(context.Background(), ctxKey{}, "caller")
	orig := run
	run = func(got context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		if cmd := name + " " + strings.Join(args, " "); cmd != want {
			t.Fatalf("ran %q, want %q", cmd, want)
		}
		if got.Value(ctxKey{}) != "caller" {
			t.Fatal("the caller's context did not reach the command")
		}
		return []byte(out), err
	}
	t.Cleanup(func() { run = orig })
	return ctx
}

func TestResolveEnv(t *testing.T) {
	t.Setenv("SEGURATA_TEST_KEY", "value")
	if v, err := Resolve(context.Background(), "env:SEGURATA_TEST_KEY"); err != nil || v != "value" {
		t.Fatalf("got %q, %v", v, err)
	}
	if _, err := Resolve(context.Background(), "env:SEGURATA_TEST_MISSING"); err == nil {
		t.Fatal("missing env var should fail")
	}
}

// Keychain references go through internal/keychain: the absolute /usr/bin/security, never one
// found in PATH.
func TestResolveKeychain(t *testing.T) {
	ctx := stubRun(t, keychain.Security+" find-generic-password -s svc -w", "secret\n", nil)
	if v, err := Resolve(ctx, "keychain:svc"); err != nil || v != "secret" {
		t.Fatalf("got %q, %v", v, err)
	}
}

// A missing item and a denied read are different problems with different fixes.
func TestKeychainMissingIsToldApartFromDenied(t *testing.T) {
	want := keychain.Security + " find-generic-password -s svc -w"
	ctx := stubRun(t, want, "", errors.New("/usr/bin/security: exit status 44: security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain."))
	if _, err := Resolve(ctx, "keychain:svc"); err == nil || !strings.Contains(err.Error(), "not found (add it with: security add-generic-password -s svc") {
		t.Fatalf("missing: %v", err)
	}
	ctx = stubRun(t, want, "", errors.New("/usr/bin/security: exit status 36: security: User interaction is not allowed."))
	_, err := Resolve(ctx, "keychain:svc")
	if err == nil || strings.Contains(err.Error(), "not found") || !strings.Contains(err.Error(), "User interaction is not allowed") {
		t.Fatalf("denied: %v", err)
	}
}

func TestResolveOnePassword(t *testing.T) {
	ctx := stubRun(t, "op read op://v/i/f", "secret\n", nil)
	if v, err := Resolve(ctx, "op://v/i/f"); err != nil || v != "secret" {
		t.Fatalf("got %q, %v", v, err)
	}
	ctx = stubRun(t, "op read op://v/i/f", "", errors.New(`op: exit status 1: [ERROR] "i" isn't an item`))
	if _, err := Resolve(ctx, "op://v/i/f"); err == nil || !strings.Contains(err.Error(), "isn't an item") {
		t.Fatalf("op failure loses its reason: %v", err)
	}
}

func TestErrorsNameTheKeyNeverTheValue(t *testing.T) {
	ctx := stubRun(t, keychain.Security+" find-generic-password -s svc -w", "", errors.New("exit 44"))
	got, errs := ResolveAll(ctx, map[string]string{"OPENAI_ADMIN_KEY": "keychain:svc"})
	if len(got) != 0 || len(errs) != 1 || !strings.HasPrefix(errs[0].Error(), "OPENAI_ADMIN_KEY: ") {
		t.Fatalf("got %v, %v", got, errs)
	}
}

func TestPlainValuesAreRejected(t *testing.T) {
	const plain = "sk-plaintext"
	if _, err := Resolve(context.Background(), plain); err == nil || strings.Contains(err.Error(), plain) {
		t.Fatal("a literal secret in config must be rejected without echoing it")
	}
}
