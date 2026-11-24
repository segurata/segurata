package secrets

import (
	"errors"
	"strings"
	"testing"
)

func stubRunner(t *testing.T, want string, out string, err error) {
	t.Helper()
	orig := runner
	runner = func(name string, args ...string) (string, error) {
		if got := name + " " + strings.Join(args, " "); got != want {
			t.Fatalf("ran %q, want %q", got, want)
		}
		return out, err
	}
	t.Cleanup(func() { runner = orig })
}

func TestResolveEnv(t *testing.T) {
	t.Setenv("SEGURATA_TEST_KEY", "value")
	if v, err := Resolve("env:SEGURATA_TEST_KEY"); err != nil || v != "value" {
		t.Fatalf("got %q, %v", v, err)
	}
	if _, err := Resolve("env:SEGURATA_TEST_MISSING"); err == nil {
		t.Fatal("missing env var should fail")
	}
}

func TestResolveKeychain(t *testing.T) {
	stubRunner(t, "security find-generic-password -s svc -w", "secret", nil)
	if v, err := Resolve("keychain:svc"); err != nil || v != "secret" {
		t.Fatalf("got %q, %v", v, err)
	}
}

func TestResolveOnePassword(t *testing.T) {
	stubRunner(t, "op read op://v/i/f", "secret", nil)
	if v, err := Resolve("op://v/i/f"); err != nil || v != "secret" {
		t.Fatalf("got %q, %v", v, err)
	}
}

func TestErrorsNameTheKeyNeverTheValue(t *testing.T) {
	stubRunner(t, "security find-generic-password -s svc -w", "", errors.New("exit 44"))
	got, errs := ResolveAll(map[string]string{"OPENAI_ADMIN_KEY": "keychain:svc"})
	if len(got) != 0 || len(errs) != 1 || !strings.HasPrefix(errs[0].Error(), "OPENAI_ADMIN_KEY: ") {
		t.Fatalf("got %v, %v", got, errs)
	}
}

func TestPlainValuesAreRejected(t *testing.T) {
	if _, err := Resolve("sk-plaintext"); err == nil {
		t.Fatal("a literal secret in config must be rejected")
	}
}
