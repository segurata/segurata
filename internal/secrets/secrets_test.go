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

func TestResolve(t *testing.T) {
	t.Setenv("SEGURATA_TEST_KEY", "value")
	t.Setenv("SEGURATA_TEST_EMPTY", "")
	const kc = keychain.Security + " find-generic-password -s svc -w"
	cases := []struct {
		ref, cmd, out string
		fail          error
		value, err    string // err: a part of the error
		notErr        string // and a part it must not have
	}{
		{ref: "env:SEGURATA_TEST_KEY", value: "value"},
		{ref: "env:SEGURATA_TEST_MISSING", err: "SEGURATA_TEST_MISSING is not set"},
		{ref: "env:SEGURATA_TEST_EMPTY", err: "SEGURATA_TEST_EMPTY is not set"},
		// Keychain references run the absolute /usr/bin/security, never one found in PATH.
		{ref: "keychain:svc", cmd: kc, out: "secret\n", value: "secret"},
		// A missing item and a denied read have different fixes.
		{ref: "keychain:svc", cmd: kc, fail: errors.New("/usr/bin/security: exit status 44: security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain."),
			err: "not found (add it with: security add-generic-password -s svc"},
		{ref: "keychain:svc", cmd: kc, out: "\n", err: "not found (add it with"},
		{ref: "keychain:svc", cmd: kc, fail: errors.New("/usr/bin/security: exit status 36: security: User interaction is not allowed."),
			err: "User interaction is not allowed", notErr: "not found"},
		{ref: "op://v/i/f", cmd: "op read op://v/i/f", out: "secret\n", value: "secret"},
		{ref: "op://v/i/f", cmd: "op read op://v/i/f", fail: errors.New(`op: exit status 1: [ERROR] "i" isn't an item`), err: "isn't an item"},
		{ref: "op://v/i/f", cmd: "op read op://v/i/f", out: "\n", err: "could not be read"},
	}
	for _, c := range cases {
		ctx := context.Background()
		if c.cmd != "" {
			ctx = stubRun(t, c.cmd, c.out, c.fail)
		}
		v, err := Resolve(ctx, c.ref)
		if c.err == "" {
			if err != nil || v != c.value {
				t.Errorf("%s: got %q, %v", c.ref, v, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.err) || c.notErr != "" && strings.Contains(err.Error(), c.notErr) {
			t.Errorf("%s: want an error with %q, got %v", c.ref, c.err, err)
		}
	}
}

func TestErrorsNameTheKeyNeverTheValue(t *testing.T) {
	ctx := stubRun(t, keychain.Security+" find-generic-password -s svc -w", "", errors.New("exit 44"))
	t.Setenv("SEGURATA_TEST_KEY", "v4lue")
	got, errs := ResolveAll(ctx, map[string]string{"OPENAI_ADMIN_KEY": "keychain:svc", "OK": "env:SEGURATA_TEST_KEY"})
	var re *ResolveError
	if len(got) != 1 || got["OK"] != "v4lue" || len(errs) != 1 || !errors.As(errs[0], &re) || re.Key != "OPENAI_ADMIN_KEY" ||
		!strings.HasPrefix(errs[0].Error(), "OPENAI_ADMIN_KEY: ") || strings.Contains(errs[0].Error(), "v4lue") {
		t.Fatalf("got %v, %v", got, errs)
	}
}

func TestPlainValuesAreRejected(t *testing.T) {
	const plain = "sk-plaintext"
	if _, err := Resolve(context.Background(), plain); err == nil || strings.Contains(err.Error(), plain) {
		t.Fatal("a literal secret in config must be rejected without echoing it")
	}
}
