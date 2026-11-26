package secrets

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/keychain"
)

// The default store runs the absolute /usr/bin/security, never one found in PATH, and maps its
// exit statuses to the fix that applies.
func TestResolveThroughSecurity(t *testing.T) {
	const kc = keychain.Security + " find-generic-password -s svc -w"
	if _, ok := store.(keychain.Keychain); !ok {
		t.Fatalf("default store %T", store)
	}
	cases := []struct {
		out        string
		fail       error
		value, err string
		notErr     string
	}{
		{out: "secret\n", value: "secret"},
		{fail: errors.New("/usr/bin/security: exit status 44: security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain."),
			err: "not found (add it with: security add-generic-password -s svc -a $USER -w)"},
		{out: "\n", err: "not found (add it with"},
		{fail: errors.New("/usr/bin/security: exit status 36: security: User interaction is not allowed."), err: "User interaction is not allowed", notErr: "not found"},
	}
	for _, c := range cases {
		ctx := stubStore(t, keychain.Keychain{Run: func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
			if cmd := name + " " + strings.Join(args, " "); cmd != kc || ctx.Value(ctxKey{}) != "caller" {
				t.Fatalf("ran %q", cmd)
			}
			return []byte(c.out), c.fail
		}})
		v, err := Resolve(ctx, "keychain:svc")
		if c.err == "" {
			if err != nil || v != c.value {
				t.Errorf("got %q, %v", v, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.err) || c.notErr != "" && strings.Contains(err.Error(), c.notErr) {
			t.Errorf("want an error with %q, got %v", c.err, err)
		}
	}
}
