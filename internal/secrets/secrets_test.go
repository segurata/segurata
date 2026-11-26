package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/keychain"
)

type ctxKey struct{}

func callerCtx() context.Context { return context.WithValue(context.Background(), ctxKey{}, "caller") }

// stubRun makes run answer the one command want with out and err, and checks that the caller's
// context reached it.
func stubRun(t *testing.T, want string, out string, err error) context.Context {
	t.Helper()
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
	return callerCtx()
}

// fakeStore holds one item, or fails every read with err.
type fakeStore struct {
	t          *testing.T
	service, v string
	err        error
}

func (f fakeStore) Store(context.Context, string, string) error { return errors.New("not used") }
func (f fakeStore) Hint(service string) string                  { return "add it with: fake-add " + service }
func (f fakeStore) Read(ctx context.Context, service string) (string, error) {
	if ctx.Value(ctxKey{}) != "caller" {
		f.t.Fatal("the caller's context did not reach the store")
	}
	switch {
	case f.err != nil:
		return "", f.err
	case service != f.service:
		return "", fmt.Errorf("%w: %s", keychain.ErrNotFound, service)
	}
	return f.v, nil
}

// stubStore makes store s, and returns a context to resolve with.
func stubStore(t *testing.T, s keychain.Store) context.Context {
	t.Helper()
	orig := store
	store = s
	t.Cleanup(func() { store = orig })
	return callerCtx()
}

func TestResolve(t *testing.T) {
	t.Setenv("SEGURATA_TEST_KEY", "value")
	t.Setenv("SEGURATA_TEST_EMPTY", "")
	cases := []struct {
		ref, cmd, out string
		fail          error
		store         *fakeStore
		value, err    string // err: a part of the error
		notErr        string // and a part it must not have
	}{
		{ref: "env:SEGURATA_TEST_KEY", value: "value"},
		{ref: "env:SEGURATA_TEST_MISSING", err: "SEGURATA_TEST_MISSING is not set"},
		{ref: "env:SEGURATA_TEST_EMPTY", err: "SEGURATA_TEST_EMPTY is not set"},
		{ref: "keychain:svc", store: &fakeStore{service: "svc", v: "secret"}, value: "secret"},
		// A missing item and a denied read have different fixes; the store says how to add one.
		{ref: "keychain:svc", store: &fakeStore{service: "other"}, err: `keychain item "svc" not found (add it with: fake-add svc)`},
		{ref: "keychain:svc", store: &fakeStore{service: "svc"}, err: "not found (add it with"},
		{ref: "keychain:svc", store: &fakeStore{err: errors.New("User interaction is not allowed.")}, err: "User interaction is not allowed", notErr: "not found"},
		{ref: "op://v/i/f", cmd: "op read op://v/i/f", out: "secret\n", value: "secret"},
		{ref: "op://v/i/f", cmd: "op read op://v/i/f", fail: errors.New(`op: exit status 1: [ERROR] "i" isn't an item`), err: "isn't an item"},
		{ref: "op://v/i/f", cmd: "op read op://v/i/f", out: "\n", err: "could not be read"},
	}
	for _, c := range cases {
		ctx := context.Background()
		switch {
		case c.cmd != "":
			ctx = stubRun(t, c.cmd, c.out, c.fail)
		case c.store != nil:
			c.store.t = t
			ctx = stubStore(t, *c.store)
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
	ctx := stubStore(t, fakeStore{t: t, service: "other"})
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
