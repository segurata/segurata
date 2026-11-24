// Package secrets resolves secret references so connector credentials never live in plain files.
//
//	env:NAME              environment variable
//	keychain:service      macOS Keychain generic password
//	op://vault/item/field 1Password CLI
package secrets

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/segurata/segurata/internal/keychain"
)

// run runs `security` and `op` with a timeout and returns stdout, its error carrying stderr; tests
// swap it.
var run keychain.Runner = keychain.Exec

// Resolve returns the value a reference points to. ctx bounds the program that reads it, which may
// be waiting on a prompt nobody will answer in an unattended run.
func Resolve(ctx context.Context, ref string) (string, error) {
	switch {
	case strings.HasPrefix(ref, "env:"):
		name := strings.TrimPrefix(ref, "env:")
		v, ok := os.LookupEnv(name)
		if !ok || v == "" {
			return "", fmt.Errorf("environment variable %s is not set", name)
		}
		return v, nil
	case strings.HasPrefix(ref, "keychain:"):
		svc := strings.TrimPrefix(ref, "keychain:")
		v, err := keychain.Keychain{Run: run}.Read(ctx, svc)
		switch {
		case errors.Is(err, keychain.ErrNotFound) || err == nil && v == "":
			return "", fmt.Errorf("keychain item %q not found (add it with: security add-generic-password -s %s -a $USER -w)", svc, svc)
		case err != nil:
			return "", fmt.Errorf("keychain item %q could not be read: %w", svc, err)
		}
		return v, nil
	case strings.HasPrefix(ref, "op://"):
		out, err := run(ctx, nil, "op", "read", ref)
		v := strings.TrimRight(string(out), "\r\n")
		if err != nil || v == "" {
			return "", errors.Join(fmt.Errorf("1Password reference %q could not be read", ref), err)
		}
		return v, nil
	}
	return "", fmt.Errorf("unsupported secret reference %q: use env:, keychain: or op://", ref)
}

// ResolveError is a reference that could not be resolved, naming its key, never the value.
type ResolveError struct {
	Key string
	Err error
}

func (e *ResolveError) Error() string { return e.Key + ": " + e.Err.Error() }
func (e *ResolveError) Unwrap() error { return e.Err }

// ResolveAll resolves every reference. Each error is a *ResolveError, in key order.
func ResolveAll(ctx context.Context, refs map[string]string) (map[string]string, []error) {
	out := map[string]string{}
	var errs []error
	for _, k := range slices.Sorted(maps.Keys(refs)) {
		v, err := Resolve(ctx, refs[k])
		if err != nil {
			errs = append(errs, &ResolveError{Key: k, Err: err})
			continue
		}
		out[k] = v
	}
	return out, errs
}
