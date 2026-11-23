// Package secrets resolves secret references so connector credentials never live in plain files.
//
//	env:NAME              environment variable
//	keychain:service      macOS Keychain generic password
//	op://vault/item/field 1Password CLI
package secrets

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// runner is swapped in tests.
var runner = func(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return strings.TrimRight(string(out), "\r\n"), err
}

func Resolve(ref string) (string, error) {
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
		v, err := runner("security", "find-generic-password", "-s", svc, "-w")
		if err != nil || v == "" {
			return "", fmt.Errorf("keychain item %q not found (add it with: security add-generic-password -s %s -a $USER -w)", svc, svc)
		}
		return v, nil
	case strings.HasPrefix(ref, "op://"):
		v, err := runner("op", "read", ref)
		if err != nil || v == "" {
			return "", fmt.Errorf("1Password reference %q could not be read", ref)
		}
		return v, nil
	}
	return "", fmt.Errorf("unsupported secret reference %q: use env:, keychain: or op://", ref)
}

// ResolveAll resolves every reference; the errors name the key, never the value.
func ResolveAll(refs map[string]string) (map[string]string, []error) {
	out := map[string]string{}
	var errs []error
	for k, ref := range refs {
		v, err := Resolve(ref)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", k, err))
			continue
		}
		out[k] = v
	}
	return out, errs
}
