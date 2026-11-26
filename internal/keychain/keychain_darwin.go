package keychain

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/segurata/segurata/internal/proc"
)

const Security = "/usr/bin/security"

// Default is the login Keychain for account ("" matches any account on reads).
func Default(account string) Store { return Keychain{Run: proc.Exec, Account: account} }

// itemNotFound is security's exit status for errSecItemNotFound.
const itemNotFound = 44

// notFound reads the exit status, or the message when a Runner gives no exit status.
func notFound(err error) bool {
	if err == nil {
		return false
	}
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == itemNotFound || strings.Contains(err.Error(), "could not be found in the keychain")
}

// Keychain is the login Keychain, for one account ("" matches any account on reads).
type Keychain struct {
	Run     proc.Runner
	Account string
}

// storable is one word to `security -i`, which splits its input on spaces and interprets quotes
// and backslashes.
var storable = regexp.MustCompile(`^[!#-&(-\[\]-~]+$`)

// Store adds or updates the item through `security -i`, which reads its command from stdin: the
// value travels on stdin, never in an argument list.
func (k Keychain) Store(ctx context.Context, service, value string) error {
	if !storable.MatchString(value) {
		return fmt.Errorf("storing %s in the Keychain: the value has spaces, quotes, backslashes or non-ASCII characters, which security -i would alter; store it by hand", service)
	}
	if !storable.MatchString(k.Account) || !storable.MatchString(service) {
		return fmt.Errorf("storing %q in the Keychain for account %q: security -i needs both as one plain word", service, k.Account)
	}
	cmd := strings.Join(append(k.args(service, "add-generic-password", "-U"), value), " ") + "\n"
	if _, err := k.Run(ctx, []byte(cmd), Security, "-i"); err != nil {
		return fmt.Errorf("storing %s in the Keychain: %s", service, strings.ReplaceAll(err.Error(), value, "[value]"))
	}
	return nil
}

// Read keeps the reason security gave for any failure but a missing item.
func (k Keychain) Read(ctx context.Context, service string) (string, error) {
	out, err := k.Run(ctx, nil, Security, k.args(service, "find-generic-password")...)
	if notFound(err) {
		return "", fmt.Errorf("%w: %s", ErrNotFound, service)
	}
	if err != nil {
		return "", fmt.Errorf("reading %s from the Keychain: %w", service, err)
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}

func (Keychain) Hint(service string) string {
	return "add it with: security add-generic-password -s " + service + " -a $USER -w"
}

// args is cmd for the account and service, ending in -w.
func (k Keychain) args(service string, cmd ...string) []string {
	if k.Account != "" {
		cmd = append(cmd, "-a", k.Account)
	}
	return append(cmd, "-s", service, "-w")
}
