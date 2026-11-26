// Package keychain reads and writes generic passwords in the macOS login Keychain through
// /usr/bin/security. A value travels on stdin or stdout, never in an argument list, which process
// listings show.
package keychain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/proc"
)

// Runner runs one external program with stdin and returns its stdout.
type Runner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

const Security = "/usr/bin/security"

// Exec is the real Runner. Its error carries stderr, never stdout, which may hold a value.
func Exec(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := proc.Command(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// ErrNotFound is returned by Read when no item has the service.
var ErrNotFound = errors.New("no such Keychain item")

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
	Run     Runner
	Account string
}

// storable is one word to `security -i`, which splits its input on spaces and interprets quotes
// and backslashes.
var storable = regexp.MustCompile(`^[!#-&(-\[\]-~]+$`)

// Store adds or updates the item through `security -i`, which reads its command from stdin.
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

// Read returns the stored value, to use or check in memory, never to print. A missing item is
// ErrNotFound; any other failure keeps the reason security gave.
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

// args is cmd for the account and service, ending in -w.
func (k Keychain) args(service string, cmd ...string) []string {
	if k.Account != "" {
		cmd = append(cmd, "-a", k.Account)
	}
	return append(cmd, "-s", service, "-w")
}
