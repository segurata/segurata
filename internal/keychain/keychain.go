// Package keychain reads and writes generic passwords in the macOS login Keychain through
// /usr/bin/security, and runs the few other programs that handle secret values. A value travels on
// stdin or stdout, never in an argument list: arguments show up in process listings, stdin does
// not. Tests inject a Runner instead of running anything.
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

// Security is the only program Keychain runs.
const Security = "/usr/bin/security"

// Exec is the real Runner. Its error carries stderr, never stdout: stdout is the channel a value
// comes back on.
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

// Scrub replaces every copy of value in msg with placeholder before msg is printed.
func Scrub(msg, value, placeholder string) string {
	if value == "" {
		return msg
	}
	return strings.ReplaceAll(msg, value, placeholder)
}

// ErrNotFound is returned by Read when no item has the service.
var ErrNotFound = errors.New("no such Keychain item")

// itemNotFound is security's exit status for errSecItemNotFound.
const itemNotFound = 44

// notFound reports whether security failed because the item does not exist: its exit status, or
// its message when a Runner gives no exit status.
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

// storable is what `security -i` reads back as one word: it splits its input on spaces and
// interprets quotes and backslashes, so anything else would be stored altered.
var storable = regexp.MustCompile(`^[!#-&(-\[\]-~]+$`)

// Store adds or updates (-U) the item through `security -i`, which reads its commands from stdin,
// so the value never appears in an argument list.
func (k Keychain) Store(ctx context.Context, service, value string) error {
	if !storable.MatchString(value) {
		return fmt.Errorf("storing %s in the Keychain: the value has spaces, quotes, backslashes or non-ASCII characters, which security -i would alter; store it by hand", service)
	}
	cmd := fmt.Sprintf("add-generic-password -U -a %s -s %s -w %s\n", k.Account, service, value)
	if _, err := k.Run(ctx, []byte(cmd), Security, "-i"); err != nil {
		return fmt.Errorf("storing %s in the Keychain: %s", service, Scrub(err.Error(), value, "[value]"))
	}
	return nil
}

// Read returns the stored value, to use or check in memory; callers never print it. A missing item
// is ErrNotFound; any other failure (access denied, a prompt nobody answered) keeps the reason
// security gave.
func (k Keychain) Read(ctx context.Context, service string) (string, error) {
	out, err := k.Run(ctx, nil, Security, k.args("find-generic-password", service, "-w")...)
	if notFound(err) {
		return "", fmt.Errorf("%w: %s", ErrNotFound, service)
	}
	if err != nil {
		return "", fmt.Errorf("reading %s from the Keychain: %w", service, err)
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}

func (k Keychain) args(cmd, service string, extra ...string) []string {
	args := []string{cmd}
	if k.Account != "" {
		args = append(args, "-a", k.Account)
	}
	return append(append(args, "-s", service), extra...)
}
