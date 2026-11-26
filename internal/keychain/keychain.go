// Package keychain reads and writes generic passwords in the platform's credential store: the
// macOS login Keychain through /usr/bin/security, or the Windows Credential Manager. Elsewhere
// keychain: references are refused. A value never enters an argument list, which process listings
// show, nor an error.
package keychain

import (
	"context"
	"errors"
)

// Store is the credential store, for one account.
type Store interface {
	// Store adds or updates the item for service.
	Store(ctx context.Context, service, value string) error
	// Read returns the stored value, to use or check in memory, never to print. A missing item is
	// ErrNotFound.
	Read(ctx context.Context, service string) (string, error)
	// Hint says how a person adds the item for service by hand, the value typed at a prompt.
	Hint(service string) string
}

// ErrNotFound is returned by Read when no item has the service.
var ErrNotFound = errors.New("no such Keychain item")
