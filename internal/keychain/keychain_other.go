//go:build !darwin && !windows

package keychain

import (
	"context"
	"errors"
)

var errUnsupported = errors.New("keychain: references need the macOS Keychain or Windows Credential Manager; use env: or op:// here")

// Available: keychain: references do not resolve here.
const Available = false

// Default is a Store that refuses every call: this platform has no credential store segurata
// supports.
func Default(string) Store { return unsupported{} }

type unsupported struct{}

func (unsupported) Store(context.Context, string, string) error  { return errUnsupported }
func (unsupported) Read(context.Context, string) (string, error) { return "", errUnsupported }
func (unsupported) Hint(string) string                           { return errUnsupported.Error() }
