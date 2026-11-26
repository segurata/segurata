//go:build !windows

package rotation

import (
	"context"
	"errors"
)

// languageMode reads PowerShell's language mode on Windows; elsewhere --to-keychain never rewrites
// a PowerShell profile, and tests that do replace it.
var languageMode = func(context.Context, string) (string, error) {
	return "", errors.New("PowerShell profiles are rewritten on Windows only")
}
