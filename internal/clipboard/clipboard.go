// Package clipboard reads the text a person copied, and clears it once used: the macOS pasteboard
// through pbpaste and pbcopy, or the Windows clipboard. Elsewhere it refuses, pointing to --stdin.
package clipboard

import "context"

type Clipboard interface {
	// Read returns the copied text, to use in memory, never to print.
	Read(ctx context.Context) ([]byte, error)
	// Clear empties the clipboard.
	Clear(ctx context.Context) error
	// Caveat names where else the platform may keep a copy, or is empty.
	Caveat() string
}
