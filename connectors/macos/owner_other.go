//go:build !unix

package macos

import "io/fs"

// ownerUID has no answer off Unix; the connector only inspects macOS.
func ownerUID(fs.FileInfo) (uint32, bool) { return 0, false }
