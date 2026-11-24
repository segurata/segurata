//go:build !unix

package redact

import "io/fs"

// ownedByMe cannot be checked here; the rename fails on a file the account may not replace.
func ownedByMe(fs.FileInfo) bool { return true }
