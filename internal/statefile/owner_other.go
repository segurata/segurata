//go:build !unix

package statefile

import "io/fs"

// OwnerID is unavailable on systems without POSIX file ownership.
func OwnerID(fs.FileInfo) (int, bool) { return 0, false }
