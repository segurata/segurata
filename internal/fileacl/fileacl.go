// Package fileacl is the one model of file privacy that every privacy decision in segurata uses,
// on Unix from the owner and mode bits and on Windows from the owner and the DACL.
//
// Exposure is given as Unix permission bits on every platform: the owner bits are the owner's, and
// the group and other bits are set when any other account may read (044) or change (022) the
// file. On Windows the accounts trusted beside the owner are SYSTEM and BUILTIN\Administrators,
// the analogue of root; files segurata creates grant access only to the current user and SYSTEM.
package fileacl

import "io/fs"

// Private is the exposure of a file nobody but its owner can reach.
const Private fs.FileMode = 0o600

// Exposed reports whether an Exposure lets any other account read or change the file.
func Exposed(m fs.FileMode) bool { return m.Perm()&0o077 != 0 }
