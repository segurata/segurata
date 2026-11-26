//go:build windows

package fileacltest

import (
	"io/fs"

	"github.com/segurata/segurata/internal/fileacl"
)

func notPrivate(path string, _ fs.FileInfo) string {
	ok, err := fileacl.HasPrivateDescriptor(path)
	switch {
	case err != nil:
		return err.Error()
	case !ok:
		s, _ := fileacl.Fingerprint(path)
		return "descriptor " + s
	}
	return ""
}
