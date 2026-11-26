package statefile

import (
	"os"

	"github.com/segurata/segurata/internal/fileacl"
)

func replaceFile(src, dst string) error {
	if err := fileacl.CopyAccess(dst, src); err != nil {
		return err
	}
	return os.Rename(src, dst)
}
