package doctor

import (
	"io/fs"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/fileacl"
)

const newDirAccess = "private"

func filePrivacy(path string, _ fs.FileInfo) privacy {
	return aclPrivacy(path, false, connector.MakePrivateCommand("windows", path, false))
}

func dirPrivacy(dir string, _ fs.FileInfo) privacy {
	return aclPrivacy(dir, true, connector.MakePrivateCommand("windows", dir, true))
}

func aclPrivacy(path string, dir bool, fix string) privacy {
	exposure, err := fileacl.Exposure(path)
	if err != nil {
		return privacy{detail: err.Error(), fix: fix}
	}
	changeable := false
	if dir {
		if changeable, err = fileacl.ChangeableByOthers(path); err != nil {
			return privacy{detail: err.Error(), fix: fix}
		}
	}
	who, err := fileacl.Describe(path)
	if err != nil {
		return privacy{detail: err.Error(), fix: fix}
	}
	switch {
	case fileacl.Exposed(exposure):
		return privacy{detail: who, fix: fix}
	case changeable:
		return privacy{detail: "another account may add, delete or re-permission its entries", fix: fix}
	}
	return privacy{ok: true, detail: who}
}
