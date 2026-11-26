//go:build unix

package doctor

import (
	"fmt"
	"io/fs"

	"github.com/segurata/segurata/internal/connector"
)

// newDirAccess is how segurata creates its folders.
const newDirAccess = "mode 0700"

func filePrivacy(path string, st fs.FileInfo) privacy {
	if mode := st.Mode().Perm(); mode != 0o600 {
		return privacy{detail: fmt.Sprintf("mode %#o, want 0600", mode), fix: connector.MakePrivateCommand("unix", path, false)}
	}
	return privacy{ok: true, detail: "mode 0600"}
}

func dirPrivacy(dir string, st fs.FileInfo) privacy {
	if mode := st.Mode().Perm(); mode != 0o700 {
		return privacy{detail: fmt.Sprintf("mode %#o, want 0700", mode), fix: connector.MakePrivateCommand("unix", dir, true)}
	}
	return privacy{ok: true, detail: newDirAccess}
}
