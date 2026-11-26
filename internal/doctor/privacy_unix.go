//go:build unix

package doctor

import (
	"fmt"
	"io/fs"
)

// newDirAccess is how segurata creates its folders.
const newDirAccess = "mode 0700"

func filePrivacy(path string, st fs.FileInfo) privacy {
	if mode := st.Mode().Perm(); mode != 0o600 {
		return privacy{detail: fmt.Sprintf("mode %#o, want 0600", mode), fix: "chmod 600 " + path}
	}
	return privacy{ok: true, detail: "mode 0600"}
}

func dirPrivacy(dir string, st fs.FileInfo) privacy {
	if mode := st.Mode().Perm(); mode != 0o700 {
		return privacy{detail: fmt.Sprintf("mode %#o, want 0700", mode), fix: "chmod 700 " + dir}
	}
	return privacy{ok: true, detail: newDirAccess}
}
