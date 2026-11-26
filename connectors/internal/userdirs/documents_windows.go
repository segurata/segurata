package userdirs

import (
	"path/filepath"

	"github.com/segurata/segurata/internal/winsys"
)

// DocumentsFolder is the user's Documents folder as the shell resolves it, redirected or not, and
// ~/Documents when the shell cannot say.
func DocumentsFolder(home string) string {
	if p, err := winsys.KnownFolderPath(&winsys.FolderIDDocuments); err == nil && p != "" {
		return p
	}
	return filepath.Join(home, "Documents")
}
