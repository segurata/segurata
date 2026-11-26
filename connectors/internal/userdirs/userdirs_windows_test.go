//go:build windows

package userdirs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On a real Windows session the variables the rules read are set and inside the profile.
func TestCurrentWindowsFolders(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	e := Current(home)
	for _, d := range []string{e.AppData(), e.LocalAppData()} {
		if !filepath.IsAbs(d) || !strings.HasPrefix(strings.ToLower(d), strings.ToLower(home)) {
			t.Errorf("%s is not an absolute folder in the profile %s", d, home)
		}
	}
	if got, want := e.Gcloud(), filepath.Join(os.Getenv("APPDATA"), "gcloud"); os.Getenv("CLOUDSDK_CONFIG") == "" && got != want {
		t.Errorf("gcloud: %s, want %s", got, want)
	}
}

// The Documents folder comes from the shell, so a folder redirected to OneDrive is found.
func TestDocumentsFolderIsTheShells(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	d := DocumentsFolder(home)
	if st, err := os.Stat(d); err != nil || !st.IsDir() || !filepath.IsAbs(d) {
		t.Errorf("Documents %s: %v", d, err)
	}
}
