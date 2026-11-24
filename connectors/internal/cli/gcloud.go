package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

// FindGcloud resolves the gcloud CLI: the configured path, then PATH, then the SDK's standard
// install folders. connector names the config section the error message points to.
func FindGcloud(configured, home, connector string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	if p, err := exec.LookPath("gcloud"); err == nil {
		return p, nil
	}
	for _, p := range gcloudInstallPaths(home) {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("gcloud CLI not found in PATH or the standard install folders: set gcloud_path in the " + connector + " connector config")
}

// gcloudInstallPaths are where the interactive installer, the Linux packages and Homebrew put
// gcloud, for when PATH lacks it (non-interactive shells often do).
func gcloudInstallPaths(home string) []string {
	return []string{
		filepath.Join(home, "google-cloud-sdk", "bin", "gcloud"),
		"/usr/lib/google-cloud-sdk/bin/gcloud",
		"/opt/homebrew/share/google-cloud-sdk/bin/gcloud",
		"/usr/local/share/google-cloud-sdk/bin/gcloud",
	}
}
