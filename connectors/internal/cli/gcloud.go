package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

// FindGcloud tries the configured path, PATH, then the SDK's install folders, which
// non-interactive shells often lack in PATH. connector names the config section an error points to.
func FindGcloud(configured, home, connector string) (string, error) {
	return findGcloud(configured, connector, gcloudInstallPaths(home))
}

func findGcloud(configured, connector string, installs []string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	if p, err := exec.LookPath("gcloud"); err == nil {
		return p, nil
	}
	for _, p := range installs {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("gcloud CLI not found in PATH or the standard install folders: set gcloud_path in the " + connector + " connector config")
}

// gcloudInstallPaths: the interactive installer, the Linux packages and Homebrew.
func gcloudInstallPaths(home string) []string {
	return []string{
		filepath.Join(home, "google-cloud-sdk", "bin", "gcloud"),
		"/usr/lib/google-cloud-sdk/bin/gcloud",
		"/opt/homebrew/share/google-cloud-sdk/bin/gcloud",
		"/usr/local/share/google-cloud-sdk/bin/gcloud",
	}
}
