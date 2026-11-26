package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/segurata/segurata/connectors/internal/userdirs"
)

// FindGcloud tries the configured path, PATH, then the SDK's install folders, which
// non-interactive shells often lack in PATH. connector names the config section an error points to.
func FindGcloud(configured, home, connector string) (string, error) {
	return findGcloud(configured, connector, gcloudInstallPaths(userdirs.Current(home)))
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

// gcloudInstallPaths: the interactive installer, the Linux packages and Homebrew; on Windows the
// installer's folder for one user and for all users, where gcloud is a batch file.
func gcloudInstallPaths(e userdirs.Env) []string {
	if e.GOOS == "windows" {
		sdk := filepath.Join("Google", "Cloud SDK", "google-cloud-sdk", "bin", "gcloud.cmd")
		out := []string{filepath.Join(e.LocalAppData(), sdk)}
		for _, d := range e.ProgramFiles() {
			out = append(out, filepath.Join(d, sdk))
		}
		return out
	}
	return []string{
		filepath.Join(e.Home, "google-cloud-sdk", "bin", "gcloud"),
		"/usr/lib/google-cloud-sdk/bin/gcloud",
		"/opt/homebrew/share/google-cloud-sdk/bin/gcloud",
		"/usr/local/share/google-cloud-sdk/bin/gcloud",
	}
}
