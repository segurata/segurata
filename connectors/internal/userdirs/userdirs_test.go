package userdirs

import (
	"path/filepath"
	"strings"
	"testing"
)

func env(goos string, vars map[string]string) Env {
	return Env{GOOS: goos, Home: filepath.Join("home", "ana"), Getenv: func(k string) string { return vars[k] }}
}

func TestToolFolders(t *testing.T) {
	home := filepath.Join("home", "ana")
	roaming := filepath.Join("R")
	for _, c := range []struct {
		name string
		got  string
		want string
	}{
		{"gcloud unix", env("linux", nil).Gcloud(), filepath.Join(home, ".config", "gcloud")},
		{"gcloud ignores XDG", env("linux", map[string]string{"XDG_CONFIG_HOME": "X"}).Gcloud(), filepath.Join(home, ".config", "gcloud")},
		{"gcloud override", env("windows", map[string]string{"CLOUDSDK_CONFIG": "C", "APPDATA": roaming}).Gcloud(), "C"},
		{"gcloud windows", env("windows", map[string]string{"APPDATA": roaming}).Gcloud(), filepath.Join(roaming, "gcloud")},
		{"gcloud windows default", env("windows", nil).Gcloud(), filepath.Join(home, "AppData", "Roaming", "gcloud")},
		{"gcloud folders", strings.Join(env("linux", nil).GcloudFolders(), ","), filepath.Join(home, ".config", "gcloud")},
		{"gcloud folders moved", strings.Join(env("linux", map[string]string{"CLOUDSDK_CONFIG": "C"}).GcloudFolders(), ","), "C," + filepath.Join(home, ".config", "gcloud")},
		{"gcloud folders moved to the default", strings.Join(env("windows", map[string]string{"CLOUDSDK_CONFIG": filepath.Join("R", "gcloud"), "APPDATA": roaming}).GcloudFolders(), ","), filepath.Join(roaming, "gcloud")},
		{"gcloud folders windows", strings.Join(env("windows", map[string]string{"CLOUDSDK_CONFIG": "C", "APPDATA": roaming}).GcloudFolders(), ","), "C," + filepath.Join(roaming, "gcloud")},
		{"gh unix", env("darwin", nil).GitHubCLI(), filepath.Join(home, ".config", "gh")},
		{"gh XDG", env("linux", map[string]string{"XDG_CONFIG_HOME": "X"}).GitHubCLI(), filepath.Join("X", "gh")},
		{"gh override", env("linux", map[string]string{"GH_CONFIG_DIR": "G", "XDG_CONFIG_HOME": "X"}).GitHubCLI(), "G"},
		{"gh windows", env("windows", map[string]string{"APPDATA": roaming}).GitHubCLI(), filepath.Join(roaming, "GitHub CLI")},
		{"local app data", env("windows", map[string]string{"LOCALAPPDATA": "L"}).LocalAppData(), "L"},
		{"local app data default", env("windows", nil).LocalAppData(), filepath.Join(home, "AppData", "Local")},
		{"program files", strings.Join(env("windows", map[string]string{"ProgramFiles": "P", "ProgramFiles(x86)": "Q"}).ProgramFiles(), ","), "P,Q"},
		{"program files on a 32-bit system", strings.Join(env("windows", map[string]string{"ProgramFiles": "P", "ProgramFiles(x86)": "P"}).ProgramFiles(), ","), "P"},
		{"no environment", Env{GOOS: "linux", Home: home}.Gcloud(), filepath.Join(home, ".config", "gcloud")},
		{"psreadline windows", env("windows", map[string]string{"APPDATA": roaming}).PSReadLine(), filepath.Join(roaming, "Microsoft", "Windows", "PowerShell", "PSReadLine")},
		{"psreadline unix", env("darwin", nil).PSReadLine(), filepath.Join(home, ".local", "share", "powershell", "PSReadLine")},
		{"psreadline XDG", env("linux", map[string]string{"XDG_DATA_HOME": "D"}).PSReadLine(), filepath.Join("D", "powershell", "PSReadLine")},
		{"profiles windows default", strings.Join(env("windows", nil).PowerShellProfiles(), ","),
			filepath.Join(home, "Documents", "PowerShell") + "," + filepath.Join(home, "Documents", "WindowsPowerShell")},
		{"profiles in a redirected Documents", strings.Join(Env{GOOS: "windows", Home: home, Documents: "O"}.PowerShellProfiles(), ","),
			filepath.Join("O", "PowerShell") + "," + filepath.Join("O", "WindowsPowerShell")},
		{"profiles unix", strings.Join(env("linux", nil).PowerShellProfiles(), ","), ""},
	} {
		if c.got != c.want {
			t.Errorf("%s: %s, want %s", c.name, c.got, c.want)
		}
	}
}
