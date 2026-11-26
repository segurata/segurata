// Package userdirs is where the CLIs and browsers segurata inspects keep a user's data, one rule
// per tool and OS, the way each tool resolves it. The environment and OS are passed in, so the
// rules are tested for every OS anywhere.
package userdirs

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
)

// Env is the user and machine the rules resolve against.
type Env struct {
	GOOS   string
	Home   string
	Getenv func(string) string // nil reads no variable
	// Documents is the Documents folder, which Windows may redirect (OneDrive); "" is ~/Documents.
	Documents string
}

// Current is this process's OS and environment, with the home folder given.
func Current(home string) Env {
	return Env{GOOS: runtime.GOOS, Home: home, Getenv: os.Getenv, Documents: DocumentsFolder(home)}
}

func (e Env) env(k string) string {
	if e.Getenv == nil {
		return ""
	}
	return e.Getenv(k)
}

// AppData is the roaming application data folder on Windows (%APPDATA%).
func (e Env) AppData() string { return e.windowsDir("APPDATA", "Roaming") }

// LocalAppData is the local application data folder on Windows (%LOCALAPPDATA%), where Chromium
// browsers keep their profiles.
func (e Env) LocalAppData() string { return e.windowsDir("LOCALAPPDATA", "Local") }

// ProgramFiles are the Windows program folders, 64-bit first, as the environment names them.
func (e Env) ProgramFiles() []string {
	var out []string
	for _, k := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
		if d := e.env(k); d != "" && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

// windowsDir falls back to the folder's default place in the profile when the variable is unset.
func (e Env) windowsDir(key, sub string) string {
	if d := e.env(key); d != "" {
		return d
	}
	return filepath.Join(e.Home, "AppData", sub)
}

// Gcloud is the gcloud configuration folder: $CLOUDSDK_CONFIG, else %APPDATA%\gcloud on Windows
// and ~/.config/gcloud elsewhere (gcloud does not read XDG_CONFIG_HOME).
func (e Env) Gcloud() string {
	if d := e.env("CLOUDSDK_CONFIG"); d != "" {
		return d
	}
	return e.defaultGcloud()
}

// GcloudFolders are the folders that may hold gcloud's credentials: Gcloud and, when
// $CLOUDSDK_CONFIG moves it, the default folder too, where an earlier login left its tokens.
func (e Env) GcloudFolders() []string {
	if d, def := e.Gcloud(), e.defaultGcloud(); d != def {
		return []string{d, def}
	}
	return []string{e.Gcloud()}
}

func (e Env) defaultGcloud() string {
	if e.GOOS == "windows" {
		return filepath.Join(e.AppData(), "gcloud")
	}
	return filepath.Join(e.Home, ".config", "gcloud")
}

// GitHubCLI is gh's configuration folder, which holds hosts.yml: $GH_CONFIG_DIR, else
// $XDG_CONFIG_HOME/gh, else %APPDATA%\GitHub CLI on Windows and ~/.config/gh elsewhere.
func (e Env) GitHubCLI() string {
	if d := e.env("GH_CONFIG_DIR"); d != "" {
		return d
	}
	if d := e.env("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "gh")
	}
	if e.GOOS == "windows" {
		return filepath.Join(e.AppData(), "GitHub CLI")
	}
	return filepath.Join(e.Home, ".config", "gh")
}

// PSReadLine is the folder of PowerShell's command histories, one file per host:
// %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine on Windows, and elsewhere
// $XDG_DATA_HOME/powershell/PSReadLine, by default under ~/.local/share.
func (e Env) PSReadLine() string {
	if e.GOOS == "windows" {
		return filepath.Join(e.AppData(), "Microsoft", "Windows", "PowerShell", "PSReadLine")
	}
	data := e.env("XDG_DATA_HOME")
	if data == "" {
		data = filepath.Join(e.Home, ".local", "share")
	}
	return filepath.Join(data, "powershell", "PSReadLine")
}

// PowerShellProfiles are the folders of the current user's PowerShell profiles on Windows, for
// PowerShell 7 and Windows PowerShell. Elsewhere PowerShell keeps them in ~/.config/powershell.
func (e Env) PowerShellProfiles() []string {
	if e.GOOS != "windows" {
		return nil
	}
	docs := e.Documents
	if docs == "" {
		docs = filepath.Join(e.Home, "Documents")
	}
	return []string{filepath.Join(docs, "PowerShell"), filepath.Join(docs, "WindowsPowerShell")}
}
