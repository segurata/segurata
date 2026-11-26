package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/segurata/segurata/connectors/internal/userdirs"
)

func TestFindGcloud(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	home := t.TempDir()
	env := userdirs.Env{GOOS: runtime.GOOS, Home: home, Getenv: func(k string) string {
		return map[string]string{"LOCALAPPDATA": filepath.Join(home, "AppData", "Local")}[k]
	}}
	installs := gcloudInstallPaths(env)[:1]
	put := func(p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if p, err := FindGcloud("/configured/gcloud", home, "gcp"); err != nil || p != "/configured/gcloud" {
		t.Fatalf("configured gcloud_path must win: %q %v", p, err)
	}
	if _, err := findGcloud("", "workspace", installs); err == nil || !strings.Contains(err.Error(), "the workspace connector config") {
		t.Fatalf("missing gcloud must name the connector's config: %v", err)
	}
	machineSpecific := filepath.Join(home, "src", "utils", "google-cloud-sdk", "bin", "gcloud")
	put(machineSpecific)
	if p, err := findGcloud("", "gcp", installs); err == nil {
		t.Fatalf("a machine-specific folder was searched: %q", p)
	}
	put(installs[0])
	if p, err := findGcloud("", "gcp", gcloudInstallPaths(env)); err != nil || p != installs[0] {
		t.Fatalf("standard install folder: %q %v", p, err)
	}
}

func TestGcloudInstallFolders(t *testing.T) {
	home := filepath.Join("home", "ana")
	unix := gcloudInstallPaths(userdirs.Env{GOOS: "darwin", Home: home})
	if unix[0] != filepath.Join(home, "google-cloud-sdk", "bin", "gcloud") || !slices.Contains(unix, "/opt/homebrew/share/google-cloud-sdk/bin/gcloud") {
		t.Errorf("unix: %v", unix)
	}
	vars := map[string]string{"LOCALAPPDATA": "L", "ProgramFiles": "P", "ProgramFiles(x86)": "Q"}
	win := gcloudInstallPaths(userdirs.Env{GOOS: "windows", Home: home, Getenv: func(k string) string { return vars[k] }})
	sdk := filepath.Join("Google", "Cloud SDK", "google-cloud-sdk", "bin", "gcloud.cmd")
	if want := []string{filepath.Join("L", sdk), filepath.Join("P", sdk), filepath.Join("Q", sdk)}; !slices.Equal(win, want) {
		t.Errorf("windows: %v, want %v", win, want)
	}
}
