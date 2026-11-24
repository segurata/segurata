package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindGcloud(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	home := t.TempDir()
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
	if _, err := FindGcloud("", home, "workspace"); err == nil || !strings.Contains(err.Error(), "the workspace connector config") {
		t.Fatalf("missing gcloud must name the connector's config: %v", err)
	}
	machineSpecific := filepath.Join(home, "src", "utils", "google-cloud-sdk", "bin", "gcloud")
	put(machineSpecific)
	if p, _ := FindGcloud("", home, "gcp"); p == machineSpecific {
		t.Fatalf("a machine-specific folder must not be searched: %q", p)
	}
	installed := filepath.Join(home, "google-cloud-sdk", "bin", "gcloud")
	put(installed)
	if p, err := FindGcloud("", home, "gcp"); err != nil || p != installed {
		t.Fatalf("standard install folder: %q %v", p, err)
	}
}
