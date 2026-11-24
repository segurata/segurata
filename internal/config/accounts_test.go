package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSetAccounts(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	file := filepath.Join(t.TempDir(), "config.json")
	before := `{"cdp_url": "http://127.0.0.1:9222", "connectors": {"gcp": {"config": {"gcloud_path": "/x/gcloud"}, "expected": [{"state": "error", "reason": "r"}]}, "aws": {}}}`
	if err := os.WriteFile(file, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, backup, err := SetAccounts(file, "gcp", []string{"me@x.com", "work@y.com"}, now)
	if err != nil || !changed || backup == "" {
		t.Fatalf("%v %q %v", changed, backup, err)
	}
	if b, _ := os.ReadFile(backup); string(b) != before {
		t.Error("backup is not the previous file")
	}
	raw, _ := os.ReadFile(file)
	got := string(raw)
	// Keys keep their order; the list lands inside config, after the keys already there.
	for _, in := range [][2]string{{`"cdp_url"`, `"connectors"`}, {`"gcp"`, `"aws"`}, {`"gcloud_path"`, `"accounts"`}, {`"config"`, `"expected"`}} {
		if strings.Index(got, in[0]) > strings.Index(got, in[1]) {
			t.Errorf("%s moved after %s:\n%s", in[0], in[1], got)
		}
	}
	cfg, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if list, set := cfg.Accounts("gcp"); !set || !slices.Equal(list, []string{"me@x.com", "work@y.com"}) {
		t.Errorf("accounts %v %v", list, set)
	}
	if _, set := cfg.Accounts("aws"); set {
		t.Error("aws has no list")
	}
	if changed, _, err := SetAccounts(file, "gcp", []string{"me@x.com", "work@y.com"}, now); changed || err != nil {
		t.Errorf("an equal list rewrote the file: %v %v", changed, err)
	}
	if _, _, err := SetAccounts(file, "gcp", nil, now); err == nil {
		t.Error("an empty list was written")
	}
	// A new instance key and a missing file both work.
	other := filepath.Join(t.TempDir(), "new.json")
	if changed, backup, err := SetAccounts(other, "google-personal", []string{"me@x.com"}, now); !changed || backup != "" || err != nil {
		t.Errorf("new file: %v %q %v", changed, backup, err)
	}
	if st, err := os.Stat(other); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("mode: %v", err)
	}
}
