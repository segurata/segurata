package awsfiles

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProviderOf(t *testing.T) {
	r2ID := "ab2665aaaabbbbccccddddeeeeffff00"
	cases := []struct {
		name string
		key  string
		cfg  Config
		want Provider
	}{
		{"aws long-lived", "AKIAIOSFODNN7EXAMPLE", Config{Region: "eu-west-1"}, AWS},
		{"aws temporary", "ASIAIOSFODNN7EXAMPLE", Config{}, AWS},
		{"sso profile without key", "", Config{}, AWS},
		{"r2 by key id shape", r2ID, Config{}, R2},
		{"r2 by region auto", "SOMEKEY", Config{Region: "auto"}, R2},
		{"r2 by endpoint", "AKIAIOSFODNN7EXAMPLE", Config{Endpoint: "https://0123.r2.cloudflarestorage.com"}, R2},
		{"other s3-compatible", "0025a1b2c3d4e5f60000000001", Config{Endpoint: "https://s3.eu-central-003.backblazeb2.com"}, S3Compatible},
	}
	for _, tc := range cases {
		if got := ProviderOf(Profile{Name: "p", KeyID: tc.key}, tc.cfg); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// Issuers reads the files the AWS CLI reads, honouring its environment overrides; a missing
// config file leaves the key id shape to decide, and a missing credentials file names no profile.
func TestIssuers(t *testing.T) {
	dir := t.TempDir()
	cred, conf := filepath.Join(dir, "credentials"), filepath.Join(dir, "config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", cred)
	t.Setenv("AWS_CONFIG_FILE", conf)
	if got := Issuers(); got != nil {
		t.Fatalf("no credentials file: %v", got)
	}
	creds := "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = x\n# comment\n[bucket]\naws_access_key_id = SOMEKEY\naws_secret_access_key = y\n"
	if err := os.WriteFile(cred, []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Issuers(); got["default"] != AWS || got["bucket"] != S3Compatible {
		t.Fatalf("without config: %v", got)
	}
	if err := os.WriteFile(conf, []byte("[default]\nregion = eu-west-1\n[profile bucket]\nregion = auto\n[sso-session x]\nregion = auto\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Issuers(); got["default"] != AWS || got["bucket"] != R2 || len(got) != 2 {
		t.Fatalf("with config: %v", got)
	}
	if cfg, err := ReadConfig(filepath.Join(dir, "absent")); err != nil || len(cfg) != 0 {
		t.Fatalf("missing config: %v %v", cfg, err)
	}
}
