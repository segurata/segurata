package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultOutDirIgnoresTheWorkingDirectory(t *testing.T) {
	t.Setenv("SEGURATA_OUT", "")
	home := t.TempDir()
	t.Setenv("SEGURATA_HOME", home)
	if got := DefaultOutDir(); got != filepath.Join(home, "out") {
		t.Fatalf("got %q", got)
	}
	out := t.TempDir()
	t.Setenv("SEGURATA_OUT", out)
	if got := DefaultOutDir(); got != out {
		t.Fatalf("SEGURATA_OUT: got %q", got)
	}
}

func loadBody(t *testing.T, body string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

// An instance label becomes part of the run file name: one that could leave
// that directory or clash with the separator is refused.
func TestLoadRejectsInstanceLabelsThatAreNotFileNameSafe(t *testing.T) {
	for _, key := range []string{"aws:", "aws:../x", "aws:a/b", "aws:a b", "aws:a:b"} {
		if _, err := loadBody(t, `{"connectors": {"`+key+`": {}}}`); err == nil {
			t.Errorf("%q: loaded", key)
		}
	}
	if _, err := loadBody(t, `{"connectors": {"aws:Work_1.prod-eu": {}, "aws": {}}}`); err != nil {
		t.Errorf("good labels refused: %v", err)
	}
}

func TestLoadRejectsATimeoutThatIsNotAPositiveDuration(t *testing.T) {
	for _, v := range []string{"soon", "0s", "-1h", "3600"} {
		if _, err := loadBody(t, `{"connectors": {"gcp": {"timeout": "`+v+`"}}}`); err == nil {
			t.Errorf("%q: loaded", v)
		}
	}
	cfg, err := loadBody(t, `{"connectors": {"gcp": {"timeout": "2h30m"}}}`)
	if err != nil || cfg.Instances("gcp")[0].RunTimeout() != 150*time.Minute {
		t.Fatalf("good timeout: %v %v", cfg.Instances("gcp"), err)
	}
}

func TestRetentionAndStalenessDays(t *testing.T) {
	day := 24 * time.Hour
	for _, c := range []struct {
		body             string
		retention, stale time.Duration
	}{
		{`{}`, 30 * day, 7 * day},
		{`{"keep_runs_days": 7, "browser_stale_days": 3}`, 7 * day, 3 * day},
		{`{"keep_runs_days": -1, "browser_stale_days": -1}`, 0, 0},
	} {
		cfg, err := loadBody(t, c.body)
		if err != nil || cfg.RunRetention() != c.retention || cfg.BrowserStaleAfter() != c.stale {
			t.Errorf("%s: retention %s, stale %s, %v", c.body, cfg.RunRetention(), cfg.BrowserStaleAfter(), err)
		}
	}
}

// A missing file is the defaults; SEGURATA_CDP and SEGURATA_CONFIG win over them.
func TestLoadDefaultsAndEnvironment(t *testing.T) {
	t.Setenv("SEGURATA_CDP", "")
	cfg, err := Load(filepath.Join(t.TempDir(), "none.json"))
	if err != nil || cfg.CDPURL != "http://127.0.0.1:9222" || cfg.Connectors == nil {
		t.Fatalf("missing file: %+v %v", cfg, err)
	}
	if cfg, err := loadBody(t, `{"connectors": null}`); err != nil || cfg.Connectors == nil {
		t.Fatalf("null connectors: %+v %v", cfg, err)
	}
	if _, err := loadBody(t, `{"connectors": [`); err == nil {
		t.Error("malformed JSON loaded")
	}
	t.Setenv("SEGURATA_CDP", "http://127.0.0.1:9333")
	if cfg, _ := loadBody(t, `{"cdp_url": "http://127.0.0.1:9444"}`); cfg.CDPURL != "http://127.0.0.1:9333" {
		t.Errorf("SEGURATA_CDP: %s", cfg.CDPURL)
	}
	t.Setenv("SEGURATA_CONFIG", "/tmp/seg.json")
	t.Setenv("SEGURATA_HOME", "/tmp/seg-home")
	if DefaultPath() != "/tmp/seg.json" {
		t.Errorf("SEGURATA_CONFIG: %s", DefaultPath())
	}
	if d, err := StateDir(); err != nil || d != "/tmp/seg-home" {
		t.Errorf("SEGURATA_HOME: %s %v", d, err)
	}
}

// Instances of a connector come sorted by label; a connector the config does not name has one
// empty unnamed instance, and a key that only starts with its name is another connector's.
func TestInstances(t *testing.T) {
	cfg := Config{Connectors: map[string]ConnectorConfig{"aws:work": {}, "aws": {Timeout: "1h"}, "aws-extra": {}, "aws:home": {}}}
	var labels []string
	for _, in := range cfg.Instances("aws") {
		labels = append(labels, in.Label)
	}
	if strings.Join(labels, ",") != ",home,work" || cfg.Instances("aws")[0].Timeout != "1h" {
		t.Errorf("aws instances %q", labels)
	}
	if got := cfg.Instances("gcp"); len(got) != 1 || got[0].Label != "" || got[0].Secrets != nil {
		t.Errorf("unconfigured connector: %+v", got)
	}
}
