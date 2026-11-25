package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultOutDirIgnoresTheWorkingDirectory(t *testing.T) {
	t.Setenv("SEGURATA_OUT", "")
	t.Setenv("SEGURATA_HOME", "/tmp/seg-home")
	if got := DefaultOutDir(); got != "/tmp/seg-home/out" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("SEGURATA_OUT", "/tmp/elsewhere")
	if got := DefaultOutDir(); got != "/tmp/elsewhere" {
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

// An instance label names the run file, out/<date>/<name>-<label>.jsonl: one that could leave
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

func TestRunRetention(t *testing.T) {
	for body, want := range map[string]time.Duration{
		`{}`:                     30 * 24 * time.Hour,
		`{"keep_runs_days": 7}`:  7 * 24 * time.Hour,
		`{"keep_runs_days": -1}`: 0,
	} {
		cfg, err := loadBody(t, body)
		if err != nil || cfg.RunRetention() != want {
			t.Errorf("%s: %s, %v", body, cfg.RunRetention(), err)
		}
	}
}

func TestBrowserStaleAfter(t *testing.T) {
	for body, want := range map[string]time.Duration{
		`{}`:                         7 * 24 * time.Hour,
		`{"browser_stale_days": 3}`:  3 * 24 * time.Hour,
		`{"browser_stale_days": -1}`: 0,
	} {
		cfg, err := loadBody(t, body)
		if err != nil || cfg.BrowserStaleAfter() != want {
			t.Errorf("%s: %s, %v", body, cfg.BrowserStaleAfter(), err)
		}
	}
}
