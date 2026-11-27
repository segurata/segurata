// Package config loads ~/.config/segurata/config.json. A missing file means defaults.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/cfgkey"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
)

type ConnectorConfig struct {
	Config  map[string]any    `json:"config,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"` // key -> reference (env:, keychain:, op://)
	// RemediationSecrets are write credentials only `segurata remediate --apply` resolves, so the
	// inventory keys can stay read-only.
	RemediationSecrets map[string]string `json:"remediation_secrets,omitempty"`
	Expected           []Expected        `json:"expected,omitempty"`
	// Timeout is a Go duration ("3h"); empty is the connector's own default, else one hour.
	Timeout string `json:"timeout,omitempty"`
}

// Instance is one configured account of a connector: key "openrouter" is the unnamed instance,
// "openrouter:personal" the one labelled "personal".
type Instance struct {
	Label string
	ConnectorConfig
}

type Config struct {
	CDPURL     string                     `json:"cdp_url"`
	Connectors map[string]ConnectorConfig `json:"connectors"`
	// Owned are the owner's accounts the connectors cannot discover (internal/attribution).
	Owned attribution.Owned `json:"owned,omitempty"`
	// KeepRunsDays and BrowserStaleDays: 0 is the default, negative is never.
	KeepRunsDays     int `json:"keep_runs_days,omitempty"`
	BrowserStaleDays int `json:"browser_stale_days,omitempty"`
}

const (
	defaultKeepRunsDays     = 30
	defaultBrowserStaleDays = 7
)

// RunRetention is how old a run file may grow before a scheduled run prunes it, 0 for never.
func (c Config) RunRetention() time.Duration { return days(c.KeepRunsDays, defaultKeepRunsDays) }

// BrowserStaleAfter is how long scheduled runs may skip the browser connectors before the owner is
// notified, 0 for never.
func (c Config) BrowserStaleAfter() time.Duration {
	return days(c.BrowserStaleDays, defaultBrowserStaleDays)
}

// days is n days, def for 0, and 0 (never) for a negative n.
func days(n, def int) time.Duration {
	switch {
	case n < 0:
		return 0
	case n == 0:
		n = def
	}
	return time.Duration(n) * 24 * time.Hour
}

// DefaultPath is $SEGURATA_CONFIG, else ~/.config/segurata/config.json on every OS.
func DefaultPath() string {
	if p := os.Getenv("SEGURATA_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "segurata.json"
	}
	return filepath.Join(home, ".config", "segurata", "config.json")
}

func Load(path string) (Config, error) {
	cfg := Config{CDPURL: "http://127.0.0.1:9222", Connectors: map[string]ConnectorConfig{}}
	raw, err := statefile.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return cfg, err
	default:
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return cfg, err
		}
		if cfg.Connectors == nil {
			cfg.Connectors = map[string]ConnectorConfig{}
		}
		if err := cfg.validate(); err != nil {
			return cfg, fmt.Errorf("%s: %w", path, err)
		}
	}
	if env := os.Getenv("SEGURATA_CDP"); env != "" {
		cfg.CDPURL = env
	}
	return cfg, nil
}

// OwnedAccounts is config `owned` plus the GitHub owners every local-secrets instance names in
// owned_owners, which judge whose a repository is at scan time and so must at attribution too.
// A malformed owned_owners adds nothing: local-secrets reports it when it runs.
func (c Config) OwnedAccounts() attribution.Owned {
	var gh []string
	for _, in := range c.Instances(secretrisk.ConnectorName) {
		if names, err := cfgkey.Strings(in.Config, secretrisk.ConnectorName, "owned_owners"); err == nil {
			gh = append(gh, names...)
		}
	}
	return c.Owned.Merge(attribution.Owned{GitHub: gh})
}

// RunTimeout is the instance's timeout, 0 for none; Load validated it.
func (cc ConnectorConfig) RunTimeout() time.Duration {
	d, _ := time.ParseDuration(cc.Timeout)
	return d
}

// Instances are a connector's configured instances by label, or one empty unnamed instance.
func (c Config) Instances(name string) []Instance {
	var out []Instance
	for key, cc := range c.Connectors {
		switch {
		case key == name:
			out = append(out, Instance{ConnectorConfig: cc})
		case strings.HasPrefix(key, name+":"):
			out = append(out, Instance{Label: strings.TrimPrefix(key, name+":"), ConnectorConfig: cc})
		}
	}
	if len(out) == 0 {
		return []Instance{{}}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// StateDir is $SEGURATA_HOME, or ~/.segurata: the tracker, its generated views and the runs.
func StateDir() (string, error) {
	if d := os.Getenv("SEGURATA_HOME"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".segurata"), nil
}

// DefaultOutDir is $SEGURATA_OUT, else out/ in StateDir, never relative to the working directory.
func DefaultOutDir() string {
	if d := os.Getenv("SEGURATA_OUT"); d != "" {
		return d
	}
	dir, err := StateDir()
	if err != nil {
		return "out"
	}
	return filepath.Join(dir, "out")
}
