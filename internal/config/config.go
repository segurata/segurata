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

	"github.com/segurata/segurata/internal/attribution"
)

type ConnectorConfig struct {
	Config  map[string]any    `json:"config,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"` // key -> reference (env:, keychain:, op://)
	// RemediationSecrets are write credentials (key -> reference) that only `segurata remediate
	// --apply` resolves, after the owner confirmed a plan. Inventory never resolves them, so the
	// inventory keys can stay read-only.
	RemediationSecrets map[string]string `json:"remediation_secrets,omitempty"`
	// Expected are the statuses other than ok this instance reports on purpose (see Expect).
	Expected []Expected `json:"expected,omitempty"`
}

// Instance is one configured account of a connector. A config key "openrouter" gives the unnamed
// instance; "openrouter:personal" gives the instance labelled "personal", so one connector can
// inspect several accounts of the same provider.
type Instance struct {
	Label string
	ConnectorConfig
}

type Config struct {
	CDPURL     string                     `json:"cdp_url"`
	Connectors map[string]ConnectorConfig `json:"connectors"`
	// Owned are the owner's accounts, projects, workspaces, GitHub owners and emails that the
	// connectors cannot discover (an old AWS account no profile reaches): attribution counts a
	// secret naming one of them as the owner's. See internal/attribution.
	Owned attribution.Owned `json:"owned,omitempty"`
}

// DefaultPath is ~/.config/segurata/config.json on every OS, like most CLIs, unless
// SEGURATA_CONFIG says otherwise.
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
	raw, err := os.ReadFile(path)
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

// Instances returns the configured instances of a connector sorted by label, or one unnamed,
// empty instance when the config does not mention it.
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

// DefaultOutDir is where inventories write their runs when --out is not given: $SEGURATA_OUT, or
// out/ in StateDir. It never depends on the directory segurata is run from.
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
