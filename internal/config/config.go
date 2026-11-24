// Package config loads ~/.config/segurata/config.json. A missing file means defaults.
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ConnectorConfig struct {
	Config  map[string]any    `json:"config,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"` // key -> reference (env:, keychain:, op://)
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
