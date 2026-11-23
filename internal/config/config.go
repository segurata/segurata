// Package config loads ~/.config/securizame/config.json. A missing file means defaults.
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type ConnectorConfig struct {
	Config  map[string]any    `json:"config,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"` // key -> reference (env:, keychain:, op://)
}

type Config struct {
	CDPURL     string                     `json:"cdp_url"`
	Connectors map[string]ConnectorConfig `json:"connectors"`
}

// DefaultPath is ~/.config/securizame/config.json on every OS, like most CLIs, unless
// SECURIZAME_CONFIG says otherwise.
func DefaultPath() string {
	if p := os.Getenv("SECURIZAME_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "securizame.json"
	}
	return filepath.Join(home, ".config", "securizame", "config.json")
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
	if env := os.Getenv("SECURIZAME_CDP"); env != "" {
		cfg.CDPURL = env
	}
	return cfg, nil
}
