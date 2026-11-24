package config

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// Accounts are the accounts a connector instance is limited to (connectors.<key>.config.accounts),
// and whether the config sets that list at all: without one, every account is inspected.
func (c Config) Accounts(key string) ([]string, bool) {
	raw, ok := c.Connectors[key].Config["accounts"].([]any)
	if !ok {
		return nil, false
	}
	var out []string
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out, true
}

// SetAccounts writes accounts as connectors.<key>.config.accounts in the config file at path and
// reports whether that changed the file, rewritten as editFile says; the backup's name is
// returned.
func SetAccounts(file, key string, accounts []string, now time.Time) (bool, string, error) {
	if len(accounts) == 0 {
		return false, "", fmt.Errorf("connectors.%s.config.accounts: an empty list would leave nothing to inspect", key)
	}
	return editFile(file, now, func(raw []byte) ([]byte, bool, error) {
		return editInstance(raw, key, func(inst *object) (bool, error) {
			var cfg object
			if err := inst.decode("config", &cfg); err != nil {
				return false, err
			}
			if v, ok := cfg.get("accounts"); ok {
				var have []string
				if json.Unmarshal(v, &have) == nil && slices.Equal(have, accounts) {
					return false, nil
				}
			}
			if err := cfg.encode("accounts", accounts); err != nil {
				return false, err
			}
			return true, inst.encode("config", cfg)
		})
	})
}
