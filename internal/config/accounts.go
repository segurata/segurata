package config

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/segurata/segurata/internal/cfgkey"
)

// Accounts are connectors.<key>.config.accounts, and whether it is set: without it, every account
// is inspected. It is read as the connector reads it, so a list the connector refuses is an error.
func (c Config) Accounts(key string) ([]string, bool, error) {
	list, err := cfgkey.Selection(c.Connectors[key].Config, key, "accounts")
	return list, list != nil, err
}

// SetAccounts writes connectors.<key>.config.accounts through editFile.
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
