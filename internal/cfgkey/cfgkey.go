// Package cfgkey reads the keys of a connector's config, decoded from JSON. An absent or null key
// gives the default; a value of another type, an empty string or a number out of range is an error
// naming the connector and the key, never a silent fallback to the default.
package cfgkey

import (
	"fmt"
	"strings"
)

// Strings reads a list of non-empty strings; an empty list is a list.
func Strings(cfg map[string]any, name, key string) ([]string, error) {
	v, ok := cfg[key]
	if !ok || v == nil {
		return nil, nil
	}
	bad := fmt.Errorf("%s config: %q must be a list of non-empty strings", name, key)
	items, ok := v.([]any)
	if !ok {
		return nil, bad
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return nil, bad
		}
		out = append(out, s)
	}
	return out, nil
}

// Selection reads a list that narrows what is inspected: absent is everything, so an empty list,
// which would inspect nothing, is an error.
func Selection(cfg map[string]any, name, key string) ([]string, error) {
	out, err := Strings(cfg, name, key)
	if err == nil && out != nil && len(out) == 0 {
		return nil, fmt.Errorf("%s config: %q must name at least one entry; leave it out for all", name, key)
	}
	return out, err
}

// String reads a string that is not empty or blank.
func String(cfg map[string]any, name, key string) (string, error) {
	v, ok := cfg[key]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("%s config: %q must be a non-empty string", name, key)
	}
	return s, nil
}

// PositiveInt reads a whole number above 0.
func PositiveInt(cfg map[string]any, name, key string, def int) (int, error) {
	v, ok := cfg[key]
	if !ok || v == nil {
		return def, nil
	}
	n, ok := v.(float64)
	if !ok || n < 1 || n != float64(int(n)) {
		return def, fmt.Errorf("%s config: %q must be a whole number above 0", name, key)
	}
	return int(n), nil
}

// Bool reads true or false.
func Bool(cfg map[string]any, name, key string, def bool) (bool, error) {
	v, ok := cfg[key]
	if !ok || v == nil {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return def, fmt.Errorf("%s config: %q must be true or false", name, key)
	}
	return b, nil
}
