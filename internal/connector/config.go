package connector

import "fmt"

// Readers of Request.Config, decoded from JSON. An absent or null key gives the default; a value of
// another type is an error naming the connector and the key.

// Strings reads a list of non-empty strings.
func Strings(cfg map[string]any, name, key string) ([]string, error) {
	v, ok := cfg[key]
	if !ok || v == nil {
		return nil, nil
	}
	bad := fmt.Errorf("%s config: %q must be a list of strings", name, key)
	items, ok := v.([]any)
	if !ok {
		return nil, bad
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		if !ok || s == "" {
			return nil, bad
		}
		out = append(out, s)
	}
	return out, nil
}

// LenientStrings keeps the non-empty strings of a list and drops anything else; ok is whether the
// value is a list at all. Only for settings whose mistakes are tolerated on purpose.
func LenientStrings(cfg map[string]any, key string) (out []string, ok bool) {
	items, ok := cfg[key].([]any)
	for _, it := range items {
		if s, _ := it.(string); s != "" {
			out = append(out, s)
		}
	}
	return out, ok
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
func Bool(cfg map[string]any, name, key string) (bool, error) {
	v, ok := cfg[key]
	if !ok || v == nil {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s config: %q must be true or false", name, key)
	}
	return b, nil
}
