package secretrisk

import (
	"encoding/json"

	"github.com/segurata/segurata/internal/finding"
)

// Map is the evidence as a finding carries it.
func (ev Evidence) Map() map[string]any {
	var m map[string]any
	raw, _ := json.Marshal(ev)
	_ = json.Unmarshal(raw, &m)
	return m
}

// EvidenceOf reads a secret finding's evidence back; ok is false when the finding carries none
// (no fingerprint).
func EvidenceOf(f finding.Finding) (Evidence, bool) {
	var ev Evidence
	raw, err := json.Marshal(f.Evidence)
	if err != nil || json.Unmarshal(raw, &ev) != nil || ev.Fingerprint == "" {
		return Evidence{}, false
	}
	return ev, true
}
