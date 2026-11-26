package secretrisk

import (
	"encoding/json"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/finding"
)

// Evidence is what a local-secrets finding carries. It never holds a secret value: at most a
// redacted hint and an HMAC fingerprint only this machine's key can reproduce.
type Evidence struct {
	attribution.Claims

	Source      string `json:"source"`              // scan | gitleaks | name | ssh
	Kind        string `json:"kind"`                // config | repo | transcript | history | log
	Type        string `json:"type"`                // a catalog key, or a gitleaks rule id
	Redacted    string `json:"redacted"`            // Redact's format: "sk_live_…a1b2(107)"
	Path        string `json:"path"`                // ~-relative
	Line        int    `json:"line,omitempty"`      // 0 when the whole file is the secret
	Mode        string `json:"mode,omitempty"`      // octal permissions for other accounts, "" for git history
	FileMode    string `json:"file_mode,omitempty"` // the file's own mode, when parent folders close it
	Tracked     bool   `json:"tracked"`             // in a git-tracked file or in git history
	Remote      bool   `json:"remote,omitempty"`
	Bucket      string `json:"bucket"` // 0-git | 1-readable | 2-trail | 3-local | ok
	Fingerprint string `json:"fingerprint,omitempty"`
	Fix         string `json:"fix"` // docs/secrets.md#anchor
	Note        string `json:"note,omitempty"`
	Count       int    `json:"count"`
	Repo        string `json:"repo,omitempty"`   // gitleaks: repository
	Commit      string `json:"commit,omitempty"` // gitleaks: first commit seen
	Date        string `json:"date,omitempty"`   // gitleaks: date of that commit
	Public      bool   `json:"public,omitempty"` // anon or expired JWT, expired STS key, public OAuth client
	Encrypted   bool   `json:"encrypted,omitempty"`
	InDataDump  bool   `json:"in_data_dump,omitempty"`
	Origin      string `json:"origin,omitempty"` // Origin*, "" when unknown or not committed
	// Reused marks a copy in someone else's repository whose value is also in one of the owner's
	// own files: it is the owner's secret, so it counts.
	Reused bool `json:"reused,omitempty"`
	// Sample marks a value that reads like test data ("test", "fake", "1234"); it makes the copy
	// noise only in a test, example or documentation path.
	Sample   bool      `json:"sample,omitempty"`
	Liveness *Liveness `json:"liveness,omitempty"`
	// Pair is the fingerprint of the other half of an AWS key pair, set only by the liveness check.
	Pair string `json:"pair,omitempty"`
}

// Map is the evidence as a finding carries it.
func (ev Evidence) Map() map[string]any {
	var m map[string]any
	raw, _ := json.Marshal(ev)
	_ = json.Unmarshal(raw, &m)
	return m
}

// EvidenceOf reads a secret finding's evidence back; ok is false without a fingerprint.
func EvidenceOf(f finding.Finding) (Evidence, bool) {
	var ev Evidence
	raw, err := json.Marshal(f.Evidence)
	if err != nil || json.Unmarshal(raw, &ev) != nil || ev.Fingerprint == "" {
		return Evidence{}, false
	}
	return ev, true
}
