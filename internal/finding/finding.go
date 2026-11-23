// Package finding defines the records every connector emits: findings and per-account statuses.
// See docs/arquitectura.md, "Modelo de hallazgo".
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type Kind string

const (
	KindGrant      Kind = "grant"      // third-party access to an account
	KindCredential Kind = "credential" // key, token, service account
	KindSetting    Kind = "setting"    // security configuration
	KindSpend      Kind = "spend"      // spend, budget or limit
	KindExposure   Kind = "exposure"   // secret left in plain sight
)

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Rank orders severities so reports can sort worst first; unknown values rank lowest.
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	}
	return 0
}

type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Remediation struct {
	Summary     string `json:"summary"`
	URL         string `json:"url,omitempty"`
	Automatable bool   `json:"automatable"`
}

// Finding is one thing worth looking at. Evidence must never hold a secret value: use Redact.
type Finding struct {
	Type        string         `json:"type"` // always "finding"
	ID          string         `json:"id"`
	Connector   string         `json:"connector"`
	Account     string         `json:"account"`
	Resource    Resource       `json:"resource"`
	Kind        Kind           `json:"kind"`
	Severity    Severity       `json:"severity"`
	Title       string         `json:"title"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	CreatedAt   *time.Time     `json:"created_at"`
	LastUsedAt  *time.Time     `json:"last_used_at"` // nil when the provider does not say
	Remediation Remediation    `json:"remediation"`
	ObservedAt  time.Time      `json:"observed_at"`
}

// Fill sets the fields a connector should not have to compute: type, stable id and observation time.
func (f *Finding) Fill(now time.Time) {
	f.Type = "finding"
	if f.ID == "" {
		f.ID = StableID(f.Connector, f.Account, f.Resource.Type, f.Resource.ID)
	}
	if f.ObservedAt.IsZero() {
		f.ObservedAt = now.UTC()
	}
}

// StableID is the same across runs for the same resource, so runs can be diffed.
func StableID(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

type State string

const (
	StateOK                 State = "ok"
	StateReauth             State = "reauth"
	StateSignedOut          State = "signedout"
	StateMissingCredentials State = "missing_credentials"
	StateUnsupported        State = "unsupported"
	StateError              State = "error"
)

// Status says whether an account could be inspected, and why not.
type Status struct {
	Type      string `json:"type"` // always "status"
	Connector string `json:"connector"`
	Account   string `json:"account"`
	State     State  `json:"state"`
	Detail    string `json:"detail,omitempty"`
}

// Redact keeps a short prefix and the length, enough to recognise a key without leaking it.
func Redact(secret string) string {
	const keep = 6
	if len(secret) <= keep*2 {
		return fmt.Sprintf("…(%d)", len(secret))
	}
	return fmt.Sprintf("%s…(%d)", secret[:keep], len(secret))
}
