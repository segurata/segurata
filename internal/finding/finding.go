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

// Remediation says how to fix a finding. Action names a built-in remediation (such as
// "macos.firewall.enable") that `securizame remediate` can apply; it is empty when the fix is
// manual. Automatable is derived from Action by Fill.
type Remediation struct {
	Summary     string `json:"summary"`
	URL         string `json:"url,omitempty"`
	Action      string `json:"action,omitempty"`
	Automatable bool   `json:"automatable"`
}

// Finding is one thing worth looking at. Evidence must never hold a secret value: use Redact.
type Finding struct {
	Type        string         `json:"type"` // always "finding"
	ID          string         `json:"id"`
	Connector   string         `json:"connector"`
	Instance    string         `json:"instance,omitempty"` // config label, for several accounts of one provider
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
	Accepted    *Acceptance    `json:"accepted,omitempty"` // set by the core from the accepted-risks file
}

// Acceptance records that the owner keeps this risk on purpose. An expired one no longer hides
// the finding.
type Acceptance struct {
	Reason     string    `json:"reason"`
	AcceptedAt time.Time `json:"accepted_at"`
	Until      string    `json:"until,omitempty"` // YYYY-MM-DD, last day it applies
	Expired    bool      `json:"expired,omitempty"`
}

// Hidden reports whether an acceptance in force keeps the finding out of summaries and lists.
func (f Finding) Hidden() bool { return f.Accepted != nil && !f.Accepted.Expired }

// DisplayTitle is the title as summaries print it: an expired acceptance says so.
func (f Finding) DisplayTitle() string {
	if f.Accepted != nil && f.Accepted.Expired {
		return f.Title + " (acceptance expired)"
	}
	return f.Title
}

// HiddenNote is the line printed under a list that left out accepted findings, or "" for none.
func HiddenNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d accepted findings hidden; see securizame accept --list", n)
}

// Fill sets the fields a connector should not have to compute: type, stable id, observation time
// and whether the remediation is automatable.
func (f *Finding) Fill(now time.Time) {
	f.Type = "finding"
	f.Remediation.Automatable = f.Remediation.Action != ""
	if f.ID == "" {
		parts := []string{f.Connector, f.Account, f.Resource.Type, f.Resource.ID}
		if f.Instance != "" {
			parts = append([]string{f.Instance}, parts...)
		}
		f.ID = StableID(parts...)
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
	Instance  string `json:"instance,omitempty"`
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
