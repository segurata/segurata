// Package finding defines the records every connector emits: findings and per-account statuses.
// See docs/architecture.md, "Finding model".
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

// Valid reports whether s is one of the five severities, spelled exactly.
func (s Severity) Valid() bool { return s == SevInfo || s.Rank() > 0 }

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
// "macos.firewall.enable") that `segurata remediate` can apply; it is empty when the fix is
// manual. Automatable is derived from Action by Fill.
//
// Group, when set, names the findings one plan fixes together: `segurata remediate` gathers every
// finding of the same connector instance with the same Action and Group, plans them as one and
// lists them as one line. Severity, when set, is the severity of what Action fixes when that is
// less than the finding's own (a hardening step on a finding graded for something else); the list
// ranks the action by it.
type Remediation struct {
	Summary     string   `json:"summary"`
	URL         string   `json:"url,omitempty"`
	Action      string   `json:"action,omitempty"`
	Group       string   `json:"group,omitempty"`
	Severity    Severity `json:"severity,omitempty"`
	Automatable bool     `json:"automatable"`
}

// ActionSeverity is the severity `segurata remediate --list` ranks the finding's action by.
func (f Finding) ActionSeverity() Severity {
	if f.Remediation.Severity != "" {
		return f.Remediation.Severity
	}
	return f.Severity
}

// Finding is one thing worth looking at. Evidence must never hold a secret value: use Redact.
type Finding struct {
	Type        string         `json:"type"` // always "finding"
	ID          string         `json:"id"`
	Connector   string         `json:"connector"`
	Instance    string         `json:"instance,omitempty"` // config label, for several accounts of one provider
	Account     string         `json:"account"`
	Scope       string         `json:"scope,omitempty"` // part of the account inspected as a unit, when narrower; see ScopeOf
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
	return fmt.Sprintf("%d accepted findings hidden; see segurata accept --list", n)
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
	StateNoScope            State = "noscope"    // signed in, but the credential lacks a permission
	StateUnverified         State = "unverified" // signed in, but the reader was never checked against a real page
	StateMissingCredentials State = "missing_credentials"
	StateUnsupported        State = "unsupported"
	StateError              State = "error"
	// StateExpected is a status other than ok that the owner's config says to expect (see
	// Status.Expected): it opens no setup item, and its scope still counts as not inspected.
	StateExpected State = "expected"
)

// Status says whether an account could be inspected, and why not. Scope, when set, narrows it to
// one part of the account (a project, a repository): a status other than ok then leaves only that
// scope uninspected instead of the whole account. See RunEnd.
type Status struct {
	Type      string `json:"type"` // always "status"
	Connector string `json:"connector"`
	Instance  string `json:"instance,omitempty"`
	Account   string `json:"account"`
	Scope     string `json:"scope,omitempty"`
	State     State  `json:"state"`
	Detail    string `json:"detail,omitempty"`
	// Expected is the reason of the config rule that made the state expected; Was is the state
	// the connector reported. Both are set by the core, never by a connector.
	Expected string `json:"expected,omitempty"`
	Was      State  `json:"was,omitempty"`
}

// IdleAfter is how long a credential can go unused before it is worth a look; a credential used
// more recently is in use.
const IdleAfter = 90 * 24 * time.Hour

// Redact keeps a short prefix and the length, enough to recognise a key without leaking it.
func Redact(secret string) string {
	const keep = 6
	if len(secret) <= keep*2 {
		return fmt.Sprintf("…(%d)", len(secret))
	}
	return fmt.Sprintf("%s…(%d)", secret[:keep], len(secret))
}
