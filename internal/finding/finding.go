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

func (s Severity) Valid() bool { return s == SevInfo || s.Rank() > 0 }

// Rank orders severities worst last; unknown values rank lowest.
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

// Pick words a severity: high for high and critical, medium for medium, low for the rest.
func (s Severity) Pick(high, medium, low string) string {
	switch {
	case s.Rank() >= SevHigh.Rank():
		return high
	case s == SevMedium:
		return medium
	}
	return low
}

// Blast is what a finding puts at stake beyond its severity, which ranks the tracker's "Do next";
// an unlisted value is none.
type Blast string

const (
	BlastLogin        Blast = "login"            // the account is the login of money and cloud accounts
	BlastOrgAccess    Blast = "org-access"       // one stolen password opens every repository of an org
	BlastDevice       Blast = "device"           // a lost, stolen or encrypted Mac takes every file
	BlastMailAndFiles Blast = "mail-and-files"   // apps that can read or change an account's mail and files
	BlastBrowser      Blast = "browser"          // any local program can drive the browser's sessions
	BlastPersonalData Blast = "personal-data"    // other people's data, with breach duties
	BlastAllRepos     Blast = "all-repositories" // write access to every repository of the account
	BlastOrgWrite     Blast = "org-write"        // every member of an org can change every repository
	BlastPosts        Blast = "posts"            // at worst, posts as the account
	BlastMoney        Blast = "money"            // spend, bounded by the card on file
	BlastLeftovers    Blast = "leftovers"        // leftovers, nothing running
)

type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Remediation says how to fix a finding. Action names what `segurata remediate` can apply ("" is a
// manual fix). Group joins the findings of one instance and Action that one plan fixes. Severity is
// what Action fixes, when less than the finding's own.
type Remediation struct {
	Summary     string   `json:"summary"`
	URL         string   `json:"url,omitempty"`
	Action      string   `json:"action,omitempty"`
	Group       string   `json:"group,omitempty"`
	Severity    Severity `json:"severity,omitempty"`
	Automatable bool     `json:"automatable"`
}

func (f Finding) ActionSeverity() Severity {
	if f.Remediation.Severity != "" {
		return f.Remediation.Severity
	}
	return f.Severity
}

// Finding is one thing worth looking at. Evidence must never hold a secret value: use Redact.
type Finding struct {
	Type      string         `json:"type"` // always "finding"
	ID        string         `json:"id"`
	Connector string         `json:"connector"`
	Instance  string         `json:"instance,omitempty"` // config label, for several accounts of one provider
	Account   string         `json:"account"`
	Scope     string         `json:"scope,omitempty"` // part of the account inspected as a unit, when narrower; see ScopeOf
	Resource  Resource       `json:"resource"`
	Kind      Kind           `json:"kind"`
	Severity  Severity       `json:"severity"`
	Title     string         `json:"title"`
	Evidence  map[string]any `json:"evidence,omitempty"`
	Blast     Blast          `json:"blast,omitempty"` // what it puts at stake beyond its severity
	// Unconfirmed: the connector is not sure the problem is real; ranking discounts it.
	Unconfirmed bool        `json:"unconfirmed,omitempty"`
	Track       *Track      `json:"track,omitempty"`
	CreatedAt   *time.Time  `json:"created_at"`
	LastUsedAt  *time.Time  `json:"last_used_at"` // nil when the provider does not say
	Remediation Remediation `json:"remediation"`
	ObservedAt  time.Time   `json:"observed_at"`
	Accepted    *Acceptance `json:"accepted,omitempty"` // set by the core from the accepted-risks file
}

// Acceptance records that the owner keeps this risk on purpose until it expires.
type Acceptance struct {
	Reason     string    `json:"reason"`
	AcceptedAt time.Time `json:"accepted_at"`
	Until      string    `json:"until,omitempty"` // YYYY-MM-DD, last day it applies
	Expired    bool      `json:"expired,omitempty"`
}

// Hidden reports whether an acceptance in force keeps the finding out of lists.
func (f Finding) Hidden() bool { return f.Accepted != nil && !f.Accepted.Expired }

func (f Finding) DisplayTitle() string {
	if f.Accepted != nil && f.Accepted.Expired {
		return f.Title + " (acceptance expired)"
	}
	return f.Title
}

// Label spells a connector instance as the config key does: "name" or "name:label".
func Label(connector, instance string) string {
	if instance == "" {
		return connector
	}
	return connector + ":" + instance
}

func (f Finding) Selector() string { return Label(f.Connector, f.Instance) }

// HiddenNote is the line under a list that left out n accepted findings, or "".
func HiddenNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d accepted findings hidden; see segurata accept --list", n)
}

// Fill sets type, stable id, observation time and Automatable.
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

// StableID is the same across runs for the same parts.
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
	// StateExpected is a state the owner's config expects: no setup item, scope still uninspected.
	StateExpected State = "expected"
)

// Status says whether an account, or with Scope one part of it, could be inspected, and why not.
type Status struct {
	Type      string `json:"type"` // always "status"
	Connector string `json:"connector"`
	Instance  string `json:"instance,omitempty"`
	Account   string `json:"account"`
	Scope     string `json:"scope,omitempty"`
	State     State  `json:"state"`
	Detail    string `json:"detail,omitempty"`
	// Expected (the rule's reason) and Was (the reported state) are set by the core only.
	Expected string `json:"expected,omitempty"`
	Was      State  `json:"was,omitempty"`
}

// IdleAfter is how long a credential can go unused before it is worth a look.
const IdleAfter = 90 * 24 * time.Hour

// Redact keeps a short prefix and the length, enough to recognise a key without leaking it.
func Redact(secret string) string {
	const keep = 6
	if len(secret) <= keep*2 {
		return fmt.Sprintf("…(%d)", len(secret))
	}
	return fmt.Sprintf("%s…(%d)", secret[:keep], len(secret))
}
