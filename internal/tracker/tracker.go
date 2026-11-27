// Package tracker keeps segurata's local record of what to do: one item per thing a person would
// act on, with its status, priority, linked findings, next step and history. Runs and findings are
// ephemeral; items are not.
//
// The file is ~/.segurata/tracker.json (or $SEGURATA_HOME), mode 0600, written atomically with the
// previous version kept as tracker.json.bak. It never holds a secret value: rotate items carry
// redacted hints and HMAC fingerprints only. See docs/architecture.md, "Tracker".
package tracker

import (
	"crypto/sha256"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// schemaVersion is bumped whenever tracker.json gains a field, even one an older file simply
// lacks: the bump keeps an older binary from loading a file with values it does not know.
const schemaVersion = 8

// Kind says what sort of action an item asks for.
type Kind string

const (
	KindFix    Kind = "fix"    // change a setting, remove a file, revoke a grant
	KindRotate Kind = "rotate" // rotate one secret (one fingerprint)
	KindDecide Kind = "decide" // answer a question before anything else can happen
	KindSetup  Kind = "setup"  // let segurata see: sign in, add a credential, grant a scope
	KindReview Kind = "review" // look at a list and keep or remove each entry
)

var kinds = []Kind{KindFix, KindRotate, KindDecide, KindSetup, KindReview}

// Status is where an item stands.
type Status string

const (
	Open       Status = "open"
	InProgress Status = "in_progress"
	Done       Status = "done"
	Accepted   Status = "accepted" // a risk kept on purpose
	Ignored    Status = "ignored"  // not a real problem, said by the owner
	Snoozed    Status = "snoozed"  // open again after snoozed_until
	// Reclassified is closed by segurata: a corrected rule rates every current sighting as noise.
	Reclassified Status = "reclassified"
	// Expected is a setup item whose statuses the config expects (connectors.<x>.expected).
	Expected Status = "expected"
	// Merged is closed by segurata: another item (merged_into) owns the same problem.
	Merged Status = "merged"
)

var statuses = []Status{Open, InProgress, Done, Accepted, Ignored, Snoozed, Reclassified, Expected, Merged}

// Who does the next step.
type Who string

const (
	You      Who = "you"
	Segurata Who = "segurata" // a segurata command does it, after your confirmation
	Agent    Who = "agent"
)

// History event categories; Event.Action keeps the precise verb, which the rotation rules read.
const (
	EvFound        = "found"
	EvSeen         = "seen"
	EvStatus       = "status"
	EvNote         = "note"
	EvVerified     = "verified"
	EvReopened     = "reopened"
	EvDecided      = "decided"
	EvPriority     = "priority"
	EvReclassified = "reclassified"
	EvMerged       = "merged"
	EvOwner        = "owner"
)

// Event is one line of an item's history.
type Event struct {
	At     time.Time `json:"at"`
	Event  string    `json:"event"`
	Action string    `json:"action,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// FindingRef links a finding, or a setup item's connector status, to an item. Gone means the
// latest run of its connector instance no longer reports it.
type FindingRef struct {
	ID        string           `json:"id"`
	Connector string           `json:"connector"`
	Instance  string           `json:"instance,omitempty"`
	Account   string           `json:"account,omitempty"`
	Scope     string           `json:"scope,omitempty"` // "" on refs recorded before scopes existed
	Title     string           `json:"title"`
	Severity  finding.Severity `json:"severity,omitempty"`
	LastSeen  time.Time        `json:"last_seen"`
	Gone      bool             `json:"gone,omitempty"`
	// Expected is the reason of the config rule that expects a setup item's status.
	Expected string `json:"expected,omitempty"`
	// Path, Repo and Project locate the finding for decision rules.
	Path        string        `json:"path,omitempty"`
	Repo        string        `json:"repo,omitempty"`
	Project     string        `json:"project,omitempty"`
	Type        string        `json:"type,omitempty"`
	Resource    string        `json:"resource,omitempty"`
	Blast       finding.Blast `json:"blast,omitempty"`
	Unconfirmed bool          `json:"unconfirmed,omitempty"`
	// Match and Confidence say how a connector's credential matched a rotate item's secret
	// (correlate.go).
	Match      string    `json:"match,omitempty"`
	Confidence string    `json:"confidence,omitempty"`
	Key        *KeyFacts `json:"key,omitempty"`
}

// KeyFacts are what a provider reports about the key a rotate item's secret is.
type KeyFacts struct {
	Name          string     `json:"name,omitempty"`
	LastUsed      *time.Time `json:"last_used,omitempty"`
	SpendMonthUSD *float64   `json:"spend_month_usd,omitempty"`
}

// Label is the connector instance as the command line names it: name or name:label.
func (r FindingRef) Label() string { return finding.Label(r.Connector, r.Instance) }

// Next is the next step: who takes it, what it is, and the command or page that does it.
type Next struct {
	Who     Who    `json:"who"`
	Action  string `json:"action"`
	Command string `json:"command,omitempty"`
	URL     string `json:"url,omitempty"`
}

// Decision is the question a decide item asks and, once answered, the answer.
type Decision struct {
	Question   string         `json:"question"`
	Options    []string       `json:"options,omitempty"`
	Answer     string         `json:"answer,omitempty"`
	AnsweredAt *time.Time     `json:"answered_at,omitempty"`
	Effects    []OptionEffect `json:"effects,omitempty"`
}

// Acceptance records why a risk is kept and until when. It outlives its last day, so findings show
// "(acceptance expired)" until the owner acts.
type Acceptance struct {
	Reason     string    `json:"reason"`
	Until      string    `json:"until,omitempty"` // YYYY-MM-DD, last day it applies
	AcceptedAt time.Time `json:"accepted_at"`
}

// Override is a priority set by hand, with the reason.
type Override struct {
	Priority secretrisk.Priority `json:"priority"`
	Reason   string              `json:"reason"`
	At       time.Time           `json:"at"`
}

// Item is one thing to do.
type Item struct {
	ID               string              `json:"id"`  // T-0001, never reused
	Key              string              `json:"key"` // what makes two findings the same item
	Kind             Kind                `json:"kind"`
	Theme            string              `json:"theme"`
	Title            string              `json:"title"`
	Status           Status              `json:"status"`
	Priority         secretrisk.Priority `json:"priority,omitempty"` // computed; "" for noise
	PriorityOverride *Override           `json:"priority_override,omitempty"`
	Severity         finding.Severity    `json:"severity,omitempty"` // worst linked finding
	Findings         []FindingRef        `json:"findings,omitempty"`
	// Possible are credential findings whose hint fits this secret and another: never merged.
	Possible     []FindingRef `json:"possible,omitempty"`
	Fingerprint  string       `json:"fingerprint,omitempty"` // rotate items
	Secret       *Secret      `json:"secret,omitempty"`      // rotate items
	Next         *Next        `json:"next,omitempty"`
	Decision     *Decision    `json:"decision,omitempty"`
	Accepted     *Acceptance  `json:"accepted,omitempty"`
	SnoozedUntil string       `json:"snoozed_until,omitempty"`
	MergedInto   string       `json:"merged_into,omitempty"`
	StatusAt     time.Time    `json:"status_at"`
	VerifiedAt   *time.Time   `json:"verified_at,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	History      []Event      `json:"history"`
}

// Theme groups items for the briefing.
type Theme = finding.Theme

// Tracker is the whole file.
type Tracker struct {
	SchemaVersion int        `json:"schema_version"`
	NextID        int        `json:"next_id"`
	LastSyncAt    *time.Time `json:"last_sync_at,omitempty"`
	LastStatusAt  *time.Time `json:"last_status_at,omitempty"`
	// Sources is the newest run folded in per connector instance; an older run is never folded
	// over it, so syncing two output folders cannot make items flap.
	Sources map[string]time.Time `json:"sources,omitempty"`
	Themes  []Theme              `json:"themes"`
	Items   []*Item              `json:"items"`
	Rules   []Rule               `json:"rules,omitempty"`
	// Owned are the owner's accounts discovered in runs, kept across syncs so a sync that reads no
	// aws run still knows the aws account.
	Owned *attribution.Owned `json:"owned,omitempty"`
	Runs  map[string]RunInfo `json:"runs,omitempty"`

	// read is the digest of the file last loaded or saved, so Save can refuse a file changed since.
	read *[sha256.Size]byte
}

// RunInfo is what a sync keeps of a connector instance's newest run.
type RunInfo struct {
	At           time.Time       `json:"at"`
	Finished     bool            `json:"finished"` // it has run_end
	Complete     bool            `json:"complete"` // finished, nothing skipped, no connector error
	Error        string          `json:"error,omitempty"`
	Expected     int             `json:"expected,omitempty"`   // scopes left out by expected statuses
	Unreadable   int             `json:"unreadable,omitempty"` // paths left out as finding.UnreadableReason
	Skipped      []string        `json:"skipped,omitempty"`    // the first few, "scope: reason"
	SkippedCount int             `json:"skipped_count,omitempty"`
	Theme        string          `json:"theme,omitempty"`
	Areas        map[string]bool `json:"areas,omitempty"` // plan area: audited by this run
}

// legacy reports whether the run was written before connectors declared themes and areas.
func (i RunInfo) legacy() bool { return i.Theme == "" }
