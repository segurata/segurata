// Package tracker keeps segurata's single local record of what to do: one item per thing a
// person would act on (a secret to rotate, five GitHub orgs that do not require 2FA, a data dump in
// git, a connector that needs a fresh sign-in, an open decision), with its status, priority, the
// findings it links, the next action and its history. Runs and findings are ephemeral; items are
// not. It absorbs the former rotation ledger (rotate items) and accepted-risks file (accepted
// items).
//
// The file is ~/.segurata/tracker.json (SEGURATA_HOME names another directory), mode 0600 in a
// 0700 directory, written atomically with the previous good version kept as tracker.json.bak. It
// never holds a secret value: rotate items carry redacted hints and HMAC fingerprints only, and
// findings carry none. See docs/architecture.md, "Tracker".
package tracker

import (
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// SchemaVersion is the tracker.json format this binary writes.
const SchemaVersion = 4

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
	Ignored    Status = "ignored"  // not a real problem (false positive, test fixture), said by the owner
	Snoozed    Status = "snoozed"  // open again after snoozed_until
	// Reclassified is closed by segurata itself: a corrected rule now rates every current sighting
	// of the secret as noise. A later sighting that is not noise opens it again.
	Reclassified Status = "reclassified"
	// Expected is a setup item whose statuses the owner's config says to expect
	// (connectors.<x>.expected); removing the rule opens it again.
	Expected Status = "expected"
	// Merged is closed by segurata: another item owns the same problem (merged_into), as a
	// connector's plain-text credential is the same secret as a rotate item's. It opens again when
	// the two stop matching.
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

// History event categories. Event.Action keeps the precise verb (done, auto-reopen,
// snooze-expired, history-only, ...), which the rotation rules read back.
const (
	EvFound    = "found"
	EvSeen     = "seen"
	EvStatus   = "status"
	EvNote     = "note"
	EvVerified = "verified"
	EvReopened = "reopened"
	EvDecided  = "decided"
	EvPriority = "priority"
	// EvReclassified closes an item segurata now rates as noise (status reclassified).
	EvReclassified = "reclassified"
	// EvMerged closes an item whose problem another item owns (status merged).
	EvMerged = "merged"
)

// Event is one line of an item's history.
type Event struct {
	At     time.Time `json:"at"`
	Event  string    `json:"event"`
	Action string    `json:"action,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// FindingRef links a finding (or, for setup items, a connector status) to an item. Gone means the
// latest run of its connector instance no longer reports it.
type FindingRef struct {
	ID        string `json:"id"`
	Connector string `json:"connector"`
	Instance  string `json:"instance,omitempty"`
	Account   string `json:"account,omitempty"`
	// Scope is finding.ScopeOf the finding; "" on refs recorded before scopes existed.
	Scope    string           `json:"scope,omitempty"`
	Title    string           `json:"title"`
	Severity finding.Severity `json:"severity,omitempty"`
	LastSeen time.Time        `json:"last_seen"`
	Gone     bool             `json:"gone,omitempty"`
	// Expected is, on a setup item's status ref, the reason of the config rule that expects it.
	Expected string `json:"expected,omitempty"`
	// Where the finding is, for decision rules (see Rule): a local path (a repository, a file), a
	// GitHub repository (owner/name) or a GCP project.
	Path    string `json:"path,omitempty"`
	Repo    string `json:"repo,omitempty"`
	Project string `json:"project,omitempty"`
	// Type and Resource are the finding's resource type and id, which ranking reads (an org's 2FA
	// check, a macOS backup setting).
	Type     string `json:"type,omitempty"`
	Resource string `json:"resource,omitempty"`
	// Match, on a rotate item's ref, says how the connector's credential was matched with the
	// secret: fingerprint, hint (redacted hint and service) or path (the file holding it).
	Match string `json:"match,omitempty"`
}

// Label is the connector instance as the command line names it: name or name:label.
func (r FindingRef) Label() string { return label(r.Connector, r.Instance) }

func label(connector, instance string) string {
	if instance == "" {
		return connector
	}
	return connector + ":" + instance
}

// Next is the next step: who takes it, what it is, and the command or page that does it.
type Next struct {
	Who     Who    `json:"who"`
	Action  string `json:"action"`
	Command string `json:"command,omitempty"`
	URL     string `json:"url,omitempty"`
}

// Decision is the question a decide item asks and, once answered, the answer.
type Decision struct {
	Question   string     `json:"question"`
	Options    []string   `json:"options,omitempty"`
	Answer     string     `json:"answer,omitempty"`
	AnsweredAt *time.Time `json:"answered_at,omitempty"`
	// Effects are the rules answering an option adds (track add --option "yes=ignore:path:~/src/old").
	Effects []OptionEffect `json:"effects,omitempty"`
}

// Acceptance records why a risk is kept and until when. It stays on the item after it expires, so
// the findings show "(acceptance expired)" until the owner acts.
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
	ID               string              `json:"id"`  // T-0001, stable, never reused
	Key              string              `json:"key"` // grouping key: what makes two findings the same item
	Kind             Kind                `json:"kind"`
	Theme            string              `json:"theme"`
	Title            string              `json:"title"`
	Status           Status              `json:"status"`
	Priority         secretrisk.Priority `json:"priority,omitempty"` // computed; "" for noise
	PriorityOverride *Override           `json:"priority_override,omitempty"`
	Severity         finding.Severity    `json:"severity,omitempty"` // worst linked finding
	Findings         []FindingRef        `json:"findings,omitempty"`
	Fingerprint      string              `json:"fingerprint,omitempty"` // rotate items
	Secret           *Secret             `json:"secret,omitempty"`      // rotate items
	Next             *Next               `json:"next,omitempty"`
	Decision         *Decision           `json:"decision,omitempty"`
	Accepted         *Acceptance         `json:"accepted,omitempty"`
	SnoozedUntil     string              `json:"snoozed_until,omitempty"`
	MergedInto       string              `json:"merged_into,omitempty"` // status merged: the item that owns the problem
	StatusAt         time.Time           `json:"status_at"`             // last status change
	VerifiedAt       *time.Time          `json:"verified_at,omitempty"`
	CreatedAt        time.Time           `json:"created_at"`
	UpdatedAt        time.Time           `json:"updated_at"`
	History          []Event             `json:"history"`
}

// Theme groups items for the briefing.
type Theme struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// Tracker is the whole file.
type Tracker struct {
	SchemaVersion int        `json:"schema_version"`
	NextID        int        `json:"next_id"`
	LastSyncAt    *time.Time `json:"last_sync_at,omitempty"`
	LastStatusAt  *time.Time `json:"last_status_at,omitempty"`
	// Sources is, per connector instance, the newest run folded in; an older run is never folded
	// over a newer one, so syncing two output folders cannot make items flap.
	Sources map[string]time.Time `json:"sources,omitempty"`
	Themes  []Theme              `json:"themes"`
	Items   []*Item              `json:"items"`
	// Rules are the effects of answered decisions, applied at every sync.
	Rules []Rule `json:"rules,omitempty"`
	// Owned are the owner's accounts, projects, workspaces, GitHub owners and emails discovered in
	// connector runs, kept across syncs (a sync that reads no aws run still knows the aws account).
	// Config `owned` adds to them at every sync; see "Attribution" in docs/architecture.md.
	Owned *attribution.Owned `json:"owned,omitempty"`
}
