package tracker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"time"

	"github.com/segurata/segurata/internal/secretrisk"
)

// The files the tracker absorbed: the rotation ledger (rotations.json, version 1) and the
// accepted-risks file (accepted.json, version 1). Their formats are frozen here, for the one-time
// import.

type legacyLedger struct {
	Version int           `json:"version"`
	Items   []*legacyItem `json:"items"`
}

type legacyItem struct {
	ID               string              `json:"id"`
	Fingerprint      string              `json:"fingerprint"`
	Service          string              `json:"service"`
	Type             string              `json:"type"`
	Redacted         string              `json:"redacted"`
	Impact           string              `json:"impact"`
	Priority         secretrisk.Priority `json:"priority"`
	Reasons          []string            `json:"reasons"`
	Status           string              `json:"status"`
	SnoozedUntil     string              `json:"snoozed_until"`
	FirstSeen        time.Time           `json:"first_seen"`
	LastSeen         time.Time           `json:"last_seen"`
	Locations        []Location          `json:"locations"`
	UsedIn           []string            `json:"used_in"`
	RotateURL        string              `json:"rotate_url"`
	History          []legacyEvent       `json:"history"`
	RotatedLocations []string            `json:"rotated_locations"`
}

type legacyEvent struct {
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	Note   string    `json:"note"`
}

type legacyAccepted struct {
	Version int `json:"version"`
	Entries []struct {
		ID         string    `json:"id"`
		Connector  string    `json:"connector"`
		Title      string    `json:"title"`
		Reason     string    `json:"reason"`
		AcceptedAt time.Time `json:"accepted_at"`
		Until      string    `json:"until"`
	} `json:"entries"`
}

// MigrationReport counts what Migrate imported.
type MigrationReport struct{ Rotations, Accepted int }

var legacyStatus = map[string]Status{"open": Open, "rotated": Done, "snoozed": Snoozed, "ignored": Ignored}

// legacyEvents maps a ledger action to its history category; the action itself is kept.
var legacyEvents = map[string]string{
	actFound: EvFound, actDone: EvStatus, actSnooze: EvStatus, actIgnore: EvStatus, actWake: EvStatus,
	actReopen: EvReopened, actAutoReopen: EvReopened,
}

// Migrate builds a tracker from the old files ("" or a missing file means none): every rotation
// item becomes a rotate item with its locations, rotated locations, snooze and full history, and
// every accepted risk an accepted item linking its finding. Stored values are imported as they
// are, not recomputed, so priorities and reasons stay exactly what the ledger said.
func Migrate(ledgerPath, acceptedPath string, now time.Time) (*Tracker, MigrationReport, error) {
	t := New(now)
	var rep MigrationReport
	var l legacyLedger
	if ok, err := readLegacy(ledgerPath, &l); err != nil {
		return nil, rep, err
	} else if ok && l.Version > 1 {
		return nil, rep, fmt.Errorf("%s: ledger version %d is newer than this binary knows", ledgerPath, l.Version)
	}
	// Ids follow first sighting, so T-0001 is the oldest secret.
	sort.SliceStable(l.Items, func(i, j int) bool {
		if !l.Items[i].FirstSeen.Equal(l.Items[j].FirstSeen) {
			return l.Items[i].FirstSeen.Before(l.Items[j].FirstSeen)
		}
		return l.Items[i].ID < l.Items[j].ID
	})
	for _, old := range l.Items {
		if err := t.importRotation(old, now); err != nil {
			return nil, rep, fmt.Errorf("%s: item %s: %w", ledgerPath, old.ID, err)
		}
		rep.Rotations++
	}
	var a legacyAccepted
	if ok, err := readLegacy(acceptedPath, &a); err != nil {
		return nil, rep, err
	} else if ok && a.Version > 1 {
		return nil, rep, fmt.Errorf("%s: version %d is newer than this binary knows", acceptedPath, a.Version)
	}
	for _, e := range a.Entries {
		if t.ByKey(pinnedKey(e.ID)) != nil {
			return nil, rep, fmt.Errorf("%s: finding %s accepted twice", acceptedPath, e.ID)
		}
		it := t.newItem(KindReview, pinnedKey(e.ID), themeOf(e.Connector, ""), e.Title, e.AcceptedAt)
		it.Findings = []FindingRef{{ID: e.ID, Connector: e.Connector, Title: e.Title, LastSeen: e.AcceptedAt.UTC()}}
		it.Log(e.AcceptedAt, EvFound, actFound, "imported from accepted.json")
		it.Accepted = &Acceptance{Reason: e.Reason, Until: e.Until, AcceptedAt: e.AcceptedAt.UTC()}
		it.setStatus(e.AcceptedAt, Accepted, EvStatus, actAccept, acceptDetail(e.Reason, e.Until))
		it.Next = acceptedNext()
		rep.Accepted++
	}
	return t, rep, t.validate()
}

func readLegacy(path string, v any) (bool, error) {
	if path == "" {
		return false, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return true, nil
}

func (t *Tracker) importRotation(old *legacyItem, now time.Time) error {
	st, ok := legacyStatus[old.Status]
	if !ok {
		return fmt.Errorf("unknown status %q", old.Status)
	}
	if old.Fingerprint == "" || old.ID == "" {
		return errors.New("no fingerprint or id")
	}
	key := "rotate:" + old.Fingerprint
	if t.ByKey(key) != nil {
		return errors.New("fingerprint appears twice")
	}
	created := old.FirstSeen
	if len(old.History) > 0 && (created.IsZero() || old.History[0].At.Before(created)) {
		created = old.History[0].At
	}
	if created.IsZero() {
		created = now
	}
	it := t.newItem(KindRotate, key, "rotations", "", created)
	it.Fingerprint = old.Fingerprint
	it.Status, it.SnoozedUntil, it.Priority = st, old.SnoozedUntil, old.Priority
	it.Secret = &Secret{ID: old.ID, Service: old.Service, Type: old.Type, Redacted: old.Redacted, Impact: old.Impact,
		Reasons: old.Reasons, FirstSeen: old.FirstSeen, LastSeen: old.LastSeen, Locations: old.Locations,
		UsedIn: old.UsedIn, RotateURL: old.RotateURL, RotatedLocations: old.RotatedLocations}
	if it.Secret.UsedIn == nil {
		it.Secret.UsedIn = []string{}
	}
	for _, e := range old.History {
		ev, ok := legacyEvents[e.Action]
		if !ok {
			ev = EvNote // next, replace-plan, replace-failed, history-only, redacted
		}
		it.Log(e.At, ev, e.Action, e.Note)
		if ev == EvStatus || ev == EvReopened {
			it.StatusAt = e.At.UTC()
		}
	}
	if old.LastSeen.After(it.UpdatedAt) {
		it.UpdatedAt = old.LastSeen.UTC()
	}
	it.Severity = secretrisk.SeverityOf(it.Priority) // info for noise
	it.secretTitleAndNext()
	return nil
}

// pinnedKey is the key of an item that holds one finding on its own (a finding grouped nowhere
// else, or accepted apart from its group): sync attaches that finding to it before any grouping.
func pinnedKey(findingID string) string { return "finding:" + findingID }
