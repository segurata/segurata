package tracker

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

// History actions; the rotation rules read some of them back.
const (
	actFound       = "found"
	actSeen        = "seen"
	actStart       = "start"
	actDone        = "done"
	actSnooze      = "snooze"
	actIgnore      = "ignore"
	actReopen      = "reopen"
	actAutoReopen  = "auto-reopen"
	actAutoDone    = "auto-done"
	actVerified    = "verified"
	actWake        = "snooze-expired"
	actAccept      = "accept"
	actUnaccept    = "unaccept"
	actAcceptLapse = "acceptance-expired"
	actNote        = "note"
	actNotChecked  = "not-checked"
	actDecide      = "decide"
	actReanswer    = "reanswer"
	actPrioritize  = "prioritize"
	actOwner       = "owner"  // the owner set whose a secret is, or cleared it
	actRaised      = "raised" // a sync raised the computed priority to P1 or P0
	actHistory     = "history-only"
	actRedacted    = "redacted"
	actReclassify  = "reclassified"
	actExpected    = "expected"
	actRule        = "rule"
	actMerged      = "merged"
	actProvenLive  = "proven-live"
	actDead        = "dead" // the liveness check found the key no longer valid
	// Logged by `segurata rotations`.
	ActNext          = "next"
	ActReplacePlan   = "replace-plan"
	ActReplaceFailed = "replace-failed"
)

func (t *Tracker) newItem(kind Kind, key, theme, title string, now time.Time) *Item {
	it := &Item{ID: formatID(t.NextID), Key: key, Kind: kind, Theme: theme, Title: title, Status: Open,
		StatusAt: now.UTC(), CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	t.NextID++
	t.Items = append(t.Items, it)
	return it
}

func (t *Tracker) itemByKey(key string) *Item {
	for _, it := range t.Items {
		if it.Key == key {
			return it
		}
	}
	return nil
}

// Log appends a history event and marks the item updated.
func (it *Item) Log(at time.Time, event, action, detail string) {
	it.History = append(it.History, Event{At: at.UTC(), Event: event, Action: action, Detail: detail})
	if at.UTC().After(it.UpdatedAt) {
		it.UpdatedAt = at.UTC()
	}
}

func (it *Item) setStatus(at time.Time, st Status, event, action, detail string) {
	it.Status, it.StatusAt = st, at.UTC()
	if st != Merged {
		it.MergedInto = ""
	}
	if st != Snoozed {
		it.SnoozedUntil = ""
	}
	if st != Done {
		it.VerifiedAt = nil
	}
	it.Log(at, event, action, detail)
}

func (it *Item) start(at time.Time, note string) error {
	if it.Closed() {
		return fmt.Errorf("%s is %s: reopen it first", it.ID, it.Status)
	}
	it.setStatus(at, InProgress, EvStatus, actStart, note)
	return nil
}

// Done marks the item done; a later sync verifies or reopens it. A rotate item records the
// locations known now, which decide whether a later sighting reopens it (rotatedSeen).
func (it *Item) Done(at time.Time, note string) {
	it.Accepted = nil
	it.setStatus(at, Done, EvStatus, actDone, note)
	if s := it.Secret; s != nil {
		s.RotatedLocations = make([]string, 0, len(s.Locations))
		for _, l := range s.Locations {
			s.RotatedLocations = append(s.RotatedLocations, l.ref())
		}
		sort.Strings(s.RotatedLocations)
	}
	it.derive()
}

func (it *Item) verifyDone(now time.Time, detail string) {
	it.setStatus(now, Done, EvVerified, actAutoDone, detail)
	at := now.UTC()
	it.VerifiedAt = &at
}

// snooze hides the item until a date (YYYY-MM-DD in at's zone).
func (it *Item) snooze(at time.Time, until, note string) error {
	d, err := time.ParseInLocation(time.DateOnly, until, at.Location())
	if err != nil {
		return fmt.Errorf("--until %q is not a date (YYYY-MM-DD)", until)
	}
	if !d.After(at) {
		return fmt.Errorf("--until %s is not in the future", until)
	}
	it.Accepted = nil
	it.setStatus(at, Snoozed, EvStatus, actSnooze, strings.TrimSpace("until "+until+" "+note))
	it.SnoozedUntil = until
	return nil
}

func (it *Item) ignore(at time.Time, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("ignore needs --reason (why this is not a real problem)")
	}
	it.Accepted = nil
	it.setStatus(at, Ignored, EvStatus, actIgnore, reason)
	return nil
}

func (it *Item) reopen(at time.Time, note string) {
	it.Accepted = nil
	it.setStatus(at, Open, EvReopened, actReopen, note)
	if it.Secret != nil {
		it.Secret.RotatedLocations = nil
	}
	if it.Decision != nil {
		it.Decision.Answer, it.Decision.AnsweredAt = "", nil
	}
	it.derive()
}

// Note adds free text to the history.
func (it *Item) Note(at time.Time, text string) error {
	if strings.TrimSpace(text) == "" {
		return errors.New("an empty note")
	}
	it.Log(at, EvNote, actNote, text)
	return nil
}

func (it *Item) decide(at time.Time, answer string) error {
	answer = strings.TrimSpace(answer)
	switch {
	case it.Decision == nil:
		return fmt.Errorf("%s is not a decision", it.ID)
	case answer == "":
		return errors.New("decide needs --answer")
	}
	at = at.UTC()
	it.Decision.Answer, it.Decision.AnsweredAt = answer, &at
	it.Log(at, EvDecided, actDecide, answer)
	it.setStatus(at, Done, EvStatus, actDone, "decided")
	return nil
}

// prioritize sets a priority by hand; "" goes back to the computed one.
func (it *Item) prioritize(at time.Time, p secretrisk.Priority, reason string) error {
	if p == "" {
		it.PriorityOverride = nil
		it.Log(at, EvPriority, actPrioritize, "back to the computed priority "+textfmt.OrDash(string(it.Priority)))
		return nil
	}
	if p.Rank() > secretrisk.P3.Rank() {
		return fmt.Errorf("priority %q: use P0, P1, P2, P3 or auto", p)
	}
	if strings.TrimSpace(reason) == "" {
		return errors.New("prioritize needs --reason")
	}
	it.PriorityOverride = &Override{Priority: p, Reason: reason, At: at.UTC()}
	it.Log(at, EvPriority, actPrioritize, string(p)+": "+reason)
	return nil
}

// parsePriority reads P0..P3 (any case), or "auto" or "" for the computed priority.
func parsePriority(s string) (secretrisk.Priority, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "", "AUTO":
		return "", nil
	case "P0", "P1", "P2", "P3":
		return secretrisk.Priority(s), nil
	}
	return "", fmt.Errorf("priority %q: use P0, P1, P2, P3 or auto", s)
}

// accept keeps the item's risk on purpose, until a date (inclusive) or for good.
func (it *Item) accept(at time.Time, reason, until string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return errors.New("accept needs --reason (why this risk is kept on purpose)")
	}
	if until != "" {
		d, err := time.ParseInLocation(time.DateOnly, until, at.Location())
		if err != nil {
			return fmt.Errorf("--until %q is not a date (YYYY-MM-DD)", until)
		}
		if !at.Before(d.AddDate(0, 0, 1)) {
			return fmt.Errorf("--until %s is in the past", until)
		}
	}
	it.Accepted = &Acceptance{Reason: reason, Until: until, AcceptedAt: at.UTC()}
	it.setStatus(at, Accepted, EvStatus, actAccept, acceptDetail(reason, until))
	return nil
}

func acceptDetail(reason, until string) string {
	if until == "" {
		return reason
	}
	return reason + " (until " + until + ")"
}

func acceptedNext() *Next {
	return &Next{Who: You, Action: "Nothing while the acceptance holds; review it when it expires."}
}

func (it *Item) unaccept(at time.Time) {
	it.Accepted = nil
	it.setStatus(at, Open, EvStatus, actUnaccept, "")
}

// AcceptanceExpired reports whether the acceptance is past its last day in now's zone, or a sync
// already lifted it.
func (it *Item) AcceptanceExpired(now time.Time) bool {
	if it.Accepted == nil {
		return false
	}
	if it.Status != Accepted {
		return true
	}
	if it.Accepted.Until == "" {
		return false
	}
	d, err := time.ParseInLocation(time.DateOnly, it.Accepted.Until, now.Location())
	return err != nil || !now.Before(d.AddDate(0, 0, 1))
}

// keptApart reports whether the owner accepted or ignored an item that holds one finding apart
// from its group, so the finding stays there.
func (it *Item) keptApart() bool {
	return it.Accepted != nil || it.Status == Ignored
}

// Closed reports whether the item is off the to-do list for a reason other than a snooze.
func (it *Item) Closed() bool {
	switch it.Status {
	case Done, Ignored, Accepted, Reclassified, Expected, Merged:
		return true
	}
	return false
}

// Active reports whether the item is open, in progress, or snoozed past its date.
func (it *Item) Active(today time.Time) bool {
	switch it.Status {
	case Open, InProgress:
		return true
	case Snoozed:
		return it.snoozeOver(today)
	}
	return false
}

// RotationStatus is the status as `segurata rotations` words it: done is "rotated".
func (it *Item) RotationStatus() string {
	if it.Status == Done {
		return "rotated"
	}
	return string(it.Status)
}

func (it *Item) snoozeOver(today time.Time) bool {
	d, err := time.ParseInLocation(time.DateOnly, it.SnoozedUntil, today.Location())
	return err != nil || !today.Before(d)
}

// NewsSince reports whether, since then, the item was found, reopened or raised to P1 or P0: what
// a scheduled run notifies.
func (it *Item) NewsSince(since time.Time) bool {
	return slices.ContainsFunc(it.History, func(ev Event) bool {
		news := ev.Event == EvFound || ev.Event == EvReopened || ev.Event == EvPriority && ev.Action == actRaised
		return news && !ev.At.Before(since.UTC())
	})
}

// EffectivePriority is the override, else the computed priority.
func (it *Item) EffectivePriority() secretrisk.Priority {
	if it.PriorityOverride != nil {
		return it.PriorityOverride.Priority
	}
	return it.Priority
}

func priorityOf(s finding.Severity) secretrisk.Priority {
	switch s {
	case finding.SevCritical:
		return secretrisk.P0
	case finding.SevHigh:
		return secretrisk.P1
	case finding.SevMedium:
		return secretrisk.P2
	case finding.SevLow:
		return secretrisk.P3
	}
	return ""
}

// find resolves an item id (T-0012 or T-12), a rotate item's short id, or a unique prefix of a
// short id or fingerprint.
func (t *Tracker) find(ref string) (*Item, error) {
	return t.findWhere(ref, func(*Item) bool { return true }, "segurata track list --all")
}

// FindRotate is find among rotate items only.
func (t *Tracker) FindRotate(ref string) (*Item, error) {
	return t.findWhere(ref, func(it *Item) bool { return it.Kind == KindRotate }, "segurata rotations list --all")
}

func (t *Tracker) findWhere(ref string, keep func(*Item) bool, hint string) (*Item, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("missing item id")
	}
	if num, ok := strings.CutPrefix(strings.ToUpper(ref), "T-"); ok {
		n, err := strconv.Atoi(num)
		if err == nil {
			for _, it := range t.Items {
				if idNumber(it.ID) == n && keep(it) {
					return it, nil
				}
			}
		}
		return nil, fmt.Errorf("no item %q (see: %s)", ref, hint)
	}
	var hits []*Item
	for _, it := range t.Items {
		if !keep(it) || it.Secret == nil {
			continue
		}
		if it.Secret.ID == ref {
			return it, nil
		}
		if strings.HasPrefix(it.Secret.ID, ref) || strings.HasPrefix(it.Fingerprint, ref) {
			hits = append(hits, it)
		}
	}
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("no item %q (see: %s)", ref, hint)
	case 1:
		return hits[0], nil
	}
	return nil, fmt.Errorf("%q matches %d items, use more characters", ref, len(hits))
}

// Sort orders items most urgent first: by priority, then secrets by proof of life and exposure,
// other items by severity, title and id.
func Sort(items []*Item) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if pa, pb := a.EffectivePriority().Rank(), b.EffectivePriority().Rank(); pa != pb {
			return pa < pb
		}
		if a.Secret != nil && b.Secret != nil {
			if la, lb := a.liveAndLeaked(), b.liveAndLeaked(); la != lb {
				return la
			}
			if ea, eb := a.worst().Level, b.worst().Level; ea != eb {
				return ea > eb
			}
			if ua, ub := len(a.Secret.UsedIn) > 0, len(b.Secret.UsedIn) > 0; ua != ub {
				return ua
			}
			if oa, ob := a.owned(), b.owned(); oa != ob {
				return oa
			}
			if da, db := a.lastCommitted(), b.lastCommitted(); da != db {
				return da > db
			}
			if na, nb := len(a.Secret.Locations), len(b.Secret.Locations); na != nb {
				return na > nb
			}
			if ra, rb := spotRank(a.worst()), spotRank(b.worst()); ra != rb {
				return ra > rb
			}
			if a.Secret.Service != b.Secret.Service {
				return a.Secret.Service < b.Secret.Service
			}
			return a.Secret.ID < b.Secret.ID
		}
		if sa, sb := a.Severity.Rank(), b.Severity.Rank(); sa != sb {
			return sa > sb
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		return idNumber(a.ID) < idNumber(b.ID)
	})
}
