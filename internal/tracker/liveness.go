package tracker

import (
	"fmt"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Liveness: local-secrets can try a secret against its provider at scan time and record the answer
// in the evidence (connectors/internal/liveness). A rotate item keeps the newest answer:
//   - live is proof the key works, as a connector's report is (see correlate.go): P0 once a copy
//     left the machine, an ignored or rotated item opens again;
//   - dead closes an open item as done, "key no longer valid": nobody can use the key, which is where
//     a rotation ends too, so the item ends the same way. Copies in working files do not reopen it
//     (they fail for whoever reads them). A later check that finds it live opens it again; the owner
//     reopening it by hand after the check sticks. Ignored and accepted items are left alone, and
//     so is an item a connector reports live: two sources disagree, the open item stays;
//   - unknown changes nothing.
// See docs/architecture.md, "Liveness".

// updateLiveness keeps the newest result among the sightings, so a run that did not check the
// secret (or a cached result older than the one held) leaves the item's as it is.
func (s *Secret) updateLiveness(g []Sighting) {
	for _, x := range g {
		if l := x.Evidence.Liveness; l != nil && (s.Liveness == nil || l.CheckedAt.After(s.Liveness.CheckedAt)) {
			c := *l
			s.Liveness = &c
		}
	}
}

// liveness is the latest check's result, nil when the item has no secret or it was never checked.
func (it *Item) liveness() *secretrisk.Liveness {
	if it.Secret == nil {
		return nil
	}
	return it.Secret.Liveness
}

func (it *Item) livenessIs(st secretrisk.LiveState) bool {
	l := it.liveness()
	return l != nil && l.State == st
}

// checkedLive reports whether the latest liveness check found the secret live.
func (it *Item) checkedLive() bool { return it.livenessIs(secretrisk.Live) }

// provenLive reports whether a connector reports the secret or the liveness check accepted it.
func (it *Item) provenLive() bool { return len(it.live()) > 0 || it.checkedLive() }

// LivenessLabel is the latest check's state for listings: live, dead, unknown, or unchecked.
func (it *Item) LivenessLabel() string {
	l := it.liveness()
	if l == nil {
		return "unchecked"
	}
	return string(l.State)
}

// livenessReason says what the latest check found, "" when it found nothing that tells.
func (it *Item) livenessReason() string {
	l := it.liveness()
	if l == nil {
		return ""
	}
	day := l.CheckedAt.Format(time.DateOnly)
	switch l.State {
	case secretrisk.Live:
		r := "live: " + l.Endpoint + " accepted it on " + day
		if l.Account != "" {
			r += " as " + l.Account
		}
		return r
	case secretrisk.Dead:
		return fmt.Sprintf("dead: %s rejected it on %s (%s)", l.Endpoint, day, l.Reason)
	}
	return ""
}

// closeDead closes an open, in-progress or snoozed item whose latest check found the key dead,
// unless a connector reports it live or the owner reopened it after that check.
func (it *Item) closeDead(now time.Time) {
	if !it.livenessIs(secretrisk.Dead) || len(it.live()) > 0 {
		return
	}
	switch it.Status {
	case Open, InProgress, Snoozed:
	default:
		return
	}
	l := it.Secret.Liveness
	if it.reopenedSince(l.CheckedAt) {
		return
	}
	it.leaveAccepted()
	it.setStatus(now, Done, EvStatus, actDead, fmt.Sprintf("key no longer valid (checked %s: %s answered %s)", l.CheckedAt.Format(time.DateOnly), l.Endpoint, l.Reason))
	it.derive()
}

// closedDead reports whether the item's latest done came from a dead check rather than the owner.
func (it *Item) closedDead() bool {
	for i := len(it.History) - 1; i >= 0; i-- {
		switch it.History[i].Action {
		case actDead:
			return true
		case actDone, actAutoDone:
			return false
		}
	}
	return false
}

// livenessClaims are the claims of the account the latest check says the secret signs in as.
func (it *Item) livenessClaims() attribution.Claims {
	l := it.liveness()
	if l == nil {
		return attribution.Claims{}
	}
	return attribution.FromAccount(l.Account)
}

// LivenessLine is the coverage of the check over the tracked secrets (not noise, not merged): how
// many it settled live or dead, and the count of each state. "" without such secrets.
func (t *Tracker) LivenessLine() string {
	counts := map[string]int{}
	total := 0
	for _, it := range t.Items {
		if it.Kind != KindRotate || it.Secret == nil || it.Priority == "" || it.Status == Merged || it.Status == Reclassified {
			continue
		}
		total++
		counts[it.LivenessLabel()]++
	}
	if total == 0 {
		return ""
	}
	var parts []string
	for _, st := range []string{"live", "dead", "unknown", "unchecked"} {
		if counts[st] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[st], st))
		}
	}
	return fmt.Sprintf("Liveness checked for %d of %d secrets: %s.", counts["live"]+counts["dead"], total, strings.Join(parts, ", "))
}
