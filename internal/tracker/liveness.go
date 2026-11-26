package tracker

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/secretrisk"
)

// updateLiveness keeps the newest trusted result among the sightings, dropping a held one that is
// no longer trusted or is dated after now (a clock that jumped). See docs/architecture.md,
// "Liveness".
func (s *Secret) updateLiveness(g []Sighting, now time.Time) {
	usable := func(l *secretrisk.Liveness) bool { return l.Trusted() && !l.CheckedAt.After(now) }
	if s.Liveness != nil && !usable(s.Liveness) {
		s.Liveness = nil
	}
	for _, x := range g {
		if l := x.Evidence.Liveness; l != nil && usable(l) && supersedes(*l, s.Liveness) {
			c := *l
			s.Liveness = &c
		}
	}
}

// supersedes reports whether l replaces held: newer, and unknown never replaces a verdict.
func supersedes(l secretrisk.Liveness, held *secretrisk.Liveness) bool {
	switch {
	case held == nil:
		return true
	case l.State == secretrisk.Unknown && held.State != secretrisk.Unknown:
		return false
	}
	return l.CheckedAt.After(held.CheckedAt)
}

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

func (it *Item) checkedLive() bool { return it.livenessIs(secretrisk.Live) }

func (it *Item) provenLive() bool { return len(it.live()) > 0 || it.checkedLive() }

const unchecked secretrisk.LiveState = "unchecked"

// LivenessLabel is the latest check's state, or unchecked.
func (it *Item) LivenessLabel() string {
	l := it.liveness()
	if l == nil {
		return string(unchecked)
	}
	return string(l.State)
}

func (it *Item) livenessReason() string {
	l := it.liveness()
	if l == nil {
		return ""
	}
	day := l.CheckedAt.Format(time.DateOnly)
	switch {
	case l.State == secretrisk.Unregistered:
		return "unregistered: " + l.Said() + " on " + day + "; not proof it is dead"
	case l.ByOwner && (l.State == secretrisk.Live || l.State == secretrisk.Dead):
		return string(l.State) + ": " + l.Said() + " on " + day
	case l.State == secretrisk.Live:
		r := "live: " + l.Endpoint + " accepted it on " + day
		if l.Account != "" {
			r += " as " + l.Account
		}
		return r
	case l.State == secretrisk.Dead:
		return fmt.Sprintf("dead: %s rejected it on %s (%s)", l.Endpoint, day, l.Reason)
	}
	return ""
}

// closeDead closes an active item whose key the latest check found dead, as a rotation would end,
// unless a connector reports it live, the owner reopened it since, or a working file still holds
// it.
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
	if it.reopenedSince(l.CheckedAt) || it.inWorkingFile() {
		return
	}
	it.Accepted = nil
	it.setStatus(now, Done, EvStatus, actDead, fmt.Sprintf("key no longer valid (checked %s: %s)", l.CheckedAt.Format(time.DateOnly), l.Said()))
	it.derive()
}

func (it *Item) inWorkingFile() bool {
	return slices.ContainsFunc(it.Secret.Locations, func(l Location) bool { return l.working() && !l.Gone })
}

// reopenUndead opens an item a dead check closed once that verdict no longer stands.
func (it *Item) reopenUndead(now time.Time) {
	if it.Status != Done || !it.closedDead() || it.livenessIs(secretrisk.Dead) {
		return
	}
	it.setStatus(now, Open, EvReopened, actAutoReopen, "the dead verdict that closed it no longer stands: the key is "+it.LivenessLabel()+" now")
	it.derive()
}

func (it *Item) closedDead() bool { return it.latestOf(actDead, actDone, actAutoDone) == actDead }

func (it *Item) livenessClaims() attribution.Claims {
	l := it.liveness()
	if l == nil {
		return attribution.Claims{}
	}
	return attribution.FromAccount(l.Account)
}

// LivenessLine is how many tracked secrets the check settled, and the count of each state.
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
	settled := 0
	for _, st := range append(slices.Clone(secretrisk.LiveStates), unchecked) {
		if counts[string(st)] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[string(st)], st))
		}
		if st != secretrisk.Unknown && st != unchecked {
			settled += counts[string(st)]
		}
	}
	return fmt.Sprintf("Liveness checked for %d of %d secrets: %s.", settled, total, strings.Join(parts, ", "))
}
