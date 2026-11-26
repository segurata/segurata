package tracker

import (
	"regexp"
	"strings"
	"time"
)

// blockedBy is the first pending decision that blocks the item, or nil.
func (t *Tracker) blockedBy(it *Item, now time.Time) *Item {
	if it.Kind == KindDecide || it.Kind == KindSetup {
		return nil
	}
	for _, d := range t.Items {
		if d.Kind == KindDecide && d.Active(now) && d.Decision != nil && blocks(d, it) {
			return d
		}
	}
	return nil
}

func (t *Tracker) unblocks(d *Item, now time.Time) []*Item {
	if d.Kind != KindDecide || d.Decision == nil || !d.Active(now) {
		return nil
	}
	var out []*Item
	for _, it := range t.Items {
		if it.Active(now) && it.Kind != KindDecide && it.Kind != KindSetup && blocks(d, it) {
			out = append(out, it)
		}
	}
	return out
}

// blocks reports whether one of the decision's option effects would close the item, or the
// decision is about data dumps and the item is one.
func blocks(d, it *Item) bool {
	for _, e := range d.Decision.Effects {
		if (Rule{Effect: e.Effect, Scope: e.Scope}).inScope(it) {
			return true
		}
	}
	return it.Theme == "data-dumps" && aboutDumps.MatchString(d.Key+" "+d.Decision.Question)
}

// aboutDumps matches "dump" or "dumps" as a word, not a tool such as mysqldump.
var aboutDumps = regexp.MustCompile(`(?i)\bdumps?\b`)

const blockedPrefix = "Blocked by decision "

// noteBlocked prefixes the next step of each blocked item other than a secret with its decision,
// and drops the prefix from items no longer blocked.
func (t *Tracker) noteBlocked(now time.Time) {
	for _, it := range t.Items {
		if it.Next == nil || it.Kind == KindRotate {
			continue
		}
		action := it.Next.Action
		if strings.HasPrefix(action, blockedPrefix) {
			if _, rest, ok := strings.Cut(action, "first. "); ok {
				action = rest
			}
		}
		if d := t.blockedBy(it, now); d != nil && it.Active(now) {
			action = blockedPrefix + d.ID + " (" + d.Decision.Question + "): answer it first. " + action
		}
		it.Next.Action = action
	}
}
