package tracker

import (
	"strings"
	"time"
)

// Blocked items wait on a pending decision: what to do with them depends on the answer. A
// decision blocks the items one of its options' effects would close, and a question about data
// dumps (its key or question names them, like "Purge the data dumps from git history?") blocks
// the data-dump items. Status shows the decision first, with how many items it unblocks, and the
// blocked item's next step names it.

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

// unblocks are the active items a pending decision blocks.
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

func blocks(d, it *Item) bool {
	for _, e := range d.Decision.Effects {
		if (Rule{Effect: e.Effect, Scope: e.Scope}).inScope(it) {
			return true
		}
	}
	return it.Theme == "data-dumps" && strings.Contains(strings.ToLower(d.Key+" "+d.Decision.Question), "dump")
}

// blockedPrefix starts the next step of a blocked item.
const blockedPrefix = "Blocked by decision "

// noteBlocked starts the next step of every blocked item other than a secret with the decision it
// waits on, and takes that note off items no longer blocked.
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
