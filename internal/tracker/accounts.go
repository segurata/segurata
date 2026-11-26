package tracker

import (
	"strings"
	"time"
)

// Setup items of watched and unwatched accounts: `segurata accounts unwatch` closes the setup
// items of an account it takes out of a connector's config, and `accounts watch` opens again the
// ones it closed.

// setupPrefix is the start of the keys of an account's setup items (setupKey), lowercased.
func setupPrefix(lbl, account string) string {
	return strings.ToLower("setup:" + lbl + "|" + account + "|")
}

// CloseSetup ignores, with reason, every open, in-progress or snoozed setup item of the account in
// the connector instance lbl, and returns them.
func (t *Tracker) CloseSetup(lbl, account, reason string, now time.Time) []*Item {
	var out []*Item
	for _, it := range t.Items {
		if it.Kind == KindSetup && strings.HasPrefix(strings.ToLower(it.Key), setupPrefix(lbl, account)) &&
			(it.Status == Open || it.Status == InProgress || it.Status == Snoozed) {
			_ = it.ignore(now, reason)
			out = append(out, it)
		}
	}
	return out
}

// ReopenSetup opens again the setup items of the account in lbl that CloseSetup ignored with
// reason, and returns them.
func (t *Tracker) ReopenSetup(lbl, account, reason, note string, now time.Time) []*Item {
	var out []*Item
	for _, it := range t.Items {
		if it.Kind == KindSetup && it.Status == Ignored && strings.HasPrefix(strings.ToLower(it.Key), setupPrefix(lbl, account)) &&
			it.lastDetail(actIgnore) == reason {
			it.setStatus(now, Open, EvReopened, actReopen, note)
			out = append(out, it)
		}
	}
	return out
}
