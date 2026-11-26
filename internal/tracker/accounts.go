package tracker

import (
	"strings"
	"time"
)

// setupPrefix is the lowercased start of an account's setup item keys (setupKey).
func setupPrefix(lbl, account string) string {
	return strings.ToLower("setup:" + lbl + "|" + account + "|")
}

// CloseSetup ignores, with reason, every active or snoozed setup item of the account in the
// connector instance lbl: `segurata accounts unwatch`.
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

// ReopenSetup opens again the setup items CloseSetup ignored with reason: `accounts watch`.
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
