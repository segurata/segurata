package tracker

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/finding"
)

// expectedReasons are the distinct reasons when every status of a setup proposal is expected, or
// nil when one is not. See docs/architecture.md, "Expected statuses".
func (p *proposal) expectedReasons() []string {
	if len(p.refs) == 0 {
		return nil
	}
	var out []string
	for _, r := range p.refs {
		if r.Expected == "" {
			return nil
		}
		if !slices.Contains(out, r.Expected) {
			out = append(out, r.Expected)
		}
	}
	return out
}

// expectedMoves closes a setup item whose every status is expected, or reopens an expected one
// that reports a status no rule covers; it reports whether it closed. A done item goes back to
// expected, not open, so an intermittent expected status never reaches the to-do list.
func (it *Item) expectedMoves(reasons []string, now time.Time) bool {
	switch {
	case reasons != nil && (it.Status == Open || it.Status == InProgress || it.Status == Snoozed || it.Status == Done):
		it.setStatus(now, Expected, EvStatus, actExpected, "expected by your config: "+strings.Join(reasons, "; "))
		return true
	case reasons == nil && it.Status == Expected:
		it.setStatus(now, Open, EvReopened, actAutoReopen, "reported again and no expected rule in your config covers it")
	}
	return false
}

// expectedByReason counts, by reason, the expected setup items whose statuses are still reported.
func expectedByReason(items []*Item) map[string]int {
	out := map[string]int{}
	for _, it := range items {
		if it.Kind != KindSetup || it.Status != Expected || !it.reported() {
			continue
		}
		seen := map[string]bool{}
		for _, r := range it.Findings {
			if !r.Gone && r.Expected != "" && !seen[r.Expected] {
				seen[r.Expected] = true
				out[r.Expected]++
			}
		}
	}
	return out
}

// expectRule is the config rule, under the connector instance key, that expects a setup item's
// statuses.
func (it *Item) expectRule(reason, detail string) (key string, rule config.Expected, err error) {
	if it.Kind != KindSetup || len(it.Findings) == 0 {
		return "", rule, fmt.Errorf("%s is not a setup item: only a connector status can be expected", it.ID)
	}
	if strings.TrimSpace(reason) == "" {
		return "", rule, errors.New("expect needs --reason (why this status is expected)")
	}
	r := it.Findings[0]
	state := it.setupState()
	rule = config.Expected{State: state, Account: globEscape(r.Account), Detail: detail, Reason: strings.TrimSpace(reason)}
	return r.Label(), rule, nil
}

// globEscape quotes the characters path.Match treats as a pattern.
func globEscape(s string) string {
	var b strings.Builder
	for _, c := range s {
		if strings.ContainsRune(`*?[\`, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func (it *Item) expect(at time.Time, rule config.Expected, where string) {
	for i := range it.Findings {
		if !it.Findings[i].Gone && rule.Matches(finding.Status{Account: it.Findings[i].Account, Detail: it.Findings[i].Title}, rule.State) {
			it.Findings[i].Expected = rule.Reason
		}
	}
	it.Accepted = nil
	it.setStatus(at, Expected, EvStatus, actExpected, "expected by your config: "+rule.Reason+" (rule in "+where+")")
	it.Next = &Next{Who: You, Action: "Nothing: expected by your config (" + rule.Reason + ")."}
}
