package tracker

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/textfmt"
)

const maxSkippedKept = 5

// recordRuns keeps what the coverage line needs of each folded run. See docs/architecture.md,
// "Coverage".
func (t *Tracker) recordRuns(folded map[string]*run) {
	if t.Runs == nil {
		t.Runs = map[string]RunInfo{}
	}
	for l, r := range folded {
		info := RunInfo{At: r.at, Finished: r.cov.Known, Error: r.failed, Theme: r.theme.ID}
		// A scope an expected status left out is left out on purpose: counted, not a partial run.
		expected := map[string]bool{}
		allExpected := len(r.statuses) > 0
		for _, st := range r.statuses {
			if st.State == finding.StateExpected {
				expected[cmp.Or(st.Scope, st.Account)] = true
			} else {
				allExpected = false
			}
		}
		// Every status expected: whatever the run left out is too.
		expected[finding.ScopeAll] = expected[finding.ScopeAll] || allExpected
		var sk []finding.Skipped
		for _, s := range r.cov.Skipped() {
			switch {
			case s.Reason == finding.UnreadableReason:
				info.Unreadable++
			case expected[s.Scope] || s.Expected():
				info.Expected++
			default:
				sk = append(sk, s)
			}
		}
		if len(sk) > 0 && sk[0].Scope == finding.ScopeAll { // nothing proven: no count of what was left out
			info.Expected, info.Unreadable = 0, 0
		}
		info.Complete = r.cov.Known && r.failed == "" && len(sk) == 0 && (r.cov.Complete() || info.Expected+info.Unreadable > 0)
		info.SkippedCount = len(sk)
		for _, a := range r.covers {
			if info.Areas == nil {
				info.Areas = map[string]bool{}
			}
			info.Areas[a.ID] = a.Audited(r.statuses)
		}
		for _, s := range sk[:min(len(sk), maxSkippedKept)] {
			info.Skipped = append(info.Skipped, s.Scope+": "+oneLine(s.Reason))
		}
		t.Runs[l] = info
	}
}

// coverageLine is "cloudflare: never run; github: 3 h ago, partial: user:me not checked".
func (t *Tracker) coverageLine(instances []string, now time.Time) string {
	all := slices.Clone(instances)
	for l := range t.Runs {
		if !slices.Contains(all, l) {
			all = append(all, l)
		}
	}
	if len(all) == 0 {
		return ""
	}
	sort.Strings(all)
	var parts []string
	for _, l := range all {
		info, ok := t.Runs[l]
		if !ok {
			if at, seen := t.Sources[l]; seen { // folded before runs were recorded
				parts = append(parts, l+": "+age(now.Sub(at)))
				continue
			}
			parts = append(parts, l+": never run")
			continue
		}
		s := l + ": " + age(now.Sub(info.At))
		switch {
		case !info.Finished:
			s += ", unfinished (no run_end)"
		case info.Error != "":
			head, _ := textfmt.Clip(info.Error, 120)
			s += ", failed: " + head
		case !info.Complete && len(info.Skipped) > 0:
			scope, _, _ := strings.Cut(info.Skipped[0], ": ")
			what := scope + " not checked"
			if scope == finding.ScopeAll {
				what = "nothing checked"
			}
			s += ", partial: " + what
			if n := info.SkippedCount - 1; n > 0 {
				s += fmt.Sprintf(" (+%d more)", n)
			}
		case !info.Complete:
			s += ", partial"
		}
		parts = append(parts, s+info.expectedNote())
	}
	return "Coverage: " + strings.Join(parts, "; ") + "."
}

// expectedNote is " (1 scope and 12 unreadable paths left out as expected)", or "".
func (i RunInfo) expectedNote() string {
	var out []string
	if i.Expected > 0 {
		out = append(out, textfmt.Count(i.Expected, "scope", "scopes"))
	}
	if i.Unreadable > 0 {
		out = append(out, textfmt.Count(i.Unreadable, "unreadable path", "unreadable paths"))
	}
	if len(out) == 0 {
		return ""
	}
	return " (" + strings.Join(out, " and ") + " left out as expected)"
}

func age(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d d ago", int(d.Hours()/24))
}

// gap is an area of docs/plan.md that may go unaudited on this machine, and the step that would
// cover it.
type gap struct {
	slug, title string
	// audited: connectors declare the area (finding.Area). Otherwise the gap stays open until the
	// owner marks it done.
	audited bool
	// unreported: the gap is open, not unknown, while no run reports the area.
	unreported    bool
	step, command string
	url           string
}

var gaps = []gap{
	{slug: "github-owner-2fa", title: "Two-factor authentication of your own GitHub account is not audited",
		audited: true,
		step:    "Give gh the read:user scope so the github connector can read whether 2FA is on, then run it again.",
		command: "gh auth refresh -h github.com -s read:user && segurata inventory github", url: "https://github.com/settings/security"},
	{slug: "google-recovery", title: "Google recovery options and passkeys are not audited by any connector",
		step: "On every Google account, run Security Checkup (sessions, devices, recovery phone and email) and register a passkey or security key; remove SMS as a second factor (docs/plan.md, section 1). Mark this done when checked.",
		url:  "https://myaccount.google.com/security-checkup"},
	{slug: "apple-account", title: "Apple Account devices and Sign in with Apple apps are not audited by any connector",
		step: "Review the devices and the apps using Sign in with Apple, and remove the ones you no longer use (docs/manual-review.md). Mark this done when checked.",
		url:  "https://account.apple.com/account/manage"},
	{slug: "stripe-keys", title: "Stripe API keys are not audited by any connector",
		step: "In every Stripe account, replace secret keys with restricted keys and delete the unused ones (docs/plan.md, section 6). Mark this done when checked.",
		url:  "https://dashboard.stripe.com/apikeys"},
	{slug: "hibp", title: "Breaches of your email addresses are not checked: the hibp connector is not set up",
		audited: true, unreported: true,
		step:    "Install the example connector and give it a Have I Been Pwned API key and your addresses (examples/hibp/README.md), then run it.",
		command: "segurata inventory hibp", url: "https://haveibeenpwned.com/API/Key"},
	{slug: "password-manager", title: "The password manager's reused and breached password report is not audited by any connector",
		step: "Review 1Password Watchtower or Bitwarden Reports and change the reused, weak and breached passwords (docs/plan.md, section 2). Mark this done when checked."},
	{slug: "workspace", title: "Google Workspace administration is not audited: no workspace tenant could be read",
		audited: true,
		step:    "Set up read-only Admin SDK credentials for each tenant (docs/inventory.md, \"Google Workspace administration\"), then run the connector.",
		command: "segurata inventory workspace"},
}

// audited is what the runs say of the gap's area: covered when one audited it, open when one could
// not, else unknown (or open, for an unreported gap with no legacy run that might cover it).
func (t *Tracker) audited(g gap) (covered bool, how string, known bool) {
	reported, legacy := false, false
	for _, l := range slices.Sorted(maps.Keys(t.Runs)) {
		info := t.Runs[l]
		legacy = legacy || info.legacy()
		a, ok := info.Areas[g.slug]
		if a {
			return true, l + " audited it", true
		}
		reported = reported || ok
	}
	return false, "", reported || g.unreported && !legacy
}

// CoverageReport counts coverage items opened and closed as covered.
type CoverageReport struct{ Opened, Covered int }

// syncCoverage opens an item for each uncovered gap and verifies the ones a run now covers. One
// the owner closed stays closed; one segurata closed reopens when the gap comes back.
func (t *Tracker) syncCoverage(now time.Time) CoverageReport {
	var rep CoverageReport
	for _, g := range gaps {
		covered, how, known := false, "", true
		if g.audited {
			covered, how, known = t.audited(g)
		}
		it := t.itemByKey("coverage:" + g.slug)
		switch {
		case !known:
		case covered && it != nil && it.Active(now):
			it.verifyDone(now, "covered: "+how)
			rep.Covered++
		case covered:
		case it == nil:
			it = t.newItem(KindReview, "coverage:"+g.slug, coverageTheme, g.title, now)
			it.Log(now, EvFound, actFound, "not audited on this machine")
			rep.Opened++
		case it.Status == Done && it.lastAction() == actAutoDone:
			it.setStatus(now, Open, EvReopened, actAutoReopen, "not audited again")
			rep.Opened++
		}
		if it != nil {
			it.Title = g.title
			it.Next = &Next{Who: You, Action: g.step, Command: g.command, URL: g.url}
		}
	}
	return rep
}

// lastAction is the action of the latest status-changing history event.
func (it *Item) lastAction() string {
	for _, e := range slices.Backward(it.History) {
		switch e.Event {
		case EvStatus, EvVerified, EvReopened, EvReclassified, EvMerged:
			return e.Action
		}
	}
	return ""
}

// notAudited lists the open coverage items apart: they are not failures.
func notAudited(d *doc.Doc, items []*Item, now time.Time) {
	var list []doc.Item
	for _, it := range sorted(items, func(it *Item) bool { return it.Theme == coverageTheme && it.Active(now) }) {
		out := doc.Item{Badge: "not audited", Text: it.Title, Meta: it.ID}
		if it.Next != nil {
			out.Details = nextDetails("Cover it", it.Next)
		}
		list = append(list, out)
	}
	if len(list) == 0 {
		return
	}
	d.H(2, "Not audited on this machine")
	d.P("Areas of the plan no connector checks here; not failures. Each says how to cover it, or mark it done once checked by hand.")
	d.List(list)
}
