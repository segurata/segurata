package tracker

import (
	"cmp"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/textfmt"
)

// Coverage: what segurata looked at, and what it cannot look at on this machine. Each sync keeps,
// per connector instance, its newest run and how complete it was (Tracker.Runs), for the coverage
// line of status: "cloudflare: never run; github: 3 h ago, partial: user:me not checked". And the
// plan's areas that no connector audits here become review items of theme coverage, each with the
// step that would cover it, listed apart from what is failing. See docs/architecture.md, "Coverage".

// maxSkippedKept is how many skipped scopes a RunInfo keeps.
const maxSkippedKept = 5

// recordRuns keeps what status needs of each folded run.
func (t *Tracker) recordRuns(folded map[string]*run) {
	if t.Runs == nil {
		t.Runs = map[string]RunInfo{}
	}
	for l, r := range folded {
		info := RunInfo{At: r.at, Finished: r.cov.Known, Error: r.failed}
		// A scope left out by a status the config expects (when the run was written, or by a rule
		// added since) is left out on purpose: counted, not listed, and not a partial run.
		expected := map[string]bool{}
		allExpected := len(r.statuses) > 0
		for _, st := range r.statuses {
			if st.State == finding.StateExpected {
				expected[cmp.Or(st.Scope, st.Account)] = true
			} else {
				allExpected = false
			}
		}
		// Every status expected: what the run left out (everything, when nothing said ok) is too.
		expected[finding.ScopeAll] = expected[finding.ScopeAll] || allExpected
		var sk []finding.Skipped
		for _, s := range r.cov.Skipped() {
			if expected[s.Scope] || strings.HasPrefix(s.Reason, string(finding.StateExpected)) {
				info.Expected++
				continue
			}
			sk = append(sk, s)
		}
		info.Complete = r.cov.Known && r.failed == "" && len(sk) == 0 && (r.cov.Complete() || info.Expected > 0)
		info.SkippedCount = len(sk)
		for _, s := range sk[:min(len(sk), maxSkippedKept)] {
			info.Skipped = append(info.Skipped, s.Scope+": "+oneLine(s.Reason))
		}
		t.Runs[l] = info
	}
}

// coverageLine says, for each connector instance (configured ones and any that ran), when its
// newest run finished and whether it saw everything.
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
			s += ", failed: " + firstSentence(info.Error)
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
		if info.Expected > 0 {
			s += fmt.Sprintf(" (%s left out as expected)", count(info.Expected, "scope", "scopes"))
		}
		parts = append(parts, s)
	}
	return "Coverage: " + strings.Join(parts, "; ") + "."
}

// age is a duration as status shows it: 25 min ago, 3 h ago, 2 d ago.
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

func firstSentence(s string) string {
	head, _ := textfmt.Clip(s, 120)
	return head
}

// gap is one area of the plan (docs/plan.md) that may go unaudited on this machine: whether it is
// covered, judged from the runs, and the step that would cover it.
type gap struct {
	slug, title string
	// covered says whether the area is audited, and how; known is false when the runs folded now
	// say nothing about it (the item is left as it is). nil: no connector audits it.
	covered       func(t *Tracker, folded map[string]*run) (covered bool, how string, known bool)
	step, command string
	url           string
}

var gaps = []gap{
	{slug: "github-owner-2fa", title: "Two-factor authentication of your own GitHub account is not audited",
		covered: githubOwner2FA,
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
		covered: ranConnector("hibp"),
		step:    "Install the example connector and give it a Have I Been Pwned API key and your addresses (examples/hibp/README.md), then run it.",
		command: "segurata inventory hibp", url: "https://haveibeenpwned.com/API/Key"},
	{slug: "password-manager", title: "The password manager's reused and breached password report is not audited by any connector",
		step: "Review 1Password Watchtower or Bitwarden Reports and change the reused, weak and breached passwords (docs/plan.md, section 2). Mark this done when checked."},
	{slug: "workspace", title: "Google Workspace administration is not audited: no workspace tenant could be read",
		covered: workspaceRead,
		step:    "Set up read-only Admin SDK credentials for each tenant (README.md, \"Google Workspace administration\"), then run the connector.",
		command: "segurata inventory workspace"},
}

// githubOwner2FA is covered when the github run read the owner's own account: no status other
// than ok for a user:<login> scope or naming the read:user scope (runs before scopes existed). A
// sync that folds no github run goes by the open setup items.
func githubOwner2FA(t *Tracker, folded map[string]*run) (bool, string, bool) {
	blocked := func(scope, detail string) bool {
		return strings.HasPrefix(scope, "user:") || strings.Contains(detail, "read:user")
	}
	r := folded["github"]
	if r == nil {
		if t.openSetup("setup:github|", func(ref FindingRef) bool { return blocked(ref.Scope, ref.Title) }) {
			return false, "", true
		}
		return false, "", false
	}
	for _, st := range r.statuses {
		if st.State != finding.StateOK && blocked(st.Scope, st.Detail) {
			return false, "", true
		}
	}
	return true, "the github run read your account", true
}

// openSetup reports whether an active setup item whose key starts with prefix has a reported
// status ref that match accepts.
func (t *Tracker) openSetup(prefix string, match func(FindingRef) bool) bool {
	for _, it := range t.Items {
		if it.Kind != KindSetup || it.Status != Open && it.Status != InProgress || !strings.HasPrefix(it.Key, prefix) {
			continue
		}
		if slices.ContainsFunc(it.Findings, func(r FindingRef) bool { return !r.Gone && match(r) }) {
			return true
		}
	}
	return false
}

// ranConnector is covered once an instance of the connector has run.
func ranConnector(name string) func(*Tracker, map[string]*run) (bool, string, bool) {
	return func(t *Tracker, _ map[string]*run) (bool, string, bool) {
		for l := range t.Runs {
			if l == name || strings.HasPrefix(l, name+":") {
				return true, l + " ran", true
			}
		}
		return false, "", true
	}
}

// workspaceRead is covered when a workspace tenant reported ok; it is a gap only when some tenant
// is configured (it ran) and none could be read: whether the owner has a tenant is not known
// otherwise.
func workspaceRead(t *Tracker, folded map[string]*run) (bool, string, bool) {
	configured := false
	for l, r := range folded {
		if l != "workspace" && !strings.HasPrefix(l, "workspace:") {
			continue
		}
		configured = true
		if slices.ContainsFunc(r.statuses, func(st finding.Status) bool { return st.State == finding.StateOK }) {
			return true, l + " was read", true
		}
	}
	if !configured && t.openSetup("setup:workspace", func(FindingRef) bool { return true }) {
		return false, "", true // no workspace run folded now, but a tenant is still waiting for setup
	}
	return false, "", configured
}

// CoverageReport counts what a sync did to coverage items.
type CoverageReport struct{ Opened, Covered int }

// syncCoverage opens a coverage item for each gap not covered and closes, as done and verified,
// the ones a run now covers. An item the owner closed by hand stays closed; one segurata closed
// opens again when the gap comes back.
func (t *Tracker) syncCoverage(folded map[string]*run, now time.Time) CoverageReport {
	var rep CoverageReport
	for _, g := range gaps {
		covered, how, known := false, "", true
		if g.covered != nil {
			covered, how, known = g.covered(t, folded)
		}
		it := t.ByKey("coverage:" + g.slug)
		switch {
		case !known:
		case covered && it != nil && it.Active(now):
			it.setStatus(now, Done, EvVerified, actAutoDone, "covered: "+how)
			at := now.UTC()
			it.VerifiedAt = &at
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
	for i := len(it.History) - 1; i >= 0; i-- {
		switch it.History[i].Event {
		case EvStatus, EvVerified, EvReopened, EvReclassified, EvMerged:
			return it.History[i].Action
		}
	}
	return ""
}

// notAudited lists the open coverage items: what segurata does not look at here, with the step
// that would cover each. They are not failures, so they stay out of the headline and "Do next".
func notAudited(d *doc.Doc, items []*Item, now time.Time) {
	var list []doc.Item
	for _, it := range sorted(items, func(it *Item) bool { return it.Theme == coverageTheme && it.Active(now) }) {
		out := doc.Item{Badge: "not audited", Text: it.Title, Meta: it.ID}
		if n := it.Next; n != nil {
			out.Details = append(out.Details, doc.Fold("Cover it", n.Action, actionLen))
			if n.Command != "" {
				out.Details = append(out.Details, doc.Detail{Label: "Command", Text: n.Command, Kind: doc.DCode})
			}
			if n.URL != "" {
				out.Details = append(out.Details, doc.Detail{Label: "Where", Text: n.URL, Kind: doc.DLink})
			}
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
