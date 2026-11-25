package finding

import (
	"fmt"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/textfmt"
)

// Run completeness: every run ends with a run_end record saying which scopes it inspected and
// which it skipped, so a finding missing from an incomplete run is never taken as resolved. See
// docs/architecture.md, "Run completeness".

// ScopeAll is the scope that stands for everything a run covers. A skipped scope ending in "*"
// covers every scope that starts with the part before it, so "*" alone covers them all.
const ScopeAll = "*"

const (
	maxInspectedListed = 50  // inspected scopes are listed for people only
	maxSkippedListed   = 200 // beyond this a run counts as having inspected nothing
	maxReason          = 200
)

// ScopeOf is the part of the account a finding belongs to, as runs report coverage: its Scope, or
// its Account when the connector inspects the account as one unit.
func ScopeOf(f Finding) string {
	if f.Scope != "" {
		return f.Scope
	}
	return f.Account
}

// Skipped is a scope a run did not inspect, and why.
type Skipped struct {
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
}

// Scopes lists a run's coverage. The lists are capped; the counts are not.
type Scopes struct {
	Inspected      []string  `json:"inspected"`
	InspectedCount int       `json:"inspected_count"`
	Skipped        []Skipped `json:"skipped"`
	SkippedCount   int       `json:"skipped_count"`
}

// RunEnd is the last record of a connector instance's output. A file without one is a run that was
// interrupted, is still running, or predates run_end records.
type RunEnd struct {
	Type      string    `json:"type"` // always "run_end"
	Connector string    `json:"connector"`
	Instance  string    `json:"instance,omitempty"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Complete  bool      `json:"complete"` // nothing skipped and no error
	Error     string    `json:"error,omitempty"`
	Scopes    Scopes    `json:"scopes"`
	// SecretFingerprints are the fingerprints (internal/fingerprint) of the secrets the core resolved
	// for this instance, by name (OPENAI_ADMIN_KEY): never the values. The tracker matches them with
	// leaked copies, which the run proves are in use.
	SecretFingerprints map[string]string `json:"secret_fingerprints,omitempty"`
	// Theme is the theme the connector declared, resolved by ThemeFor; zero for none (and in runs
	// written before connectors declared one).
	Theme Theme `json:"theme,omitzero"`
}

// Tally collects a run's coverage as records arrive. It is not safe for concurrent use.
type Tally struct {
	inspected   []string
	isInspected map[string]bool
	skipped     []Skipped
	isSkipped   map[string]bool
	any         bool // something was inspected
}

// Status counts a status: ok marks its scope (or account) inspected; any other state leaves it
// uninspected, and a status naming neither leaves everything uninspected.
func (t *Tally) Status(st Status) {
	id := st.Scope
	if id == "" {
		id = st.Account
	}
	if st.State == StateOK {
		t.Declare(id, true, "")
		return
	}
	reason := string(st.State)
	if st.Detail != "" {
		reason += ": " + st.Detail
	}
	t.Declare(id, false, reason)
}

// Declare records a scope a connector inspected, or skipped for reason. A skipped "" is ScopeAll.
func (t *Tally) Declare(id string, inspected bool, reason string) {
	if inspected {
		t.any = true
		if id == "" || t.isInspected[id] {
			return
		}
		if t.isInspected == nil {
			t.isInspected = map[string]bool{}
		}
		t.isInspected[id] = true
		t.inspected = append(t.inspected, id)
		return
	}
	if id == "" {
		id = ScopeAll
	}
	if t.isSkipped[id] {
		return
	}
	if t.isSkipped == nil {
		t.isSkipped = map[string]bool{}
	}
	if reason == "" {
		reason = "not inspected"
	}
	t.isSkipped[id] = true
	t.skipped = append(t.skipped, Skipped{Scope: id, Reason: clip(reason)})
}

// End is the run_end record for what was tallied. err is the connector's own error (it could not
// start, or was interrupted): then nothing counts as inspected. So too when no status said ok and
// no scope was declared inspected.
func (t *Tally) End(connector, instance string, started, ended time.Time, err error) RunEnd {
	var all []Skipped
	switch {
	case err != nil:
		all = []Skipped{{Scope: ScopeAll, Reason: clip(err.Error())}}
	case !t.any && !t.isSkipped[ScopeAll]:
		all = []Skipped{{Scope: ScopeAll, Reason: "no account was reported as inspected"}}
	}
	skipped := all
	for _, s := range t.skipped {
		if len(all) == 0 || s.Scope != ScopeAll {
			skipped = append(skipped, s)
		}
	}
	inspected := []string{}
	for _, id := range t.inspected {
		if !t.isSkipped[id] {
			inspected = append(inspected, id)
		}
	}
	e := RunEnd{Type: "run_end", Connector: connector, Instance: instance, StartedAt: started.UTC(), EndedAt: ended.UTC(),
		Complete: len(skipped) == 0,
		Scopes: Scopes{Inspected: inspected[:min(len(inspected), maxInspectedListed)], InspectedCount: len(inspected),
			Skipped: append([]Skipped{}, skipped[:min(len(skipped), maxSkippedListed)]...), SkippedCount: len(skipped)}}
	if err != nil {
		e.Error = clip(err.Error())
	}
	return e
}

func clip(s string) string {
	return textfmt.Truncate(strings.Join(strings.Fields(s), " "), maxReason+1)
}

// unknownCoverage explains why a file without run_end is never trusted to say something is gone.
const unknownCoverage = "no run_end record: the run was interrupted, is still running, or predates run_end records"

// Coverage answers, for one run, whether a finding's scope was inspected. The zero value is a run
// without run_end: usable for display, never proof that anything is gone.
type Coverage struct {
	Known   bool // the run has a run_end record
	all     string
	skipped []Skipped
}

// CoverageOf reads a run_end record; nil (or a zero record) gives the unknown coverage.
func CoverageOf(end *RunEnd) Coverage {
	if end == nil || end.Type != "run_end" {
		return Coverage{}
	}
	c := Coverage{Known: true, skipped: end.Scopes.Skipped}
	if end.Scopes.SkippedCount > len(end.Scopes.Skipped) {
		c.all = fmt.Sprintf("%d scopes not inspected, too many to list", end.Scopes.SkippedCount)
	}
	for _, s := range c.skipped {
		if s.Scope == ScopeAll {
			c.all = s.Reason
		}
	}
	return c
}

// Complete reports whether the run has a run_end and skipped nothing.
func (c Coverage) Complete() bool { return c.Known && c.all == "" && len(c.skipped) == 0 }

// Skipped is what the run did not inspect.
func (c Coverage) Skipped() []Skipped { return c.skipped }

// NoneChecked reports, with the reason, a run that proves nothing gone: no run_end, or nothing
// inspected.
func (c Coverage) NoneChecked() (string, bool) {
	switch {
	case !c.Known:
		return unknownCoverage, true
	case c.all != "":
		return c.all, true
	}
	return "", false
}

// Unchecked reports, with the reason, whether the run did not inspect the given account and scope.
// scope "" means unknown (recorded before scopes existed): then any skipped scope counts.
func (c Coverage) Unchecked(account, scope string) (string, bool) {
	if why, none := c.NoneChecked(); none {
		return why, true
	}
	for _, s := range c.skipped {
		switch {
		case matchScope(s.Scope, scope) || matchScope(s.Scope, account):
			return s.Scope + ": " + s.Reason, true
		case scope == "":
			return "recorded without a scope, and this run skipped " + s.Scope + ": " + s.Reason, true
		}
	}
	return "", false
}

// UncheckedFinding is Unchecked for a finding of a run that records scopes.
func (c Coverage) UncheckedFinding(f Finding) (string, bool) {
	return c.Unchecked(f.Account, ScopeOf(f))
}

func matchScope(pattern, id string) bool {
	if id == "" {
		return false
	}
	if p, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(id, p)
	}
	return pattern == id
}
