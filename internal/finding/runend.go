package finding

import (
	"fmt"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/textfmt"
)

// ScopeAll stands for everything a run covers: a skipped "prefix*" covers every scope with that
// prefix (docs/architecture.md, "Run completeness").
const ScopeAll = "*"

const (
	maxInspectedListed = 50  // inspected scopes are listed for people only
	maxSkippedListed   = 200 // beyond this a run counts as having inspected nothing
	maxReason          = 200
)

// ScopeOf is the coverage scope of a finding: its Scope, else its Account.
func ScopeOf(f Finding) string {
	if f.Scope != "" {
		return f.Scope
	}
	return f.Account
}

type Skipped struct {
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
}

// Scopes lists a run's coverage; the lists are capped, the counts are not.
type Scopes struct {
	Inspected      []string  `json:"inspected"`
	InspectedCount int       `json:"inspected_count"`
	Skipped        []Skipped `json:"skipped"`
	SkippedCount   int       `json:"skipped_count"`
}

// RunEnd is the last record of a finished run of one connector instance.
type RunEnd struct {
	Type      string    `json:"type"` // always "run_end"
	Connector string    `json:"connector"`
	Instance  string    `json:"instance,omitempty"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Complete  bool      `json:"complete"` // nothing skipped and no error
	Error     string    `json:"error,omitempty"`
	Scopes    Scopes    `json:"scopes"`
	// SecretFingerprints of the secrets the core resolved, by name, so the tracker can tell a leaked
	// copy is in use.
	SecretFingerprints map[string]string `json:"secret_fingerprints,omitempty"`
	Theme              Theme             `json:"theme,omitzero"` // zero in runs from before themes
	Covers             []Area            `json:"covers,omitempty"`
}

// Tally collects a run's coverage as records arrive; not safe for concurrent use.
type Tally struct {
	inspected   []string
	isInspected map[string]bool
	skipped     []Skipped
	isSkipped   map[string]bool
	any         bool // something was inspected
}

// Status marks the status's scope (or account) inspected when ok, skipped otherwise.
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

// Declare records a scope inspected, or skipped for reason; a skipped "" is ScopeAll.
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

// End is the run_end record. Nothing counts as inspected after err, or when nothing was inspected.
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

const unknownCoverage = "no run_end record: the run was interrupted, is still running, or predates run_end records"

// Coverage answers whether a run inspected a finding's scope. The zero value, a run without
// run_end, never proves anything gone.
type Coverage struct {
	Known   bool // the run has a run_end record
	all     string
	skipped []Skipped
}

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

func (c Coverage) Complete() bool { return c.Known && c.all == "" && len(c.skipped) == 0 }

func (c Coverage) Skipped() []Skipped { return c.skipped }

// Expected reports a scope the owner's config left out; it still proves nothing there gone.
func (s Skipped) Expected() bool { return strings.HasPrefix(s.Reason, string(StateExpected)) }

// Missed is what the run did not inspect and the config did not leave out.
func (c Coverage) Missed() []Skipped {
	var out []Skipped
	for _, s := range c.skipped {
		if !s.Expected() {
			out = append(out, s)
		}
	}
	return out
}

func (c Coverage) CompleteAsConfigured() bool { return c.Known && c.all == "" && len(c.Missed()) == 0 }

// NoneChecked reports, with the reason, a run that proves nothing gone.
func (c Coverage) NoneChecked() (string, bool) {
	switch {
	case !c.Known:
		return unknownCoverage, true
	case c.all != "":
		return c.all, true
	}
	return "", false
}

// Unchecked reports, with the reason, whether the run did not inspect account and scope. scope ""
// (recorded before scopes existed) counts as unchecked when anything was skipped.
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

// PathScope is the part of scope at path, skipped when a run could not read it.
func PathScope(scope, path string) string { return scope + ":" + path }

// UncheckedPath is also unchecked when the run skipped a PathScope that holds path or lies in it.
func (c Coverage) UncheckedPath(account, scope, path string) (string, bool) {
	if why, unchecked := c.Unchecked(account, scope); unchecked || path == "" {
		return why, unchecked
	}
	for _, s := range c.skipped {
		if p, ok := strings.CutPrefix(s.Scope, PathScope(scope, "")); ok && overlaps(p, path) {
			return s.Scope + ": " + s.Reason, true
		}
	}
	return "", false
}

func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func (c Coverage) UncheckedFinding(f Finding) (string, bool) {
	return c.UncheckedPath(f.Account, ScopeOf(f), PathOf(f))
}

// PathOf is the local path in a finding's evidence: its repository, else its file.
func PathOf(f Finding) string {
	for _, k := range []string{"repo", "path"} {
		if p, _ := f.Evidence[k].(string); strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "/") {
			return p
		}
	}
	return ""
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
