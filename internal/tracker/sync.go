package tracker

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/runfile"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

// SyncOptions say which runs a sync folds in.
type SyncOptions struct {
	OutDir       string // the latest run of every connector instance in it
	From         string // a local-secrets output to use instead of its latest run
	IncludeNoise bool   // track noise-only secrets too, without a priority
	// Expect applies the config's expected rules to each status, at every sync, so a rule added
	// since the run counts.
	Expect func(*finding.Status)
	Owned  attribution.Owned // accounts the runs do not show: config `owned`, the git email
}

// SyncReport counts what a sync changed.
type SyncReport struct {
	Runs    []string // connector instances folded in
	Stale   []string // skipped: older than the run already folded
	Secrets SecretReport
	// Items other than secrets.
	Created, Verified, Reopened int
	Expected                    int // setup items closed because the config expects them
	Ruled                       int // items closed by a decision's rule
	Merged                      int // connector items closed into the rotate item of their secret
	Coverage                    CoverageReport
	// Every item.
	Woken, Lapsed int
	// Unreadable are run files skipped with their error: their instance counts as not run, so
	// nothing it reported closes.
	Unreadable []string
}

type run struct {
	label    string
	at       time.Time
	findings []finding.Finding
	statuses []finding.Status
	cov      finding.Coverage
	failed   string // the connector's own error, from run_end
	// The rest comes from run_end.
	fingerprints map[string]string // the secrets the core resolved for the instance, by name
	theme        finding.Theme
	covers       []finding.Area
}

// statusesUnproven reports, with the reason, a run whose statuses cannot prove an earlier one
// gone: unfinished, or failed. Completeness of scopes protects findings, not statuses.
func (r *run) statusesUnproven() (string, bool) {
	if !r.cov.Known {
		return r.cov.NoneChecked()
	}
	if r.failed != "" {
		return "the connector failed: " + r.failed, true
	}
	return "", false
}

// legacy reports whether the run predates connectors declaring their theme and grouping.
func (r *run) legacy() bool { return r.theme.ID == "" }

// wholeInstance reports whether the run has a status of that state for no account in particular.
func (r *run) wholeInstance(state finding.State) bool {
	return slices.ContainsFunc(r.statuses, func(st finding.Status) bool {
		return st.Account == "" && st.Scope == "" && reported(st).State == state
	})
}

// notChecked is the same for every sync of one run, so each item logs it once.
func (r *run) notChecked(why string) string {
	return fmt.Sprintf("not checked in run %s of %s (%s)", r.label, r.at.Format(time.RFC3339), why)
}

// Sync folds the latest run of every connector instance into the items: secrets into rotate
// items, findings at low or above into their groups, statuses other than ok into setup items.
// Then items no run reports any more close as verified, done items reported again reopen, and
// expired snoozes and acceptances lapse. A finding is gone only when a finished run inspected its
// scope. See docs/architecture.md, "Run completeness".
func (t *Tracker) Sync(opt SyncOptions, now time.Time) (SyncReport, error) {
	var rep SyncReport
	runs, unreadable, err := readRuns(opt, now)
	if err != nil {
		return rep, err
	}
	rep.Unreadable = unreadable
	folded := map[string]*run{}
	for _, r := range runs {
		// A source after now (a future timestamp) would hold every later run back: absent.
		if prev, ok := t.Sources[r.label]; ok && !prev.After(now) && r.at.Before(prev) {
			rep.Stale = append(rep.Stale, r.label)
			continue
		}
		if opt.Expect != nil {
			for i := range r.statuses {
				opt.Expect(&r.statuses[i])
			}
		}
		folded[r.label] = r
	}
	for l := range folded {
		rep.Runs = append(rep.Runs, l)
	}
	sort.Strings(rep.Runs)

	byKey := map[string]*Item{}
	was := map[*Item]secretrisk.Priority{}
	for _, it := range t.Items {
		byKey[it.Key] = it
		was[it] = it.EffectivePriority()
	}
	// Accounts first, so a secret attributed mine counts in full from its first sync.
	t.discover(runs)
	owned := t.ownedAll(opt.Owned)
	for _, l := range rep.Runs {
		if r := folded[l]; r.isSecrets() {
			rep.Secrets.add(t.SyncSecrets(sightingsOf(r.findings), now, opt.IncludeNoise, opt.Owned))
			rep.Secrets.add(t.syncNoise(noiseOnly(r.findings), now))
			t.markGoneLocations(r)
		}
	}
	claims, possible := t.correlate(folded)
	props, regroup := t.propose(rep.Runs, folded, claims, byKey)
	seen := t.applyProposals(props, byKey, now, &rep)

	t.attachLive(claims, possible, folded)
	moved := claimedBy(claims)
	for id, key := range regroup {
		moved[id] = byKey[key].ID
	}
	for _, it := range t.Items {
		if it.Kind == KindRotate || len(it.Findings) == 0 {
			continue
		}
		if it.moveRefs(moved, now) {
			rep.Merged++
		}
		if it.Status == Merged {
			continue
		}
		held := it.markGone(seen[it], folded)
		t.lifecycle(it, folded, now, &rep)
		it.noteHeld(held, now)
	}
	t.expireAll(now, &rep)
	t.collectClaims(folded)
	t.attribute(owned)
	rep.Ruled = t.applyRules(now)
	t.noteBlocked(now)
	t.seed(now)
	t.declareThemes(folded)
	if t.Sources == nil {
		t.Sources = map[string]time.Time{}
	}
	for l, r := range folded {
		t.Sources[l] = r.at
	}
	t.recordRuns(folded)
	rep.Coverage = t.syncCoverage(now)
	noteRaised(was, now)
	at := now.UTC()
	t.LastSyncAt = &at
	return rep, nil
}

// proposals are what a sync proposes, by item key, in the order first proposed.
type proposals struct {
	byKey map[string]*proposal
	order []string
}

func (ps *proposals) at(key string, p proposal) *proposal {
	if got, ok := ps.byKey[key]; ok {
		return got
	}
	p.key = key
	ps.byKey[key] = &p
	ps.order = append(ps.order, key)
	return &p
}

// propose groups the findings and statuses of the folded runs into the items they belong to.
// Secrets, claimed credentials and info findings make none. regroup maps each finding that moves
// from an item of its own into a group to that group's key.
func (t *Tracker) propose(labels []string, folded map[string]*run, claims map[string]claim, byKey map[string]*Item) (props *proposals, regroup map[string]string) {
	props, regroup = &proposals{byKey: map[string]*proposal{}}, map[string]string{}
	holders := t.findingHolders()
	for _, l := range labels {
		r := folded[l]
		for _, f := range r.findings {
			if ev, ok := secretEvidence(f); ok {
				if trail[ev.Kind] && secretrisk.ImpactOf(ev) != secretrisk.Noise {
					props.at("transcripts:redact|"+r.label, transcriptsProposal()).add(f)
				}
				continue
			}
			if _, claimed := claims[f.ID]; claimed || f.Severity.Rank() < finding.SevLow.Rank() {
				continue
			}
			held := holders[f.ID]
			key, p, moves := placeFinding(f, r, held, byKey)
			if moves {
				regroup[f.ID] = key
			}
			got := props.at(key, p)
			got.add(f)
			if p.grouping.keepTitle {
				got.keepWhere(held)
			}
		}
		for _, st := range r.statuses {
			if st.State != finding.StateOK {
				key, p := setupProposal(r.label, st)
				props.at(key, p).addStatus(st, r.at)
			}
		}
	}
	return props, regroup
}

// placeFinding is the key and proposal of f's item: its grouping's, except that a legacy run keeps
// f in the item that holds it, and a finding held on its own stays there unless its grouping now
// groups it (moves).
func placeFinding(f finding.Finding, r *run, held *Item, byKey map[string]*Item) (key string, p proposal, moves bool) {
	g := groupingFor(f)
	key, p = groupKey(f, g, themeOf(f, r.theme.ID))
	if r.legacy() && held != nil && ruleKey(held.Key) {
		kept := *g
		kept.keepTitle = true
		key, p.grouping = held.Key, &kept
	}
	if pin, pinned := byKey[pinnedKey(f.ID)]; pinned && pin.Key != key {
		if g.by == perFinding || pin.keptApart() {
			p.grouping = &grouping{kind: g.kind}
			return pinnedKey(f.ID), p, false
		}
		return key, p, true
	}
	return key, p, false
}

// applyProposals folds each proposal into its item, creating or reopening it, and returns the
// refs each item saw.
func (t *Tracker) applyProposals(props *proposals, byKey map[string]*Item, now time.Time, rep *SyncReport) map[*Item]map[string]bool {
	seen := map[*Item]map[string]bool{}
	for _, key := range props.order {
		p := props.byKey[key]
		it, existed := byKey[key]
		expected := p.expectedReasons()
		if !existed {
			it = t.newItem(p.kind, key, p.theme, "", now)
			byKey[key] = it
			it.Log(now, EvFound, actFound, textfmt.Count(len(p.refs), "finding", "findings"))
			if expected == nil {
				rep.Created++
			}
		} else if it.Status == Merged {
			it.reopenMerged(now)
			rep.Reopened++
		}
		seen[it] = map[string]bool{}
		if added := it.upsert(p.refs, seen[it]); added > 0 && existed {
			it.Log(now, EvSeen, actSeen, textfmt.Count(added, "new finding", "new findings"))
		}
		switch {
		case strings.HasPrefix(key, "transcripts:"):
			p.finishTranscripts()
		case p.kind == KindSetup:
			p.finishSetup(it.ID)
		}
		p.finish(it.ID)
		if p.title != "" {
			it.Title = p.title
		}
		if p.next != nil && it.Status != Accepted {
			it.Next = p.next
		}
		it.Severity = p.severity()
		it.Priority = priorityOf(it.Severity)
		if p.kind == KindSetup && it.expectedMoves(expected, now) {
			rep.Expected++
		}
	}
	return seen
}

// noteRaised logs each item the sync raised to P1 or P0, so the raise is news (NewsSince).
func noteRaised(was map[*Item]secretrisk.Priority, now time.Time) {
	for it, before := range was {
		if p := it.EffectivePriority(); p.Rank() <= secretrisk.P1.Rank() && p.Rank() < before.Rank() {
			it.Log(now, EvPriority, actRaised, "raised to "+string(p)+" from "+textfmt.OrDash(string(before)))
		}
	}
}

func (r SyncReport) foldedSecrets() bool {
	for _, l := range r.Runs {
		if isSecretsLabel(l) {
			return true
		}
	}
	return false
}

// syncLine sums up what a sync did to items other than secrets.
func syncLine(r SyncReport) string {
	s := fmt.Sprintf("Tracker: %s folded; %d new items, %d verified done, %d reopened, %d expected by your config, %d closed by decisions, %d merged into the secret they hold; %d snoozes and %d acceptances expired.\n",
		textfmt.Count(len(r.Runs), "run", "runs"), r.Created, r.Verified, r.Reopened, r.Expected, r.Ruled, r.Merged, r.Woken, r.Lapsed)
	if len(r.Stale) > 0 {
		s += fmt.Sprintf("Skipped older runs than the tracker already holds: %s.\n", strings.Join(r.Stale, ", "))
	}
	for _, u := range r.Unreadable {
		s += fmt.Sprintf("Skipped an unreadable run, nothing it reported was closed: %s\n", u)
	}
	return s
}

func (s *SecretReport) add(o SecretReport) {
	s.Secrets += o.Secrets
	s.Created += o.Created
	s.Updated += o.Updated
	s.Reopened += o.Reopened
	s.Skipped += o.Skipped
	s.Reclassified += o.Reclassified
	s.HistoryOnly += o.HistoryOnly
	s.Paired += o.Paired
}

// trail are the local-secrets location kinds `segurata redact` cleans.
var trail = map[string]bool{"transcript": true, "history": true, "log": true}

func (r *run) isSecrets() bool { return isSecretsLabel(r.label) }

func isSecretsLabel(l string) bool {
	return l == secretrisk.ConnectorName || strings.HasPrefix(l, secretrisk.ConnectorName+":")
}

func transcriptsProposal() proposal {
	return proposal{theme: "transcripts", kind: KindFix, connector: secretrisk.ConnectorName, maxSeverity: finding.SevMedium,
		next: &Next{Who: Segurata, Command: "segurata redact --trails",
			Action: "Review the dry run, then run it again with --apply. Rotation is still needed: these copies already reached the model provider or wherever the trail went."}}
}

func (p *proposal) finishTranscripts() {
	files := map[string]bool{}
	for _, f := range p.findings {
		if ev, ok := secretEvidence(f); ok {
			files[ev.Path] = true
		}
	}
	p.title = fmt.Sprintf("Redact secrets from %s (agent transcripts, shell histories, logs)", textfmt.Count(len(files), "trail file", "trail files"))
}

// readRuns reads the latest run of every connector instance, and opt.From. A run that cannot be
// read goes to unreadable: one torn file must not stop every other connector's sync.
func readRuns(opt SyncOptions, now time.Time) (runs []*run, unreadable []string, err error) {
	files, err := runfile.LatestFiles(opt.OutDir, now)
	if err != nil {
		if opt.From == "" {
			return nil, nil, err
		}
		files = nil
	}
	var from *run
	if opt.From != "" {
		if from, err = readRunFile(opt.From); err != nil {
			return nil, nil, err
		}
	}
	for _, f := range files {
		r, err := readRunFile(f)
		if err != nil {
			unreadable = append(unreadable, err.Error())
			continue
		}
		if from == nil || r.label != from.label {
			runs = append(runs, r)
		}
	}
	if from != nil {
		runs = append(runs, from)
	}
	return runs, unreadable, nil
}

func readRunFile(file string) (*run, error) {
	rf, err := runfile.Read(file)
	if err != nil {
		return nil, err
	}
	r := &run{label: rf.Label(file), findings: rf.Findings, statuses: rf.Statuses, cov: rf.Coverage()}
	// Without run_end: the newest observed_at not in the future, then the file's mtime.
	if rf.End != nil {
		r.at, r.failed, r.fingerprints, r.theme, r.covers = rf.End.EndedAt, rf.End.Error, rf.End.SecretFingerprints, rf.End.Theme, rf.End.Covers
	} else {
		limit := time.Now()
		for _, f := range rf.Findings {
			if f.ObservedAt.After(r.at) && !f.ObservedAt.After(limit) {
				r.at = f.ObservedAt
			}
		}
	}
	if r.at.IsZero() {
		st, err := os.Stat(file)
		if err != nil {
			return nil, err
		}
		r.at = st.ModTime()
	}
	r.at = r.at.UTC()
	return r, nil
}

// upsert adds or refreshes refs and returns how many were new.
func (it *Item) upsert(refs []FindingRef, seen map[string]bool) int {
	idx := make(map[string]int, len(it.Findings))
	for i, r := range it.Findings {
		idx[r.ID] = i
	}
	added := 0
	for _, r := range refs {
		seen[r.ID] = true
		if i, ok := idx[r.ID]; ok {
			if r.LastSeen.IsZero() {
				r.LastSeen = it.Findings[i].LastSeen
			}
			it.Findings[i] = r
			continue
		}
		idx[r.ID] = len(it.Findings)
		it.Findings = append(it.Findings, r)
		added++
	}
	return added
}

// markGone flags the refs this sync did not see whose scope their run inspected, and returns the
// "not checked" note of each ref it held back. A status ref is gone once a finished run lacks it,
// or any run reports the item's key with other details or the same state for the whole instance.
func (it *Item) markGone(seen map[string]bool, folded map[string]*run) map[string]string {
	held := map[string]string{}
	for i := range it.Findings {
		r := &it.Findings[i]
		if seen[r.ID] {
			continue
		}
		run, ok := folded[r.Label()]
		if !ok {
			continue
		}
		why, unchecked := run.cov.UncheckedPath(r.Account, r.Scope, r.Path)
		if strings.HasPrefix(r.ID, "status:") {
			why, unchecked = run.statusesUnproven()
			if len(seen) > 0 || r.Account != "" && run.wholeInstance(it.setupState()) {
				unchecked = false
			}
		}
		if unchecked {
			held[r.ID] = run.notChecked(why)
			continue
		}
		r.Gone = true
	}
	return held
}

// noteHeld logs, once per run, why an item that would have closed did not: every finding still
// counted as reported lies in a scope its run did not inspect.
func (it *Item) noteHeld(held map[string]string, now time.Time) {
	if len(held) == 0 || (it.Closed() && !(it.Status == Done && it.VerifiedAt == nil)) {
		return
	}
	var notes []string
	for _, r := range it.Findings {
		if r.Gone {
			continue
		}
		note, ok := held[r.ID]
		if !ok {
			return
		}
		if !slices.Contains(notes, note) {
			notes = append(notes, note)
		}
	}
	for _, note := range notes {
		if !slices.ContainsFunc(it.History, func(e Event) bool { return e.Action == actNotChecked && e.Detail == note }) {
			it.Log(now, EvNote, actNotChecked, note)
		}
	}
}

func (it *Item) reported() bool {
	return slices.ContainsFunc(it.Findings, func(r FindingRef) bool { return !r.Gone })
}

func (it *Item) reportedAfter(t time.Time) bool {
	return slices.ContainsFunc(it.Findings, func(r FindingRef) bool { return !r.Gone && r.LastSeen.After(t) })
}

func (t *Tracker) lifecycle(it *Item, folded map[string]*run, now time.Time, rep *SyncReport) {
	present := it.reported()
	switch it.Status {
	case Open, InProgress, Snoozed, Expected:
		if !present {
			detail := "verified (no longer reported)"
			if it.Kind == KindSetup {
				detail = "verified (status no longer reported)"
			}
			it.verifyDone(now, detail)
			rep.Verified++
		}
	case Done:
		since := it.StatusAt
		if it.VerifiedAt != nil && it.VerifiedAt.After(since) {
			since = *it.VerifiedAt
		}
		switch {
		case it.reportedAfter(since):
			it.setStatus(now, Open, EvReopened, actAutoReopen, "reported again by "+strings.Join(it.labelsPresent(), ", "))
			rep.Reopened++
		case it.VerifiedAt == nil && !present && t.ranAfter(it, folded, it.StatusAt):
			at := now.UTC()
			it.VerifiedAt = &at
			it.Log(now, EvVerified, actVerified, "verified: a run after it was marked done no longer reports it")
			rep.Verified++
		}
	}
}

func (it *Item) labelsPresent() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range it.Findings {
		if !r.Gone && !seen[r.Label()] {
			seen[r.Label()] = true
			out = append(out, r.Label())
		}
	}
	sort.Strings(out)
	return out
}

// ranAfter reports whether every connector instance of the item's findings ran after at.
func (t *Tracker) ranAfter(it *Item, folded map[string]*run, at time.Time) bool {
	for _, r := range it.Findings {
		when, ok := t.Sources[r.Label()]
		if f, in := folded[r.Label()]; in {
			when, ok = f.at, true
		}
		if !ok || !when.After(at) {
			return false
		}
	}
	return true
}

func (t *Tracker) expireAll(now time.Time, rep *SyncReport) {
	for _, it := range t.Items {
		it.expire(now, rep)
		it.derive()
	}
}

func (it *Item) expire(now time.Time, rep *SyncReport) {
	switch {
	case it.Status == Snoozed && it.snoozeOver(now):
		it.setStatus(now, Open, EvStatus, actWake, "")
		rep.Woken++
	case it.Status == Accepted && it.AcceptanceExpired(now):
		it.setStatus(now, Open, EvStatus, actAcceptLapse, "acceptance ended "+it.Accepted.Until)
		rep.Lapsed++
	}
}

func (t *Tracker) withFinding(id string) *Item { return t.findingHolders()[id] }

// findingHolders maps each finding id to the item other than a rotate item that holds it. When
// a renamed family key left two items holding it, the one that saw it last wins, open over closed.
func (t *Tracker) findingHolders() map[string]*Item {
	type holder struct {
		it   *Item
		seen time.Time
	}
	best := map[string]holder{}
	for _, it := range t.Items {
		if it.Kind == KindRotate {
			continue
		}
		for _, r := range it.Findings {
			h, ok := best[r.ID]
			if !ok || r.LastSeen.After(h.seen) || r.LastSeen.Equal(h.seen) && h.it.Closed() && !it.Closed() {
				best[r.ID] = holder{it, r.LastSeen}
			}
		}
	}
	out := make(map[string]*Item, len(best))
	for id, h := range best {
		out[id] = h.it
	}
	return out
}

// ruleKey reports whether a grouping made the key.
func ruleKey(key string) bool {
	return strings.HasPrefix(key, "group:") || strings.HasPrefix(key, "finding:")
}

// pinnedKey is the key of an item that holds one finding on its own, which wins over its grouping.
func pinnedKey(findingID string) string { return "finding:" + findingID }

// AcceptFinding keeps a finding's risk on purpose. A finding in a group moves to an item of its
// own first, so accepting one org's setting does not hide the other orgs'.
func (t *Tracker) AcceptFinding(f finding.Finding, reason, until string, now time.Time) (*Item, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, errors.New("accept needs --reason (why this risk is kept on purpose)")
	}
	it := t.withFinding(f.ID)
	theme := themeOf(f, t.Runs[finding.Label(f.Connector, f.Instance)].Theme)
	if it != nil {
		theme = it.Theme
	}
	if it != nil && len(it.Findings) > 1 && it.Key != pinnedKey(f.ID) {
		kept := it.Findings[:0]
		for _, r := range it.Findings {
			if r.ID != f.ID {
				kept = append(kept, r)
			}
		}
		it.Findings = kept
		it = nil
	}
	if it == nil {
		r := groupingFor(f)
		it = t.newItem(r.kind, pinnedKey(f.ID), theme, f.Title, now)
		it.Findings = []FindingRef{refOf(f)}
		it.Severity, it.Priority = f.Severity, priorityOf(f.Severity)
		it.Log(now, EvFound, actFound, "accepted on its own")
	}
	if err := it.accept(now, reason, until); err != nil {
		return nil, err
	}
	it.Next = acceptedNext()
	return it, nil
}

// AcceptedItems are the items with an acceptance, in force or expired.
func (t *Tracker) AcceptedItems() []*Item {
	var out []*Item
	for _, it := range t.Items {
		if it.Accepted != nil {
			out = append(out, it)
		}
	}
	return out
}

// Unaccept lifts the acceptance of the item with id ref, or whose finding id is or starts with ref.
func (t *Tracker) Unaccept(ref string, now time.Time) (*Item, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("no finding id given")
	}
	var hit *Item
	for _, it := range t.AcceptedItems() {
		exact := strings.EqualFold(it.ID, ref)
		prefix := false
		for _, r := range it.Findings {
			exact = exact || r.ID == ref
			prefix = prefix || strings.HasPrefix(r.ID, ref)
		}
		if exact {
			hit = it
			break
		}
		if prefix {
			if hit != nil {
				return nil, fmt.Errorf("%q matches several accepted findings: give more of the id", ref)
			}
			hit = it
		}
	}
	if hit == nil {
		return nil, fmt.Errorf("no accepted finding %q (see segurata accept --list)", ref)
	}
	hit.unaccept(now)
	return hit, nil
}

// Annotator sets each finding's acceptance from the tracker, so a finding from an older run gets
// today's answer.
func (t *Tracker) Annotator(now func() time.Time) func(*finding.Finding) {
	by := map[string]*Item{}
	for _, it := range t.AcceptedItems() {
		for _, r := range it.Findings {
			by[r.ID] = it
		}
	}
	return func(f *finding.Finding) {
		it := by[f.ID]
		if it == nil {
			f.Accepted = nil
			return
		}
		a := it.Accepted
		f.Accepted = &finding.Acceptance{Reason: a.Reason, AcceptedAt: a.AcceptedAt, Until: a.Until, Expired: it.AcceptanceExpired(now())}
	}
}
