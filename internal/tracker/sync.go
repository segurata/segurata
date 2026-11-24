package tracker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

// SyncOptions say which runs a sync folds in.
type SyncOptions struct {
	OutDir       string // inventory output directory; the latest run of every connector instance
	From         string // a local-secrets output to use instead of its latest run ("" for none)
	IncludeNoise bool   // track noise-only secrets too, without a priority
	// Expect applies the config's expected rules to each status read (config.Config.Expect); nil
	// for none. Statuses are matched at every sync, so a rule added or removed since the run counts.
	Expect func(*finding.Status)
	// Owned are the owner's accounts the runs do not show (config `owned`, the git email): added to
	// the ones discovered, for attribution.
	Owned attribution.Owned
}

// SyncReport counts what a sync changed.
type SyncReport struct {
	Runs    []string // connector instances folded in
	Stale   []string // connector instances whose run is older than one already folded: skipped
	Secrets SecretReport
	// Items other than secrets.
	Created, Verified, Reopened int
	// Expected counts setup items closed (or created closed) because the config expects them.
	Expected int
	// Ruled counts items closed by a decision's rule.
	Ruled int
	// Merged counts connector items closed because a rotate item owns their secret.
	Merged int
	// Coverage counts coverage items opened (positive) and closed as covered.
	Coverage CoverageReport
	// Every item.
	Woken, Lapsed int
	// Unreadable are run files that could not be read (a torn line): skipped with their error, so
	// their connector instance counts as not run and nothing it reported closes.
	Unreadable []string
}

// run is one connector instance's latest output.
type run struct {
	label    string
	at       time.Time
	findings []finding.Finding
	statuses []finding.Status
	cov      finding.Coverage // which scopes it inspected
	failed   string           // the connector's own error, from run_end
	// fingerprints are the secrets the core resolved for the instance, by name (run_end).
	fingerprints map[string]string
}

// statusesUnproven reports, with the reason, a run whose statuses do not prove an earlier status
// gone: one without run_end (killed, still running, or older), or one whose connector failed and
// may have stopped before reporting. A finished run reports every status it has, whatever it
// inspected: completeness protects findings, not statuses.
func (r *run) statusesUnproven() (string, bool) {
	if !r.cov.Known {
		return r.cov.NoneChecked()
	}
	if r.failed != "" {
		return "the connector failed: " + r.failed, true
	}
	return "", false
}

// wholeInstance reports whether the run has a status of that state for no account in particular.
func (r *run) wholeInstance(state finding.State) bool {
	return slices.ContainsFunc(r.statuses, func(st finding.Status) bool {
		return st.Account == "" && st.Scope == "" && reported(st).State == state
	})
}

// notChecked is the history note for a finding a run did not inspect, the same for every item and
// sync that folds that run, so each item logs it once.
func (r *run) notChecked(why string) string {
	return fmt.Sprintf("not checked in run %s of %s (%s)", r.label, r.at.Format(time.RFC3339), why)
}

// Sync folds the latest run of every connector instance into the items:
//
//   - local-secrets findings into rotate items (SyncSecrets);
//   - every other finding at low or above into the item its grouping rule names, creating it
//     when new; info findings never make an item;
//   - every status other than ok into a setup item.
//
// Then the lifecycle: an open item whose findings no run reports any more is done, "verified (no
// longer reported)"; a done item is verified once a run after it was marked done no longer reports
// its findings, and reopened if a run after that reports one again; expired snoozes and
// acceptances open their items again. Accepted and ignored items only get their findings updated.
// A finding counts as gone only when its connector instance's run finished (ends with run_end) and
// inspected the finding's scope; otherwise the item keeps it and logs "not checked in run …" once
// per run instead of closing. See docs/architecture.md, "Run completeness".
func (t *Tracker) Sync(opt SyncOptions, now time.Time) (SyncReport, error) {
	var rep SyncReport
	runs, unreadable, err := readRuns(opt, now)
	if err != nil {
		return rep, err
	}
	rep.Unreadable = unreadable
	folded := map[string]*run{}
	for _, r := range runs {
		// A source after now came from a future timestamp: it counts as absent, or it would hold
		// every later run back as stale.
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
	for _, it := range t.Items {
		byKey[it.Key] = it
	}
	proposals := map[string]*proposal{}
	var order []string
	propose := func(key string, p proposal) *proposal {
		if got, ok := proposals[key]; ok {
			return got
		}
		p.key = key
		proposals[key] = &p
		order = append(order, key)
		return &p
	}
	// The owner's accounts are known before secrets are folded, so a secret attributed mine counts in
	// full from its first sync (see SyncSecrets).
	t.discover(runs)
	owned := t.OwnedAll(opt.Owned)
	for _, l := range rep.Runs {
		if r := folded[l]; r.isSecrets() {
			rep.Secrets.add(t.syncSecrets(Sightings(r.findings), now, opt.IncludeNoise, owned))
			rep.Secrets.add(t.SyncNoise(NoiseOnly(r.findings), now))
			t.markGoneLocations(r)
		}
	}
	// A connector's credential that is a rotate item's secret goes to that item, not to a group of
	// its own (see correlate.go).
	claims, possible := t.correlate(folded)
	regroup := map[string]string{} // finding id -> key of the group it moves to
	for _, l := range rep.Runs {
		r := folded[l]
		for _, f := range r.findings {
			if ev, ok := secretEvidence(f); ok {
				if trail[ev.Kind] && secretrisk.ImpactOf(ev) != secretrisk.Noise {
					propose("transcripts:redact|"+r.label, transcriptsProposal()).add(f)
				}
				continue
			}
			if _, claimed := claims[f.ID]; claimed || f.Severity.Rank() < finding.SevLow.Rank() {
				continue
			}
			rl := ruleFor(f)
			key, p := groupKey(f, rl)
			if pin, pinned := byKey[pinnedKey(f.ID)]; pinned && pin.Key != key {
				if rl.by == perFinding || pin.keptApart() {
					// An item already holds this finding on its own: it stays there, titled by the finding.
					key, p.rule = pinnedKey(f.ID), &rule{kind: rl.kind}
				} else {
					// Its rule groups it now (data dumps per repository): it moves to the group.
					regroup[f.ID] = key
				}
			}
			propose(key, p).add(f)
		}
		for _, st := range r.statuses {
			if st.State != finding.StateOK {
				key, p := setupProposal(r.label, st)
				propose(key, p).addStatus(st, r.at)
			}
		}
	}

	seen := map[*Item]map[string]bool{}
	for _, key := range order {
		p := proposals[key]
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
	t.Attribute(owned)
	rep.Ruled = t.applyRules(now)
	t.noteBlocked(now)
	t.seed(now)
	if t.Sources == nil {
		t.Sources = map[string]time.Time{}
	}
	for l, r := range folded {
		t.Sources[l] = r.at
	}
	t.recordRuns(folded)
	rep.Coverage = t.syncCoverage(folded, now)
	at := now.UTC()
	t.LastSyncAt = &at
	return rep, nil
}

// FoldedSecrets reports whether a local-secrets run was folded in.
func (r SyncReport) FoldedSecrets() bool {
	for _, l := range r.Runs {
		if isSecretsLabel(l) {
			return true
		}
	}
	return false
}

// SyncLine is the one-line summary of what a sync did to items other than secrets.
func SyncLine(r SyncReport) string {
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
}

// trail are the local-secrets location kinds `segurata redact` cleans.
var trail = map[string]bool{"transcript": true, "history": true, "log": true}

func (r *run) isSecrets() bool { return isSecretsLabel(r.label) }

func isSecretsLabel(l string) bool {
	return l == SecretsConnector || strings.HasPrefix(l, SecretsConnector+":")
}

func transcriptsProposal() proposal {
	return proposal{theme: "transcripts", kind: KindFix, connector: SecretsConnector, maxSeverity: finding.SevMedium,
		next: &Next{Who: Segurata, Command: "segurata redact --trails",
			Action: "Review the dry run, then run it again with --apply. Rotation is still needed: these copies already reached the model provider or wherever the trail went."}}
}

// finishTranscripts names the trail item by the files it covers.
func (p *proposal) finishTranscripts() {
	files := map[string]bool{}
	for _, f := range p.findings {
		if ev, ok := secretEvidence(f); ok {
			files[ev.Path] = true
		}
	}
	p.title = fmt.Sprintf("Redact secrets from %s (agent transcripts, shell histories, logs)", textfmt.Count(len(files), "trail file", "trail files"))
}

// RunLabel names a connector instance from its records, which carry the exact connector name and
// instance label; a run with none falls back to the file name.
func RunLabel(file string, rf remediate.RunFile) string {
	switch {
	case rf.End != nil:
		return label(rf.End.Connector, rf.End.Instance)
	case len(rf.Findings) > 0:
		return label(rf.Findings[0].Connector, rf.Findings[0].Instance)
	case len(rf.Statuses) > 0:
		return label(rf.Statuses[0].Connector, rf.Statuses[0].Instance)
	}
	base := filepath.Base(file)
	return base[:len(base)-len(filepath.Ext(base))]
}

// readRuns reads the latest run of every connector instance as of now, and opt.From. A latest run that
// cannot be read is left out and returned with its error in unreadable: one torn file must not
// stop the sync of every other connector, and an instance with no run folded closes nothing.
func readRuns(opt SyncOptions, now time.Time) (runs []*run, unreadable []string, err error) {
	files, err := remediate.LatestFiles(opt.OutDir, now)
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
	rf, err := remediate.ReadRun(file)
	if err != nil {
		return nil, err
	}
	r := &run{label: RunLabel(file, rf), findings: rf.Findings, statuses: rf.Statuses, cov: rf.Coverage()}
	// A finished run's time is when it ended. A file without run_end falls back to its newest
	// observed_at that is not in the future, then to its modification time.
	if rf.End != nil {
		r.at, r.failed, r.fingerprints = rf.End.EndedAt, rf.End.Error, rf.End.SecretFingerprints
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

// upsert adds or refreshes refs and returns how many were new to the item.
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

// markGone flags the refs this sync did not see, when their connector instance's run inspected
// their scope; it returns, by ref id, the "not checked" note of each ref it held back instead. A
// status ref (setup items) is gone as soon as a finished run (run_end, no connector error) lacks
// that status, whatever that run inspected (an aws error replaced by noscope, a reauth no longer
// emitted); even in an unfinished run when it reports the item's key with other details (the
// details changed, or the ref predates one ref per detail), or the same state for the whole
// instance (no account), which covers it: the core's one missing_credentials status replaces the
// one a connector used to emit per account.
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
		why, unchecked := run.cov.Unchecked(r.Account, r.Scope)
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

// noteHeld logs, once per run, why an item that would have closed or been verified did not: every
// finding still counted as reported belongs to a scope its latest run did not inspect.
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
			return // something inspected still reports it: nothing was held back
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

// reported reports whether any of the item's findings is not gone.
func (it *Item) reported() bool {
	return slices.ContainsFunc(it.Findings, func(r FindingRef) bool { return !r.Gone })
}

// reportedAfter reports whether a finding that is not gone was last seen after t.
func (it *Item) reportedAfter(t time.Time) bool {
	return slices.ContainsFunc(it.Findings, func(r FindingRef) bool { return !r.Gone && r.LastSeen.After(t) })
}

// lifecycle moves an item with findings on after its refs were updated.
func (t *Tracker) lifecycle(it *Item, folded map[string]*run, now time.Time, rep *SyncReport) {
	present := it.reported()
	switch it.Status {
	case Open, InProgress, Snoozed, Expected:
		if !present {
			detail := "verified (no longer reported)"
			if it.Kind == KindSetup {
				detail = "verified (status no longer reported)"
			}
			it.setStatus(now, Done, EvVerified, actAutoDone, detail)
			at := now.UTC()
			it.VerifiedAt = &at
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

// ranAfter reports whether every connector instance the item's findings come from has a run
// after t.
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

// expireAll opens the items whose snooze or acceptance is over and recomputes what each item's
// own data determines.
func (t *Tracker) expireAll(now time.Time, rep *SyncReport) {
	for _, it := range t.Items {
		it.expire(now, rep)
		it.derive()
	}
}

// expire opens an item whose snooze or acceptance is over.
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

// derive recomputes what an item's own data determines; for a rotate item, everything its
// locations decide. Other items get title, severity and priority from sync.
func (it *Item) derive() {
	if it.Secret != nil {
		it.refreshSecret()
	}
}

// withFinding returns the item (not a rotate item) that links the finding, or nil.
func (t *Tracker) withFinding(id string) *Item {
	for _, it := range t.Items {
		if it.Kind == KindRotate {
			continue
		}
		for _, r := range it.Findings {
			if r.ID == id {
				return it
			}
		}
	}
	return nil
}

// pinnedKey is the key of an item that holds one finding on its own (a finding grouped nowhere
// else, or accepted apart from its group): sync attaches that finding to it before any grouping.
func pinnedKey(findingID string) string { return "finding:" + findingID }

// AcceptFinding keeps a finding's risk on purpose. When its item groups other findings too, the
// finding moves to an item of its own first, so accepting one org's setting does not hide the
// other orgs'.
func (t *Tracker) AcceptFinding(f finding.Finding, reason, until string, now time.Time) (*Item, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, errors.New("accept needs --reason (why this risk is kept on purpose)")
	}
	it := t.withFinding(f.ID)
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
		r := ruleFor(f)
		it = t.newItem(r.kind, pinnedKey(f.ID), themeOf(f.Connector, f.Resource.Type), f.Title, now)
		it.Findings = []FindingRef{refOf(f)}
		it.Severity, it.Priority = f.Severity, priorityOf(f.Severity)
		it.Log(now, EvFound, actFound, "accepted on its own")
	}
	if err := it.Accept(now, reason, until); err != nil {
		return nil, err
	}
	it.Next = acceptedNext()
	return it, nil
}

// AcceptedItems are the items that carry an acceptance, in force or expired.
func (t *Tracker) AcceptedItems() []*Item {
	var out []*Item
	for _, it := range t.Items {
		if it.Accepted != nil {
			out = append(out, it)
		}
	}
	return out
}

// Unaccept lifts the acceptance of the item with that id, or of the one whose finding id is, or
// starts with, ref.
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
	hit.Unaccept(now)
	return hit, nil
}

// Annotator sets each finding's acceptance from the tracker, replacing whatever it carried, so a
// finding loaded from an older run gets today's answer.
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
