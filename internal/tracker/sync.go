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

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/secretrisk"
)

// SyncOptions say which runs a sync folds in.
type SyncOptions struct {
	OutDir       string // inventory output directory; the latest run of every connector instance
	From         string // a local-secrets output to use instead of its latest run ("" for none)
	IncludeNoise bool   // track noise-only secrets too, without a priority
}

// SyncReport counts what a sync changed.
type SyncReport struct {
	Runs    []string // connector instances folded in
	Stale   []string // connector instances whose run is older than one already folded: skipped
	Secrets SecretReport
	// Items other than secrets.
	Created, Verified, Reopened int
	// Every item.
	Woken, Lapsed int
}

// run is one connector instance's latest output.
type run struct {
	label    string
	at       time.Time
	findings []finding.Finding
	statuses []finding.Status
	blocked  map[string]bool // accounts (or "" for all) with a status other than ok
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
// A finding counts as gone only when its connector instance ran and could inspect its account.
func (t *Tracker) Sync(opt SyncOptions, now time.Time) (SyncReport, error) {
	var rep SyncReport
	runs, err := readRuns(opt)
	if err != nil {
		return rep, err
	}
	folded := map[string]*run{}
	for _, r := range runs {
		if prev, ok := t.Sources[r.label]; ok && r.at.Before(prev) {
			rep.Stale = append(rep.Stale, r.label)
			continue
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
	for _, l := range rep.Runs {
		r := folded[l]
		if r.isSecrets() {
			rep.Secrets.add(t.SyncSecrets(Sightings(r.findings), now, opt.IncludeNoise))
		}
		for _, f := range r.findings {
			if ev, ok := secretEvidence(f); ok {
				if trail[ev.Kind] && secretrisk.ImpactOf(ev) != secretrisk.Noise {
					propose("transcripts:redact|"+r.label, transcriptsProposal()).add(f)
				}
				continue
			}
			if f.Severity.Rank() < finding.SevLow.Rank() {
				continue
			}
			rl := ruleFor(f)
			key, p := groupKey(f, rl)
			if _, pinned := byKey[pinnedKey(f.ID)]; pinned {
				// An item already holds this finding on its own: it stays there, titled by the finding.
				key, p.rule = pinnedKey(f.ID), &rule{kind: rl.kind}
			}
			propose(key, p).add(f)
		}
		for _, st := range r.statuses {
			if st.State != finding.StateOK {
				key, p := setupProposal(r.label, st)
				if pp := propose(key, p); len(pp.refs) == 0 {
					pp.refs = p.refs
				}
			}
		}
	}

	seen := map[*Item]map[string]bool{}
	for _, key := range order {
		p := proposals[key]
		it, existed := byKey[key]
		if !existed {
			it = t.newItem(p.kind, key, p.theme, "", now)
			byKey[key] = it
			it.Log(now, EvFound, actFound, count(len(p.refs), "finding", "findings"))
			rep.Created++
		}
		seen[it] = map[string]bool{}
		if added := it.upsert(p.refs, seen[it]); added > 0 && existed {
			it.Log(now, EvSeen, actSeen, count(added, "new finding", "new findings"))
		}
		if strings.HasPrefix(key, "transcripts:") {
			p.finishTranscripts()
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
	}

	for _, it := range t.Items {
		if it.Kind == KindRotate || len(it.Findings) == 0 {
			continue
		}
		it.markGone(seen[it], folded)
		t.lifecycle(it, folded, now, &rep)
	}
	t.expireAll(now, &rep)
	t.seed(now)
	if t.Sources == nil {
		t.Sources = map[string]time.Time{}
	}
	for l, r := range folded {
		t.Sources[l] = r.at
	}
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
	s := fmt.Sprintf("Tracker: %s folded; %d new items, %d verified done, %d reopened; %d snoozes and %d acceptances expired.\n",
		count(len(r.Runs), "run", "runs"), r.Created, r.Verified, r.Reopened, r.Woken, r.Lapsed)
	if len(r.Stale) > 0 {
		s += fmt.Sprintf("Skipped older runs than the tracker already holds: %s.\n", strings.Join(r.Stale, ", "))
	}
	return s
}

func (s *SecretReport) add(o SecretReport) {
	s.Secrets += o.Secrets
	s.Created += o.Created
	s.Updated += o.Updated
	s.Reopened += o.Reopened
	s.Skipped += o.Skipped
	s.HistoryOnly += o.HistoryOnly
}

// trail are the local-secrets location kinds `securizame redact` cleans.
var trail = map[string]bool{"transcript": true, "history": true, "log": true}

func (r *run) isSecrets() bool { return isSecretsLabel(r.label) }

func isSecretsLabel(l string) bool {
	return l == SecretsConnector || strings.HasPrefix(l, SecretsConnector+":")
}

func transcriptsProposal() proposal {
	return proposal{theme: "transcripts", kind: KindFix, connector: SecretsConnector, maxSeverity: finding.SevMedium,
		next: &Next{Who: Securizame, Command: "securizame redact --trails",
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
	p.title = fmt.Sprintf("Redact secrets from %s (agent transcripts, shell histories, logs)", count(len(files), "trail file", "trail files"))
}

// setupProposal is the setup item for a connector status other than ok.
func setupProposal(lbl string, st finding.Status) (string, proposal) {
	key := "setup:" + lbl + "|" + st.Account + "|" + string(st.State)
	sev := finding.SevMedium
	if st.State == finding.StateUnsupported || st.State == finding.StateUnverified {
		sev = finding.SevLow
	}
	who := lbl
	if st.Account != "" {
		who += " · " + st.Account
	}
	action, cmd := StatusAction(st, lbl)
	detail := st.Detail
	if detail == "" {
		detail = string(st.State)
	}
	p := proposal{theme: "setup", kind: KindSetup, connector: st.Connector, instance: st.Instance, account: st.Account,
		title: who + ": " + statePhrase[st.State], next: &Next{Who: You, Action: action, Command: cmd},
		refs: []FindingRef{{ID: "status:" + key, Connector: st.Connector, Instance: st.Instance, Account: st.Account,
			Title: detail, Severity: sev}}}
	return key, p
}

var statePhrase = map[finding.State]string{
	finding.StateReauth:             "needs a fresh sign-in",
	finding.StateSignedOut:          "is signed out",
	finding.StateNoScope:            "lacks a permission",
	finding.StateUnverified:         "reader never checked against a real page",
	finding.StateMissingCredentials: "has no credentials configured",
	finding.StateUnsupported:        "is not supported here",
	finding.StateError:              "failed",
}

// StatusAction is what to do about a status, and the command that checks it afterwards.
// Connectors usually put the exact fix in the detail (a command to run, a page to open); then the
// action points there instead of guessing from the state alone.
func StatusAction(st finding.Status, label string) (string, string) {
	rerun := "securizame inventory " + label
	if detailHasFix(st.Detail) {
		return "Do what the status detail says.", rerun
	}
	switch st.State {
	case finding.StateReauth:
		return "Sign in to this account again (in the browser for browser connectors, with the provider's CLI otherwise).", rerun
	case finding.StateSignedOut:
		return "Sign in to this account in the browser securizame drives, or drop it from the config if it is gone.", rerun
	case finding.StateMissingCredentials:
		return "Check the secret reference for " + label + " in ~/.config/securizame/config.json (Keychain item, 1Password field or environment variable).", rerun
	case finding.StateNoScope:
		return "Grant the permission the detail names to the credential this connector uses.", rerun
	case finding.StateUnsupported:
		return "Install what the detail names (respecting the 4-day quarantine), or remove " + label + " from the config.", rerun
	}
	return "Run it again with connector logs to see what failed.", rerun + " --verbose"
}

// detailHasFix reports whether a status detail already carries a concrete step.
func detailHasFix(detail string) bool {
	d := strings.ToLower(detail)
	for _, cue := range []string{"run:", "run gcloud", "run gh", "run aws", "run az", "; run ", "open http", "store it with", "raise ", "create an "} {
		if strings.Contains(d, cue) {
			return true
		}
	}
	return false
}

// RunLabel names a connector instance from its records, which carry the exact connector name and
// instance label; an empty run falls back to the file name.
func RunLabel(file string, findings []finding.Finding, statuses []finding.Status) string {
	switch {
	case len(findings) > 0:
		return label(findings[0].Connector, findings[0].Instance)
	case len(statuses) > 0:
		return label(statuses[0].Connector, statuses[0].Instance)
	}
	base := filepath.Base(file)
	return base[:len(base)-len(filepath.Ext(base))]
}

func readRuns(opt SyncOptions) ([]*run, error) {
	files, err := remediate.LatestFiles(opt.OutDir)
	if err != nil {
		if opt.From == "" {
			return nil, err
		}
		files = nil
	}
	var runs []*run
	var from *run
	if opt.From != "" {
		if from, err = readRunFile(opt.From); err != nil {
			return nil, err
		}
	}
	for _, f := range files {
		r, err := readRunFile(f)
		if err != nil {
			return nil, err
		}
		if from == nil || r.label != from.label {
			runs = append(runs, r)
		}
	}
	if from != nil {
		runs = append(runs, from)
	}
	return runs, nil
}

func readRunFile(file string) (*run, error) {
	findings, statuses, err := remediate.ReadRun(file)
	if err != nil {
		return nil, err
	}
	r := &run{label: RunLabel(file, findings, statuses), findings: findings, statuses: statuses, blocked: map[string]bool{}}
	for _, f := range findings {
		if f.ObservedAt.After(r.at) {
			r.at = f.ObservedAt
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
	for _, st := range statuses {
		if st.State != finding.StateOK {
			r.blocked[st.Account] = true
		}
	}
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

// markGone flags the refs this sync did not see, when their connector instance ran and could
// inspect their account. A status ref (setup items) is gone as soon as the run lacks that status.
func (it *Item) markGone(seen map[string]bool, folded map[string]*run) {
	for i := range it.Findings {
		r := &it.Findings[i]
		if seen[r.ID] {
			continue
		}
		run, ok := folded[r.Label()]
		if !ok {
			continue
		}
		if !strings.HasPrefix(r.ID, "status:") && (run.blocked[r.Account] || run.blocked[""]) {
			continue
		}
		r.Gone = true
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
	case Open, InProgress, Snoozed:
		if !present {
			it.setStatus(now, Done, EvVerified, actAutoDone, "verified (no longer reported)")
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
		return nil, fmt.Errorf("no accepted finding %q (see securizame accept --list)", ref)
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
