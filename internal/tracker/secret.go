package tracker

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/docref"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

// StillPresent is why a rotated secret seen again in a working file reopens.
const StillPresent = "still present after rotation (old value still in a working file)"

const historyOnly = "old value still in history/transcripts; harmless after revocation — purge if you like: see " + docref.Docs + "secrets.md#after-a-rotation"

// Location is one place the secret was found.
type Location struct {
	Path     string    `json:"path"`
	Line     int       `json:"line,omitempty"`
	Bucket   string    `json:"bucket"`
	Tracked  bool      `json:"tracked"`
	Mode     string    `json:"mode,omitempty"`
	Source   string    `json:"source"` // scan | gitleaks | name | ssh
	Kind     string    `json:"kind"`   // config | repo | transcript | history | log
	Remote   bool      `json:"remote,omitempty"`
	Repo     string    `json:"repo,omitempty"`   // git history: the repository
	Date     string    `json:"date,omitempty"`   // git history: first commit seen, YYYY-MM-DD
	Origin   string    `json:"origin,omitempty"` // whose repository (secretrisk.Origin*)
	Reused   bool      `json:"reused,omitempty"` // a third-party copy of a value the owner also holds
	LastSeen time.Time `json:"last_seen"`
	// Gone marks a working file a finished run read without the secret: kept for the record, left
	// out of current. Records of the past are never gone.
	Gone bool `json:"gone,omitempty"`
}

func (l Location) key() string { return l.Source + "\x00" + l.Path }

// ref names the location in rotated_locations.
func (l Location) ref() string { return l.Source + ":" + l.Path }

// working reports whether a consumer reads the secret from here. Git history, transcripts, logs
// and shell history are records of the past, dead once the value is revoked.
func (l Location) working() bool {
	return l.Source != "gitleaks" && (l.Kind == "config" || l.Kind == "repo")
}

// Spot is how exposed this location left the secret; a copy in someone else's repository exposes
// the upstream's secret.
func (l Location) Spot() secretrisk.Spot {
	if s, ok := secretrisk.UpstreamSpot(l.Origin, l.Reused); ok {
		return s
	}
	return secretrisk.Where(l.Kind, l.Mode, l.Tracked, l.Remote)
}

// Where is path:line, or the path.
func (l Location) Where() string {
	if l.Line > 0 {
		return fmt.Sprintf("%s:%d", l.Path, l.Line)
	}
	return l.Path
}

// Secret is what a rotate item knows about its secret: never the value, only a redacted hint.
type Secret struct {
	ID               string               `json:"id"` // shortest unique fingerprint prefix, from 8 characters
	Service          string               `json:"service"`
	Type             string               `json:"type"`
	Redacted         string               `json:"redacted"`
	Impact           string               `json:"impact"`
	Reasons          []string             `json:"reasons"`
	FirstSeen        time.Time            `json:"first_seen"`
	LastSeen         time.Time            `json:"last_seen"`
	Locations        []Location           `json:"locations"`
	UsedIn           []string             `json:"used_in"`
	RotateURL        string               `json:"rotate_url,omitempty"`
	RotatedLocations []string             `json:"rotated_locations,omitempty"` // known when marked done
	Attribution      *attribution.Result  `json:"attribution,omitempty"`
	Liveness         *secretrisk.Liveness `json:"liveness,omitempty"` // the provider's newest answer
	// Pair is the fingerprint of the other half of an AWS key pair; KeyID, on a secret access key,
	// the hint of the key id folded into its item.
	Pair  string `json:"pair,omitempty"`
	KeyID string `json:"key_id,omitempty"`
}

// Sighting is one finding of a secret.
type Sighting struct {
	Evidence secretrisk.Evidence
	Seen     time.Time
}

func sightingsOf(fs []finding.Finding) []Sighting {
	var out []Sighting
	for _, f := range fs {
		if ev, ok := secretEvidence(f); ok {
			out = append(out, Sighting{Evidence: ev, Seen: f.ObservedAt})
		}
	}
	return out
}

func secretEvidence(f finding.Finding) (secretrisk.Evidence, bool) {
	if f.Connector != secretrisk.ConnectorName {
		return secretrisk.Evidence{}, false
	}
	return secretrisk.EvidenceOf(f)
}

// SecretReport counts what folding secret sightings changed.
type SecretReport struct {
	Secrets, Created, Updated, Reopened, Skipped int
	Reclassified                                 int // every current sighting is now noise
	HistoryOnly                                  int // rotated, seen again only in records of the past
	Paired                                       int // AWS key ids folded into their secret key's item
}

// SyncSecrets folds sightings into rotate items, attributed with what the tracker knows of
// ownership plus extra. A noise-only secret is skipped unless includeNoise, and its existing item
// reclassified. Items not seen keep their locations: git history does not forget, and a transcript
// copy already reached the model provider.
func (t *Tracker) SyncSecrets(sightings []Sighting, now time.Time, includeNoise bool, extra attribution.Owned) SecretReport {
	owned := t.ownedAll(extra)
	groups := map[string][]Sighting{}
	var order []string
	for _, s := range sightings {
		fp := s.Evidence.Fingerprint
		if _, ok := groups[fp]; !ok {
			order = append(order, fp)
		}
		groups[fp] = append(groups[fp], s)
	}
	var rep SecretReport
	existing := t.byFingerprint()
	for _, fp := range order {
		g := groups[fp]
		it, ok := existing[fp]
		mineAfterAll(it, g, owned)
		best := bestSighting(g)
		impact := secretrisk.ImpactOf(best.Evidence)
		noise := impact == secretrisk.Noise && !includeNoise
		if noise && !ok {
			rep.Skipped++
			continue
		}
		seen := latest(g, now)
		if !noise {
			rep.Secrets++
		}
		if !ok {
			it = t.newItem(KindRotate, "rotate:"+fp, "rotations", "", now)
			it.Fingerprint = fp
			it.Secret = &Secret{ID: t.newSecretID(fp), FirstSeen: seen.UTC()}
			existing[fp] = it
			it.Log(now, EvFound, actFound, fmt.Sprintf("found in %d %s", len(g), textfmt.Plural(len(g), "place", "places")))
			rep.Created++
		} else if !noise {
			rep.Updated++
		}
		s := it.Secret
		// From the best current sighting, so a corrected rule can lower it as well as raise it.
		s.Type, s.Redacted, s.Impact = best.Evidence.Type, best.Evidence.Redacted, impact.String()
		s.LastSeen = seen.UTC()
		s.updateLiveness(g, now)
		for _, x := range g {
			it.merge(x.Evidence, seen)
		}
		if pair := newestPair(g); pair != "" {
			s.Pair = pair
		}
		switch {
		case noise:
			if it.reclassify(now, best.Evidence.Type) {
				rep.Reclassified++
			}
		case it.Status == Reclassified:
			if it.unreclassify(now) {
				rep.Reopened++
			}
		case it.Status == Done:
			it.rotatedSeen(g, now, &rep)
		}
		it.derive()
	}
	rep.Paired = foldPairs(existing, now)
	return rep
}

func newestPair(g []Sighting) string {
	pair, at := "", time.Time{}
	for _, x := range g {
		if x.Evidence.Pair != "" && !x.Seen.Before(at) {
			pair, at = x.Evidence.Pair, x.Seen
		}
	}
	return pair
}

// foldPairs merges each AWS key id's item into its secret access key's, since deactivating the key
// closes both, and returns how many it merged. A key id whose secret key has no item or is noise
// stays on its own.
func foldPairs(byFP map[string]*Item, now time.Time) int {
	merged := 0
	keyIDs := map[*Item]string{}
	for _, fp := range slices.Sorted(maps.Keys(byFP)) {
		it := byFP[fp]
		s := it.Secret
		if s == nil || s.Type != "aws-access-key-id" || s.Pair == "" {
			continue
		}
		into, ok := byFP[s.Pair]
		standing := ok && into.Secret != nil && into.Status != Reclassified
		if it.Status == Merged && (!standing || it.MergedInto != into.ID) {
			it.reopenMerged(now)
		}
		if !standing {
			continue
		}
		keyIDs[into] = s.Redacted
		if it.mergeInto(into.ID, now, "merged into "+into.ID+", its secret access key: deactivating the key closes both") {
			merged++
		}
	}
	for _, it := range byFP {
		if it.Secret != nil && it.Secret.KeyID != keyIDs[it] {
			it.Secret.KeyID = keyIDs[it]
			it.derive()
		}
	}
	return merged
}

// mineAfterAll marks Reused the copies in someone else's repository of a secret attributed mine:
// it is the owner's secret leaked there, never noise for where it sits.
func mineAfterAll(it *Item, g []Sighting, owned attribution.Owned) {
	var facts attribution.Facts
	if it != nil && it.Secret != nil && it.Secret.Attribution != nil {
		facts = it.Secret.Attribution.Facts.Clone()
	}
	upstream := false
	for _, s := range g {
		facts.Add(s.Evidence.Claims)
		if l := s.Evidence.Liveness; l != nil {
			facts.Add(attribution.FromAccount(l.Account))
		}
		upstream = upstream || secretrisk.NotOwners(s.Evidence.Origin, s.Evidence.Reused)
	}
	if !upstream || attribution.Attribute(facts, owned).Owner != attribution.Mine {
		return
	}
	for i := range g {
		if secretrisk.NotOwners(g[i].Evidence.Origin, g[i].Evidence.Reused) {
			g[i].Evidence.Reused = true
		}
	}
}

// noiseOnly reads a local-secrets run's noise summary: the type of each noise-only fingerprint,
// which the connector emits instead of the noise findings.
func noiseOnly(fs []finding.Finding) map[string]string {
	for _, f := range fs {
		if f.Connector != secretrisk.ConnectorName || f.Resource.Type != secretrisk.NoiseSummaryType {
			continue
		}
		raw, _ := json.Marshal(f.Evidence[secretrisk.NoiseFingerprints])
		var m map[string]string
		if json.Unmarshal(raw, &m) == nil {
			return m
		}
	}
	return nil
}

// syncNoise reclassifies the items a noise summary names; it never creates one. An item attributed
// mine with an upstream copy stays: that copy is noise only for where it sits.
func (t *Tracker) syncNoise(noise map[string]string, now time.Time) SecretReport {
	var rep SecretReport
	if len(noise) == 0 {
		return rep
	}
	for fp, it := range t.byFingerprint() {
		typ, ok := noise[fp]
		if !ok || it.Owner() == attribution.Mine && it.upstreamCopy() {
			continue
		}
		it.Secret.Impact = secretrisk.Noise.String()
		if it.reclassify(now, typ) {
			rep.Reclassified++
		}
		it.derive()
	}
	return rep
}

// reclassify closes an item whose every sighting is noise, and reports whether it did. Done and
// accepted items stay settled; an ignored one keeps its reason in the event, so "ignored" counts
// only real secrets.
func (it *Item) reclassify(now time.Time, typ string) bool {
	switch it.Status {
	case Open, InProgress, Snoozed, Ignored:
	default:
		return false
	}
	detail := "every current sighting is noise (" + typ + ")"
	if it.Status == Ignored {
		detail = wasIgnored + it.lastDetail(actIgnore) + "; " + detail
	}
	it.setStatus(now, Reclassified, EvReclassified, actReclassify, detail)
	return true
}

const wasIgnored = "was ignored: "

// unreclassify puts back an item no longer noise: ignored again if it was, else open; it reports
// whether it reopened.
func (it *Item) unreclassify(now time.Time) bool {
	if prev, ok := strings.CutPrefix(it.lastDetail(actReclassify), wasIgnored); ok {
		reason, _, _ := strings.Cut(prev, "; every current sighting is noise")
		it.setStatus(now, Ignored, EvStatus, actIgnore, reason)
		return false
	}
	it.setStatus(now, Open, EvReopened, actAutoReopen, "a current sighting is no longer noise")
	return true
}

func (it *Item) lastDetail(action string) string {
	if i := it.latestIndex(action); i >= 0 {
		return it.History[i].Detail
	}
	return ""
}

func (it *Item) latestOf(actions ...string) string {
	if i := it.latestIndex(actions...); i >= 0 {
		return it.History[i].Action
	}
	return ""
}

func (it *Item) latestIndex(actions ...string) int {
	for i, e := range slices.Backward(it.History) {
		if slices.Contains(actions, e.Action) {
			return i
		}
	}
	return -1
}

// rotatedSeen reopens a done item seen again in a working file, which the new value never reached.
// Once revoked, copies in records of the past are harmless: noted once per rotation.
func (it *Item) rotatedSeen(g []Sighting, now time.Time, rep *SecretReport) {
	known := map[string]bool{}
	for _, r := range it.Secret.RotatedLocations {
		known[r] = true
	}
	var still, fresh []string
	for _, s := range g {
		loc := locationOf(s.Evidence, now)
		switch {
		case !loc.working():
		case known[loc.ref()]:
			still = append(still, loc.Path)
		default:
			fresh = append(fresh, loc.Path)
		}
	}
	if len(still)+len(fresh) == 0 {
		if !it.notedHistoryOnly() {
			it.Log(now, EvNote, actHistory, historyOnly)
			rep.HistoryOnly++
		}
		return
	}
	var parts []string
	if len(still) > 0 {
		parts = append(parts, "still in "+strings.Join(still, ", "))
	}
	if len(fresh) > 0 {
		parts = append(parts, "new working location "+strings.Join(fresh, ", "))
	}
	it.Secret.RotatedLocations = nil
	it.setStatus(now, Open, EvReopened, actAutoReopen, StillPresent+": "+strings.Join(parts, "; "))
	rep.Reopened++
}

// markGoneLocations flags the working locations a local-secrets run read without reporting the
// secret. A skipped file or a noise-only secret proves nothing.
func (t *Tracker) markGoneLocations(r *run) {
	if _, unchecked := r.cov.Unchecked("", secretrisk.FilesScope); unchecked {
		return
	}
	seen := map[string]bool{}
	for _, s := range sightingsOf(r.findings) {
		seen[s.Evidence.Fingerprint+"\x00"+locationOf(s.Evidence, time.Time{}).key()] = true
	}
	noise := noiseOnly(r.findings)
	for fp, it := range t.byFingerprint() {
		if _, isNoise := noise[fp]; isNoise {
			continue
		}
		for i := range it.Secret.Locations {
			l := &it.Secret.Locations[i]
			if _, unchecked := r.cov.UncheckedPath("", secretrisk.FilesScope, l.Path); l.working() && !unchecked && !seen[fp+"\x00"+l.key()] {
				l.Gone = true
			}
		}
	}
}

// current are the locations not gone, or all of them when every one is: the item keeps its
// exposure until it is settled.
func (it *Item) current() []Location {
	var out []Location
	for _, l := range it.Secret.Locations {
		if !l.Gone {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return it.Secret.Locations
	}
	return out
}

// NoteRedaction records a `segurata redact`. The locations stay: the copies already left.
func (it *Item) NoteRedaction(at time.Time, files int) {
	it.Log(at, EvNote, actRedacted, fmt.Sprintf("redacted from %d trail %s", files, textfmt.Plural(files, "file", "files")))
}

func latest(g []Sighting, now time.Time) time.Time {
	var t time.Time
	for _, s := range g {
		if s.Seen.After(t) {
			t = s.Seen
		}
	}
	if t.IsZero() {
		return now
	}
	return t
}

// vague services say what a secret looks like, not whose it is.
var vague = map[string]bool{"private-key": true, "unknown": true, "oauth": true, "url": true, "generic": true}

// bestSighting picks the sighting that names the secret best: impact, then a catalog type, a
// provider over a shape, a working file over git history.
func bestSighting(g []Sighting) Sighting {
	best := g[0]
	score := func(s Sighting) int {
		ev := s.Evidence
		sc := int(secretrisk.ImpactOf(ev)) * 100
		if t, known := secretrisk.Known(ev.Type); known {
			sc += 10
			if !vague[t.Service] {
				sc += 5
			}
		}
		if ev.Source != "gitleaks" {
			sc++
		}
		return sc
	}
	for _, s := range g[1:] {
		if score(s) > score(best) {
			best = s
		}
	}
	return best
}

func locationOf(ev secretrisk.Evidence, seen time.Time) Location {
	return Location{Path: ev.Path, Line: ev.Line, Bucket: ev.Bucket, Tracked: ev.Tracked, Mode: ev.Mode,
		Source: ev.Source, Kind: ev.Kind, Remote: ev.Remote, Repo: ev.Repo, Date: ev.Date, Origin: ev.Origin,
		Reused: ev.Reused, LastSeen: seen.UTC()}
}

func (it *Item) merge(ev secretrisk.Evidence, seen time.Time) {
	s := it.Secret
	loc := locationOf(ev, seen)
	for i := range s.Locations {
		if s.Locations[i].key() == loc.key() {
			s.Locations[i] = loc
			return
		}
	}
	s.Locations = append(s.Locations, loc)
	sort.Slice(s.Locations, func(i, j int) bool { return s.Locations[i].key() < s.Locations[j].key() })
}

func (t *Tracker) byFingerprint() map[string]*Item {
	m := map[string]*Item{}
	for _, it := range t.Items {
		if it.Kind == KindRotate {
			m[it.Fingerprint] = it
		}
	}
	return m
}

// newSecretID is the shortest unused prefix of the fingerprint, from 8 characters.
func (t *Tracker) newSecretID(fp string) string {
	used := map[string]bool{}
	for _, it := range t.Items {
		if it.Secret != nil {
			used[it.Secret.ID] = true
		}
	}
	for n := 8; n < len(fp); n++ {
		if !used[fp[:n]] {
			return fp[:n]
		}
	}
	return fp
}

func (it *Item) worst() secretrisk.Spot {
	s, _ := it.worstSpot()
	return s
}

func (it *Item) worstSpot() (secretrisk.Spot, bool) {
	var best secretrisk.Spot
	found := false
	if it.Secret == nil {
		return best, false
	}
	for _, l := range it.current() {
		s := l.Spot()
		if !found || spotRank(s) > spotRank(best) {
			best, found = s, true
		}
	}
	return best, found
}

// spotOrder breaks ties within an exposure level; copies in other people's repositories rank last.
var spotOrder = map[string]int{"git+remote": 7, "transcript": 6, "git": 5, "readable": 4, "history": 3, "log": 2, "local": 1,
	secretrisk.OriginThirdParty: 0, secretrisk.OriginForkUpstream: 0}

func spotRank(s secretrisk.Spot) int { return int(s.Level)*10 + spotOrder[s.Label] }

// SpotRank orders locations for listings: higher is worse.
func SpotRank(l Location) int { return spotRank(l.Spot()) }

// WorstLabel is the short label of the worst exposure.
func (it *Item) WorstLabel() string { return it.worst().Label }

func impactByName(name string) secretrisk.Impact {
	for i := secretrisk.Noise; i <= secretrisk.High; i++ {
		if i.String() == name {
			return i
		}
	}
	return secretrisk.Medium
}

// derive recomputes what a rotate item's locations decide: priority, severity, reasons, used_in,
// rotate_url, title and next step. Other items get those from sync.
func (it *Item) derive() {
	s := it.Secret
	if s == nil {
		return
	}
	t := secretrisk.TypeFor(s.Type, s.Redacted)
	s.Service, s.RotateURL = t.Service, t.RotateURL
	worst, located := it.worstSpot()
	live := it.live()
	it.Priority = it.secretPriority(worst, located, live)
	it.Severity = secretrisk.SeverityOf(it.Priority) // info for noise
	s.Reasons = it.secretReasons(t, worst, located, live)
	s.UsedIn = it.usedIn()
	it.secretTitleAndNext()
}

// secretPriority is the worst location's priority, raised by connectors that report the secret
// live, P0 for a live key that left the machine.
func (it *Item) secretPriority(worst secretrisk.Spot, located bool, live []FindingRef) secretrisk.Priority {
	if it.liveAndLeaked() {
		return secretrisk.P0
	}
	var p secretrisk.Priority
	if located {
		p = secretrisk.PriorityOf(impactByName(it.Secret.Impact), worst.Level)
	}
	for _, r := range live {
		if lp := priorityOf(r.Severity); lp != "" && lp.Rank() < p.Rank() {
			p = lp
		}
	}
	if it.livenessIs(secretrisk.Unregistered) && len(live) == 0 {
		p = p.Lower()
	}
	return p
}

func (it *Item) secretReasons(t secretrisk.Type, worst secretrisk.Spot, located bool, live []FindingRef) []string {
	var reasons []string
	if it.liveAndLeaked() {
		if primary, ok := it.primaryLocation(); ok {
			reasons = append(reasons, "live key, leaked in "+primary.name())
		}
	}
	if it.reopenedStillPresent() {
		reasons = append(reasons, StillPresent)
	}
	for _, r := range live {
		reasons = append(reasons, "live: "+r.Label()+": "+r.Title)
	}
	if r := it.livenessReason(); r != "" {
		reasons = append(reasons, r)
	}
	for _, r := range it.Possible {
		reasons = append(reasons, "possibly: "+r.Label()+": "+r.Title)
	}
	if located {
		reasons = append(reasons, secretrisk.Reason(t, worst))
		reasons = append(reasons, it.alsoReasons(worst)...)
	}
	if it.Owner() == attribution.Mine && it.upstreamCopy() {
		reasons = append(reasons, "yours by attribution ("+it.Secret.Attribution.Reasons[0]+"), so its copies in other people's repositories count in full")
	}
	return reasons
}

// alsoReasons count the other current locations by spot: "also in shell history (2 places)".
func (it *Item) alsoReasons(worst secretrisk.Spot) []string {
	counts := map[string]int{}
	phrase := map[string]string{}
	for _, l := range it.current() {
		sp := l.Spot()
		counts[sp.Label]++
		phrase[sp.Label] = sp.Phrase
	}
	counts[worst.Label]--
	labels := slices.Collect(maps.Keys(counts))
	slices.SortFunc(labels, func(a, b string) int { return cmp.Or(spotOrder[b]-spotOrder[a], strings.Compare(a, b)) })
	var out []string
	for _, lb := range labels {
		if n := counts[lb]; n > 0 {
			out = append(out, fmt.Sprintf("also %s (%d %s)", phrase[lb], n, textfmt.Plural(n, "place", "places")))
		}
	}
	return out
}

func (it *Item) usedIn() []string {
	out := []string{}
	for _, l := range it.Secret.Locations {
		if l.working() && !l.Gone && !slices.Contains(out, l.Path) {
			out = append(out, l.Path)
		}
	}
	sort.Strings(out)
	return out
}

func (it *Item) secretTitleAndNext() {
	s := it.Secret
	it.Title = it.secretTitle()
	where := "in the provider's console"
	if s.RotateURL != "" {
		where = "at " + s.RotateURL
	}
	n := &Next{Who: You, URL: s.RotateURL, Command: "segurata rotations done " + s.ID}
	_, single := secretrisk.ParseHint(s.Redacted)
	switch {
	case len(s.UsedIn) == 0:
		n.Action = "Rotate it " + where + ", then mark it done (no working file holds it)."
	case !single:
		n.Action = fmt.Sprintf("Rotate it %s, put the new value in %s by hand, then mark it done.", where, textfmt.Count(len(s.UsedIn), "file", "files"))
	default:
		n.Action = fmt.Sprintf("Rotate it %s and copy the new value; segurata puts it in %s.", where, textfmt.Count(len(s.UsedIn), "file", "files"))
		n.Command = "segurata rotations replace " + s.ID
	}
	it.Next = n
}

// secretTitle is `<label> <hint> = "<key name>" (in use, $42.00 this month) in <repo>:<file>
// (+N places), committed YYYY-MM`.
func (it *Item) secretTitle() string {
	s := it.Secret
	title := secretrisk.TypeFor(s.Type, s.Redacted).Label
	if _, single := secretrisk.ParseHint(s.Redacted); single {
		title += " " + s.Redacted
	}
	if s.KeyID != "" {
		title += " (key id " + s.KeyID + ")"
	}
	title += it.keyFacts()
	primary, ok := it.primaryLocation()
	if !ok {
		return title
	}
	title += " in " + primary.name()
	if n := len(it.current()) - 1; n > 0 {
		title += fmt.Sprintf(" (+%d %s)", n, textfmt.Plural(n, "place", "places"))
	}
	if d := it.firstCommitted(); d != "" {
		title += ", committed " + d[:7]
	}
	return title
}

// keyFacts is ` = "Claude Code" (in use, $42.00 this month)` from the surest live ref with key
// facts, or "".
func (it *Item) keyFacts() string {
	var best *FindingRef
	for _, r := range it.live() {
		if r.Key != nil && r.Key.Name != "" && (best == nil || confRank[r.Confidence] > confRank[best.Confidence]) {
			best = &r
		}
	}
	if best == nil {
		return ""
	}
	k := best.Key
	var facts []string
	switch {
	case k.LastUsed != nil && best.LastSeen.Sub(*k.LastUsed) <= finding.IdleAfter:
		facts = append(facts, "in use")
	case k.LastUsed != nil:
		facts = append(facts, "last used "+k.LastUsed.Format(time.DateOnly))
	}
	if k.SpendMonthUSD != nil && *k.SpendMonthUSD > 0 {
		facts = append(facts, textfmt.USD(*k.SpendMonthUSD)+" this month")
	}
	out := fmt.Sprintf(" = %q", k.Name)
	if len(facts) > 0 {
		out += " (" + strings.Join(facts, ", ") + ")"
	}
	return out
}

// primaryLocation is the worst exposed location; among equals, the owner's repository, then the
// most recent commit, then the path.
func (it *Item) primaryLocation() (Location, bool) {
	locs := it.current()
	if len(locs) == 0 {
		return Location{}, false
	}
	best := locs[0]
	for _, l := range locs[1:] {
		if r, br := spotRank(l.Spot()), spotRank(best.Spot()); r != br {
			if r > br {
				best = l
			}
			continue
		}
		if lo, bo := l.Origin == secretrisk.OriginOwned, best.Origin == secretrisk.OriginOwned; lo != bo {
			if lo {
				best = l
			}
			continue
		}
		if l.Date != best.Date {
			if l.Date > best.Date {
				best = l
			}
			continue
		}
		if l.Path < best.Path {
			best = l
		}
	}
	return best, true
}

// name is <repo>:<file> for git history, else the path.
func (l Location) name() string {
	if l.Repo != "" && strings.HasPrefix(l.Path, l.Repo+"/") {
		return strings.TrimPrefix(l.Repo, "~/src/") + ":" + strings.TrimPrefix(l.Path, l.Repo+"/")
	}
	return l.Path
}

func (it *Item) firstCommitted() string {
	first := ""
	for _, l := range it.Secret.Locations {
		if len(l.Date) >= 7 && (first == "" || l.Date < first) {
			first = l.Date
		}
	}
	return first
}

func (it *Item) lastCommitted() string {
	last := ""
	for _, l := range it.Secret.Locations {
		if l.Date > last {
			last = l.Date
		}
	}
	return last
}

func (it *Item) upstreamCopy() bool {
	return slices.ContainsFunc(it.Secret.Locations, func(l Location) bool {
		return l.Origin == secretrisk.OriginThirdParty || l.Origin == secretrisk.OriginForkUpstream
	})
}

func (it *Item) owned() bool {
	return slices.ContainsFunc(it.Secret.Locations, func(l Location) bool { return l.Origin == secretrisk.OriginOwned })
}

func (it *Item) reopenedStillPresent() bool {
	return it.Status != Done && it.latestOf(actAutoReopen, actDone, actReopen) == actAutoReopen
}

func (it *Item) notedHistoryOnly() bool { return it.latestOf(actHistory, actDone) == actHistory }
