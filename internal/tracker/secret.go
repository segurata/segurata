package tracker

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

// Rotate items: one per secret fingerprint, fed by local-secrets findings. This is the former
// rotation ledger; `segurata rotations` is its command family. The risk model it shares with
// the connector lives in internal/secretrisk, so a finding's severity and an item's priority never
// disagree. See docs/architecture.md, "Rotation ledger".

// SecretsConnector is the connector whose findings feed rotate items.
const SecretsConnector = "local-secrets"

// StillPresent is the reason given when a rotated secret shows up again, with the same value, in a
// working file: somewhere a consumer still reads it.
const StillPresent = "still present after rotation (old value still in a working file)"

// HistoryOnly is noted once when a rotated secret is seen again only where nothing reads it.
const HistoryOnly = "old value still in history/transcripts; harmless after revocation — purge if you like: see docs/secrets.md#after-a-rotation"

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
	Date     string    `json:"date,omitempty"`   // git history: date of the first commit seen, YYYY-MM-DD
	Origin   string    `json:"origin,omitempty"` // whose repository: secretrisk.OriginOwned, OriginThirdParty, OriginForkUpstream
	Reused   bool      `json:"reused,omitempty"` // a third-party copy of a value the owner also holds
	LastSeen time.Time `json:"last_seen"`
	// Gone marks a working location the latest finished local-secrets run read without finding the
	// secret there: kept for the record, left out of used_in, the exposure and path rules (see
	// current). Records of the past (history, transcripts, logs) are never gone.
	Gone bool `json:"gone,omitempty"`
}

func (l Location) key() string { return l.Source + "\x00" + l.Path }

// ref names the location in rotated_locations: source and path, as key does.
func (l Location) ref() string { return l.Source + ":" + l.Path }

// Working reports whether a consumer reads the secret from here: a config, .env, rc or repo
// working-tree file. Git history (gitleaks), transcripts, logs and shell history are records of
// the past; once the value is revoked their copies are dead.
func (l Location) Working() bool {
	return l.Source != "gitleaks" && (l.Kind == "config" || l.Kind == "repo")
}

// Spot is how exposed this location left the secret: a copy in someone else's repository exposes
// the upstream's secret, not the owner's.
func (l Location) Spot() secretrisk.Spot {
	if s, ok := secretrisk.UpstreamSpot(l.Origin, l.Reused); ok {
		return s
	}
	return secretrisk.Where(l.Source, l.Kind, l.Mode, l.Tracked, l.Remote)
}

// Where is path:line, or the path when the line is unknown.
func (l Location) Where() string {
	if l.Line > 0 {
		return fmt.Sprintf("%s:%d", l.Path, l.Line)
	}
	return l.Path
}

// Secret is what a rotate item knows about its secret. Never the value: a redacted hint and, on the
// item, the HMAC fingerprint.
type Secret struct {
	ID        string     `json:"id"` // shortest unique fingerprint prefix, from 8 characters
	Service   string     `json:"service"`
	Type      string     `json:"type"`
	Redacted  string     `json:"redacted"`
	Impact    string     `json:"impact"`
	Reasons   []string   `json:"reasons"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	Locations []Location `json:"locations"`
	UsedIn    []string   `json:"used_in"`
	RotateURL string     `json:"rotate_url,omitempty"`
	// RotatedLocations are the locations (source:path) known when the item was marked done.
	RotatedLocations []string `json:"rotated_locations,omitempty"`
	// Attribution says whose the secret is, from the claims its sightings made (see attribution.go).
	Attribution *attribution.Result `json:"attribution,omitempty"`
	// Liveness is the newest answer of the provider when the secret was tried (see liveness.go).
	Liveness *secretrisk.Liveness `json:"liveness,omitempty"`
}

// Sighting is one finding of a secret, reduced to what a rotate item needs.
type Sighting struct {
	Evidence secretrisk.Evidence
	Seen     time.Time
}

// Sightings returns the secret findings of a local-secrets run: those whose evidence carries a
// fingerprint.
func Sightings(fs []finding.Finding) []Sighting {
	var out []Sighting
	for _, f := range fs {
		if ev, ok := secretEvidence(f); ok {
			out = append(out, Sighting{Evidence: ev, Seen: f.ObservedAt})
		}
	}
	return out
}

func secretEvidence(f finding.Finding) (secretrisk.Evidence, bool) {
	if f.Connector != SecretsConnector || f.Evidence == nil {
		return secretrisk.Evidence{}, false
	}
	raw, _ := json.Marshal(f.Evidence)
	var ev secretrisk.Evidence
	if json.Unmarshal(raw, &ev) != nil || ev.Fingerprint == "" {
		return secretrisk.Evidence{}, false
	}
	return ev, true
}

// SecretReport counts what folding secret sightings changed.
type SecretReport struct {
	Secrets, Created, Updated, Reopened, Skipped int
	// Reclassified counts items closed because every current sighting is now noise.
	Reclassified int
	// HistoryOnly counts rotated items seen again only in history, transcripts or logs, noted for
	// the first time in this sync.
	HistoryOnly int
}

// SyncSecrets folds sightings into rotate items. Secrets whose every sighting is noise (generic
// matches, public or encrypted values) are skipped unless includeNoise; when such a secret already
// has an item (a rule was corrected since), the item is updated to noise and closed as
// reclassified (see reclassify). A done item found again
// with the same fingerprint is reopened only when a sighting is in a working file (see
// rotatedSeen). Items not seen keep their history and last_seen: git history and transcripts do
// not forget, and a redacted copy still reached the model provider.
//
// A secret attributed mine (a claim names one of the owner's accounts, known to the tracker) counts
// in full wherever it sits: copies in third-party repositories and in history a fork inherited are
// the owner's leaked secret, not the upstream's (see mineAfterAll).
func (t *Tracker) SyncSecrets(sightings []Sighting, now time.Time, includeNoise bool) SecretReport {
	return t.syncSecrets(sightings, now, includeNoise, t.OwnedAll(attribution.Owned{}))
}

func (t *Tracker) syncSecrets(sightings []Sighting, now time.Time, includeNoise bool, owned attribution.Owned) SecretReport {
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
		// Impact comes from the best current sighting, so a corrected rule (or a sighting that turns
		// out to be a temporary credential) can lower it as well as raise it.
		s.Type, s.Redacted, s.Impact = best.Evidence.Type, best.Evidence.Redacted, impact.String()
		s.LastSeen = seen.UTC()
		s.updateLiveness(g)
		for _, x := range g {
			it.merge(x.Evidence, seen)
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
	return rep
}

// mineAfterAll counts in full the copies of a secret attributed mine that sit in someone else's
// repository: the claims of the sightings (and the facts the item already holds) name one of the
// owner's accounts, so it is the owner's secret leaked there. Such a copy is marked Reused, as a
// third-party copy of a value the owner holds elsewhere is, and so is never noise or local for
// being there.
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

// NoiseOnly reads the noise summary of a local-secrets run: every fingerprint whose copies are all
// noise, with its type. The connector emits it instead of the noise findings themselves (unless
// emit_noise), so a secret a corrected rule made noise still reaches its item.
func NoiseOnly(fs []finding.Finding) map[string]string {
	for _, f := range fs {
		if f.Connector != SecretsConnector || f.Resource.Type != noiseSummaryType {
			continue
		}
		raw, _ := json.Marshal(f.Evidence["noise_fingerprints"])
		var m map[string]string
		if json.Unmarshal(raw, &m) == nil {
			return m
		}
	}
	return nil
}

// noiseSummaryType is localsecrets.NoiseSummaryType (the tracker does not import connectors).
const noiseSummaryType = "noise_summary"

// SyncNoise applies a noise summary to the items it names, as SyncSecrets does for a secret whose
// every sighting is noise: impact noise, and open, in-progress, snoozed or ignored items closed as
// reclassified. Fingerprints without an item are left alone: noise never creates one. An item
// attributed mine with a copy in someone else's repository is left alone too: that copy is noise
// for the connector only because of where it sits, and attribution makes it the owner's.
func (t *Tracker) SyncNoise(noise map[string]string, now time.Time) SecretReport {
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

// reclassify closes an item whose every current sighting is noise, and reports whether it did.
// Done and accepted items keep their status: the owner settled them. An ignored item becomes
// reclassified too, its ignore reason kept in the event, so the "ignored" count holds only what
// the owner ignored about real secrets.
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

// wasIgnored starts a reclassified event's detail when the item had been ignored by the owner.
const wasIgnored = "was ignored: "

// unreclassify puts back a reclassified item whose secret is no longer noise: ignored again with
// the owner's reason when it was ignored before, open otherwise; it reports whether it reopened.
func (it *Item) unreclassify(now time.Time) bool {
	if prev, ok := strings.CutPrefix(it.lastDetail(actReclassify), wasIgnored); ok {
		reason, _, _ := strings.Cut(prev, "; every current sighting is noise")
		it.setStatus(now, Ignored, EvStatus, actIgnore, reason)
		return false
	}
	it.setStatus(now, Open, EvReopened, actAutoReopen, "a current sighting is no longer noise")
	return true
}

// lastDetail is the detail of the latest history event with that action, or "".
func (it *Item) lastDetail(action string) string {
	for i := len(it.History) - 1; i >= 0; i-- {
		if it.History[i].Action == action {
			return it.History[i].Detail
		}
	}
	return ""
}

// rotatedSeen handles a done item seen again. After a real rotation the old value is revoked, so
// only a working file that still holds it matters: one known at rotation time (the new value never
// reached it) or one that appeared since. Copies only in git history, transcripts, logs or shell
// history leave the item done, with a note logged once per rotation.
func (it *Item) rotatedSeen(g []Sighting, now time.Time, rep *SecretReport) {
	if it.livenessIs(secretrisk.Dead) || it.closedDead() {
		// The provider rejected the key: a working file that still holds it fails, it leaks nothing.
		// If a later check finds it live, reopenProvenLive opens the item, as proven live.
		g = nil
	}
	known := map[string]bool{}
	for _, r := range it.Secret.RotatedLocations {
		known[r] = true
	}
	var still, fresh []string
	for _, s := range g {
		loc := locationOf(s.Evidence, now)
		switch {
		case !loc.Working():
		case known[loc.ref()]:
			still = append(still, loc.Path)
		default:
			fresh = append(fresh, loc.Path)
		}
	}
	if len(still)+len(fresh) == 0 {
		if !it.notedHistoryOnly() {
			it.Log(now, EvNote, actHistory, HistoryOnly)
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

// secretsFilesScope is the scope of local-secrets findings outside git history
// (localsecrets.filesScope; the tracker does not import connectors).
const secretsFilesScope = "files"

// markGoneLocations flags, on every rotate item, the working locations a local-secrets run did not
// report although it read the files: the secret is no longer there. A run that skipped the files
// proves nothing, and noise-only secrets are not reported one by one, so neither marks anything. A
// location reported again is no longer gone (merge replaces it).
func (t *Tracker) markGoneLocations(r *run) {
	if _, unchecked := r.cov.Unchecked("", secretsFilesScope); unchecked {
		return
	}
	seen := map[string]bool{}
	for _, s := range Sightings(r.findings) {
		seen[s.Evidence.Fingerprint+"\x00"+locationOf(s.Evidence, time.Time{}).key()] = true
	}
	noise := NoiseOnly(r.findings)
	for fp, it := range t.byFingerprint() {
		if _, isNoise := noise[fp]; isNoise {
			continue
		}
		for i := range it.Secret.Locations {
			if l := &it.Secret.Locations[i]; l.Working() && !seen[fp+"\x00"+l.key()] {
				l.Gone = true
			}
		}
	}
}

// current are the locations that still hold the secret as far as segurata knows: every one not
// gone, or all of them when every one is gone (the item keeps its exposure until it is settled).
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

// NoteRedaction records that `segurata redact` replaced the value in some trail files. The
// locations stay: the copies reached wherever they went before the local file was cleaned.
func (it *Item) NoteRedaction(at time.Time, files int) {
	it.Log(at, EvNote, actRedacted, fmt.Sprintf("redacted from %d trail %s", files, textfmt.Plural(files, "file", "files")))
}

// latest is when the group was last observed, or now when the findings carry no time.
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

// vague services say what a secret looks like rather than whose it is.
var vague = map[string]bool{"private-key": true, "unknown": true, "oauth": true, "url": true, "generic": true}

// bestSighting picks the sighting that names the secret best: highest impact, then a catalog type
// over a gitleaks rule id, a provider over a shape ("GCP service account key" over "Private key"),
// then a working-tree file over git history.
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

// merge adds or updates one location.
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

// newSecretID is the shortest prefix of the fingerprint, from 8 characters, no other item uses.
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

// worst is the location that exposed the secret the most.
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

// spotOrder breaks ties between spots of the same exposure level. Copies in other people's
// repositories rank last.
var spotOrder = map[string]int{"git+remote": 7, "transcript": 6, "git": 5, "readable": 4, "history": 3, "log": 2, "local": 1,
	secretrisk.OriginThirdParty: 0, secretrisk.OriginForkUpstream: 0}

func spotRank(s secretrisk.Spot) int { return int(s.Level)*10 + spotOrder[s.Label] }

// SpotRank orders locations, worst exposure first, for listings.
func SpotRank(l Location) int { return spotRank(l.Spot()) }

// WorstLabel is the short label of the worst exposure, for tables.
func (it *Item) WorstLabel() string { return it.worst().Label }

func impactByName(name string) secretrisk.Impact {
	for i := secretrisk.Noise; i <= secretrisk.High; i++ {
		if i.String() == name {
			return i
		}
	}
	return secretrisk.Medium
}

// refreshSecret recomputes everything derived from a rotate item's locations: priority, severity,
// reasons, used_in, rotate_url, title and next step.
func (it *Item) refreshSecret() {
	s := it.Secret
	t := secretrisk.TypeFor(s.Type, s.Redacted)
	s.Service, s.RotateURL = t.Service, t.RotateURL
	worst, ok := it.worstSpot()
	it.Priority = ""
	if ok {
		it.Priority = secretrisk.PriorityOf(impactByName(s.Impact), worst.Level)
	}
	// A connector that reports the same credential proves it live: the worse of the two priorities
	// holds, and a live key that left the machine is P0 (see correlate.go).
	live := it.live()
	for _, r := range live {
		if p := priorityOf(r.Severity); p != "" && p.Rank() < it.Priority.Rank() {
			it.Priority = p
		}
	}
	if it.livenessIs(secretrisk.Unregistered) && len(live) == 0 {
		it.Priority = it.Priority.Lower()
	}
	var reasons []string
	if it.LiveAndLeaked() {
		it.Priority = secretrisk.P0
		if primary, ok := it.primaryLocation(); ok {
			reasons = append(reasons, "live key, leaked in "+primary.Name())
		}
	}
	it.Severity = secretrisk.SeverityOf(it.Priority) // info for noise
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
	if ok {
		reasons = append(reasons, secretrisk.Reason(t, worst))
		counts := map[string]int{}
		phrase := map[string]string{}
		for _, l := range it.current() {
			sp := l.Spot()
			counts[sp.Label]++
			phrase[sp.Label] = sp.Phrase
		}
		labels := make([]string, 0, len(counts))
		for lb := range counts {
			labels = append(labels, lb)
		}
		sort.Slice(labels, func(i, j int) bool { return spotOrder[labels[i]] > spotOrder[labels[j]] })
		for _, lb := range labels {
			n := counts[lb]
			if lb == worst.Label {
				n--
			}
			if n > 0 {
				reasons = append(reasons, fmt.Sprintf("also %s (%d %s)", phrase[lb], n, textfmt.Plural(n, "place", "places")))
			}
		}
	}
	if it.Owner() == attribution.Mine && it.upstreamCopy() {
		reasons = append(reasons, "yours by attribution ("+it.Secret.Attribution.Reasons[0]+"), so its copies in other people's repositories count in full")
	}
	s.Reasons = reasons
	seen := map[string]bool{}
	s.UsedIn = []string{}
	for _, l := range s.Locations {
		if l.Working() && !l.Gone && !seen[l.Path] {
			seen[l.Path] = true
			s.UsedIn = append(s.UsedIn, l.Path)
		}
	}
	sort.Strings(s.UsedIn)
	it.secretTitleAndNext()
}

// secretTitleAndNext names a rotate item and says how to rotate it.
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

// secretTitle names a rotate item by what it is, the provider's name for the key when a live
// provider key matched it, and where it was found worst: "<label> <hint> = "<key name>" (in use,
// $42.00 this month) in <repo>:<file> (+N places), committed YYYY-MM". The hint is left out when
// it is not one value ("PEM"); the date is the earliest commit among the locations.
func (it *Item) secretTitle() string {
	s := it.Secret
	title := secretrisk.TypeFor(s.Type, s.Redacted).Label
	if _, single := secretrisk.ParseHint(s.Redacted); single {
		title += " " + s.Redacted
	}
	title += it.keyFacts()
	primary, ok := it.primaryLocation()
	if !ok {
		return title
	}
	title += " in " + primary.Name()
	if n := len(it.current()) - 1; n > 0 {
		title += fmt.Sprintf(" (+%d %s)", n, textfmt.Plural(n, "place", "places"))
	}
	if d := it.firstCommitted(); d != "" {
		title += ", committed " + d[:7]
	}
	return title
}

// keyFacts names the provider's key the secret is, from the surest live ref that carries key facts:
// ` = "Claude Code" (in use, $42.00 this month)`. In use means used within finding.IdleAfter of the
// run that reported it. "" when no live provider key matched.
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

// primaryLocation is the location that exposed the secret the most; among equals, the owner's
// repository, then the most recent commit, then the path.
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

// Name is the location as a title shows it: <repo>:<file> for git history (the repository
// without its ~/src/ prefix), else the path.
func (l Location) Name() string {
	if l.Repo != "" && strings.HasPrefix(l.Path, l.Repo+"/") {
		return strings.TrimPrefix(l.Repo, "~/src/") + ":" + strings.TrimPrefix(l.Path, l.Repo+"/")
	}
	return l.Path
}

// firstCommitted is the earliest commit date among the locations, "" when none was committed.
func (it *Item) firstCommitted() string {
	first := ""
	for _, l := range it.Secret.Locations {
		if len(l.Date) >= 7 && (first == "" || l.Date < first) {
			first = l.Date
		}
	}
	return first
}

// lastCommitted is the latest commit date among the locations, "" when none was committed.
func (it *Item) lastCommitted() string {
	last := ""
	for _, l := range it.Secret.Locations {
		if l.Date > last {
			last = l.Date
		}
	}
	return last
}

// upstreamCopy reports whether a location is in someone else's repository or in history a fork
// inherited.
func (it *Item) upstreamCopy() bool {
	for _, l := range it.Secret.Locations {
		if l.Origin == secretrisk.OriginThirdParty || l.Origin == secretrisk.OriginForkUpstream {
			return true
		}
	}
	return false
}

// owned reports whether a location is in one of the owner's repositories.
func (it *Item) owned() bool {
	for _, l := range it.Secret.Locations {
		if l.Origin == secretrisk.OriginOwned {
			return true
		}
	}
	return false
}

// reopenedStillPresent: the last done/reopen event is an automatic reopen.
func (it *Item) reopenedStillPresent() bool {
	for i := len(it.History) - 1; i >= 0; i-- {
		switch it.History[i].Action {
		case actAutoReopen:
			return it.Status != Done
		case actDone, actReopen:
			return false
		}
	}
	return false
}

// notedHistoryOnly reports whether the history-only note was logged since the last done.
func (it *Item) notedHistoryOnly() bool {
	for i := len(it.History) - 1; i >= 0; i-- {
		switch it.History[i].Action {
		case actHistory:
			return true
		case actDone:
			return false
		}
	}
	return false
}
