package tracker

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

// Rotate items: one per secret fingerprint, fed by local-secrets findings. This is the former
// rotation ledger; `securizame rotations` is its command family. The risk model it shares with
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
	LastSeen time.Time `json:"last_seen"`
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

// Spot is how exposed this location left the secret.
func (l Location) Spot() secretrisk.Spot {
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
	// HistoryOnly counts rotated items seen again only in history, transcripts or logs, noted for
	// the first time in this sync.
	HistoryOnly int
}

// SyncSecrets folds sightings into rotate items. Secrets whose every sighting is noise (generic
// matches, public or encrypted values) are skipped unless includeNoise. A done item found again
// with the same fingerprint is reopened only when a sighting is in a working file (see
// rotatedSeen). Items not seen keep their history and last_seen: git history and transcripts do
// not forget, and a redacted copy still reached the model provider.
func (t *Tracker) SyncSecrets(sightings []Sighting, now time.Time, includeNoise bool) SecretReport {
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
		best := bestSighting(g)
		impact := secretrisk.ImpactOf(best.Evidence)
		if impact == secretrisk.Noise && !includeNoise {
			rep.Skipped++
			continue
		}
		rep.Secrets++
		seen := latest(g, now)
		it, ok := existing[fp]
		if !ok {
			it = t.newItem(KindRotate, "rotate:"+fp, "rotations", "", now)
			it.Fingerprint = fp
			it.Secret = &Secret{ID: t.newSecretID(fp), FirstSeen: seen.UTC()}
			existing[fp] = it
			it.Log(now, EvFound, actFound, fmt.Sprintf("found in %d %s", len(g), textfmt.Plural(len(g), "place", "places")))
			rep.Created++
		} else {
			rep.Updated++
		}
		s := it.Secret
		// Impact comes from the best current sighting, so a corrected rule (or a sighting that turns
		// out to be a temporary credential) can lower it as well as raise it.
		s.Type, s.Redacted, s.Impact = best.Evidence.Type, best.Evidence.Redacted, impact.String()
		s.LastSeen = seen.UTC()
		for _, x := range g {
			it.merge(x.Evidence, seen)
		}
		if it.Status == Done {
			it.rotatedSeen(g, now, &rep)
		}
		it.derive()
	}
	return rep
}

// rotatedSeen handles a done item seen again. After a real rotation the old value is revoked, so
// only a working file that still holds it matters: one known at rotation time (the new value never
// reached it) or one that appeared since. Copies only in git history, transcripts, logs or shell
// history leave the item done, with a note logged once per rotation.
func (it *Item) rotatedSeen(g []Sighting, now time.Time, rep *SecretReport) {
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

// NoteRedaction records that `securizame redact` replaced the value in some trail files. The
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
		Source: ev.Source, Kind: ev.Kind, Remote: ev.Remote, LastSeen: seen.UTC()}
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
	for _, l := range it.Secret.Locations {
		s := l.Spot()
		if !found || spotRank(s) > spotRank(best) {
			best, found = s, true
		}
	}
	return best, found
}

// spotOrder breaks ties between spots of the same exposure level.
var spotOrder = map[string]int{"git+remote": 7, "transcript": 6, "git": 5, "readable": 4, "history": 3, "log": 2, "local": 1}

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
	it.Severity = secretrisk.SeverityOf(it.Priority) // info for noise
	var reasons []string
	if it.reopenedStillPresent() {
		reasons = append(reasons, StillPresent)
	}
	if ok {
		reasons = append(reasons, secretrisk.Reason(t, worst))
		counts := map[string]int{}
		phrase := map[string]string{}
		for _, l := range s.Locations {
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
	s.Reasons = reasons
	seen := map[string]bool{}
	s.UsedIn = []string{}
	for _, l := range s.Locations {
		if l.Working() && !seen[l.Path] {
			seen[l.Path] = true
			s.UsedIn = append(s.UsedIn, l.Path)
		}
	}
	sort.Strings(s.UsedIn)
	it.secretTitleAndNext()
}

// secretTitleAndNext names a rotate item by its type and redacted hint, and says how to rotate it.
func (it *Item) secretTitleAndNext() {
	s := it.Secret
	it.Title = strings.TrimSpace(secretrisk.TypeFor(s.Type, s.Redacted).Label + " " + s.Redacted)
	where := "in the provider's console"
	if s.RotateURL != "" {
		where = "at " + s.RotateURL
	}
	n := &Next{Who: You, URL: s.RotateURL, Command: "securizame rotations done " + s.ID}
	_, single := secretrisk.ParseHint(s.Redacted)
	switch {
	case len(s.UsedIn) == 0:
		n.Action = "Rotate it " + where + ", then mark it done (no working file holds it)."
	case !single:
		n.Action = fmt.Sprintf("Rotate it %s, put the new value in %s by hand, then mark it done.", where, count(len(s.UsedIn), "file", "files"))
	default:
		n.Action = fmt.Sprintf("Rotate it %s and copy the new value; securizame puts it in %s.", where, count(len(s.UsedIn), "file", "files"))
		n.Command = "securizame rotations replace " + s.ID
	}
	it.Next = n
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
