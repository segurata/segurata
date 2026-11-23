package rotation

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Connector is the connector whose findings feed the ledger.
const Connector = "local-secrets"

// Sighting is one finding of a secret, reduced to what the ledger needs.
type Sighting struct {
	Evidence secretrisk.Evidence
	Seen     time.Time
}

// ReadFindings reads a local-secrets JSONL output and returns its secret findings.
func ReadFindings(r io.Reader) ([]Sighting, error) {
	var out []Sighting
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var f finding.Finding
		if json.Unmarshal(sc.Bytes(), &f) != nil || f.Type != "finding" || f.Connector != Connector {
			continue
		}
		raw, _ := json.Marshal(f.Evidence)
		var ev secretrisk.Evidence
		if json.Unmarshal(raw, &ev) != nil || ev.Fingerprint == "" {
			continue
		}
		out = append(out, Sighting{Evidence: ev, Seen: f.ObservedAt})
	}
	return out, sc.Err()
}

// LatestOutput is the newest out/<date>/local-secrets.jsonl.
func LatestOutput(outDir string) (string, error) {
	matches, _ := filepath.Glob(filepath.Join(outDir, "*", Connector+".jsonl"))
	if len(matches) == 0 {
		return "", fmt.Errorf("no %s output under %s: run `securizame inventory %s` first", Connector, outDir, Connector)
	}
	sort.Strings(matches)
	return matches[len(matches)-1], nil
}

// Report counts what a sync changed.
type Report struct {
	Secrets, Created, Updated, Reopened, Woken, Skipped int
}

// Sync merges sightings into the ledger. Secrets whose every sighting is noise (generic matches,
// public or encrypted values) are skipped unless includeNoise. A rotated item found again with the
// same fingerprint is reopened. Items not seen keep their history and last_seen.
func (l *Ledger) Sync(sightings []Sighting, now time.Time, includeNoise bool) Report {
	groups := map[string][]Sighting{}
	var order []string
	for _, s := range sightings {
		fp := s.Evidence.Fingerprint
		if _, ok := groups[fp]; !ok {
			order = append(order, fp)
		}
		groups[fp] = append(groups[fp], s)
	}
	var rep Report
	existing := l.byFingerprint()
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
			it = &Item{ID: l.newID(fp), Fingerprint: fp, Status: Open, FirstSeen: seen.UTC()}
			l.Items = append(l.Items, it)
			existing[fp] = it
			it.log(now, actFound, fmt.Sprintf("found in %d %s", len(g), plural(len(g), "place", "places")))
			rep.Created++
		} else {
			rep.Updated++
		}
		if !ok || impact >= impactByName(it.Impact) {
			it.Type, it.Redacted, it.Impact = best.Evidence.Type, best.Evidence.Redacted, impact.String()
		}
		it.LastSeen = seen.UTC()
		for _, s := range g {
			it.merge(s.Evidence, seen)
		}
		if it.Status == Rotated {
			it.Status = Open
			it.log(now, actAutoReopen, stillPresent)
			rep.Reopened++
		}
	}
	for _, it := range l.Items {
		if it.Status == Snoozed && it.Active(now) {
			it.Status, it.SnoozedUntil = Open, ""
			it.log(now, actWake, "")
			rep.Woken++
		}
		it.refresh()
	}
	return rep
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

// merge adds or updates one location.
func (it *Item) merge(ev secretrisk.Evidence, seen time.Time) {
	loc := Location{Path: ev.Path, Line: ev.Line, Bucket: ev.Bucket, Tracked: ev.Tracked, Mode: ev.Mode,
		Source: ev.Source, Kind: ev.Kind, Remote: ev.Remote, LastSeen: seen.UTC()}
	for i := range it.Locations {
		if it.Locations[i].key() == loc.key() {
			it.Locations[i] = loc
			return
		}
	}
	it.Locations = append(it.Locations, loc)
	sort.Slice(it.Locations, func(i, j int) bool { return it.Locations[i].key() < it.Locations[j].key() })
}

// SyncFile loads the findings file and syncs it.
func (l *Ledger) SyncFile(path string, now time.Time, includeNoise bool) (Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	s, err := ReadFindings(f)
	if err != nil {
		return Report{}, err
	}
	return l.Sync(s, now, includeNoise), nil
}
