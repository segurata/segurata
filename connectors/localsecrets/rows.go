package localsecrets

import (
	"fmt"
	"sort"
	"strings"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// The steps of findings that look at every row at once.

// fileValueKey identifies one value in one file.
func fileValueKey(ev secretrisk.Evidence) string { return ev.Path + "\x00" + ev.Fingerprint }

// inheritForkUpstream marks a fork's working copy of a file as inherited when git history shows
// that same value at that path in a commit the upstream already had: the working tree has no
// commit of its own to judge by.
func inheritForkUpstream(evs []secretrisk.Evidence) []secretrisk.Evidence {
	inherited := map[string]bool{}
	for _, ev := range evs {
		if ev.Source == "gitleaks" && ev.Origin == secretrisk.OriginForkUpstream {
			inherited[fileValueKey(ev)] = true
		}
	}
	for i, ev := range evs {
		if ev.Source != "gitleaks" && ev.Tracked && ev.Origin == secretrisk.OriginOwned && inherited[fileValueKey(ev)] {
			evs[i].Origin = secretrisk.OriginForkUpstream
		}
	}
	return evs
}

// markReused flags the copies in other people's repositories of a value that one of the owner's
// own files also holds (a config or .env file, a working file or commit in the owner's
// repositories): the owner's secret, leaked into a third-party repository, so it counts. Trails
// do not count as the owner's here: an agent that read a third-party file left its value in a
// transcript without making it the owner's.
func markReused(evs []secretrisk.Evidence) []secretrisk.Evidence {
	owned := map[string]bool{}
	for _, ev := range evs {
		if !secretrisk.NotOwners(ev.Origin, false) && (ev.Kind == "config" || ev.Kind == "repo") {
			owned[ev.Fingerprint] = true
		}
	}
	for i, ev := range evs {
		if secretrisk.NotOwners(ev.Origin, false) && owned[ev.Fingerprint] {
			evs[i].Reused = true
		}
	}
	return evs
}

// collapseTemporaryAWS reports the temporary AWS key ids and pre-signed URLs of one file as a
// single finding: a page of signed links (197 in one committed JSON file on 2026-11-24) is one
// thing to clean up, not 197 keys to rotate. The row kept is the one with the smallest
// fingerprint, so the same file keeps the same finding across runs; it counts every match and is
// expired only when all of them are.
func collapseTemporaryAWS(evs []secretrisk.Evidence) []secretrisk.Evidence {
	groups := map[string][]int{}
	var out []secretrisk.Evidence
	for i, ev := range evs {
		if secretrisk.TemporaryAWS(ev) || ev.Type == "aws-presigned-url" {
			k := ev.Source + "\x00" + ev.Path
			groups[k] = append(groups[k], i)
			continue
		}
		out = append(out, ev)
	}
	for _, idx := range groups {
		if len(idx) == 1 {
			out = append(out, evs[idx[0]])
			continue
		}
		sort.Slice(idx, func(a, b int) bool { return evs[idx[a]].Fingerprint < evs[idx[b]].Fingerprint })
		keep := evs[idx[0]]
		keep.Count, keep.Public = 0, true
		presigned := false
		for _, i := range idx {
			keep.Count += evs[i].Count
			keep.Public = keep.Public && evs[i].Public
			presigned = presigned || evs[i].Type == "aws-presigned-url"
		}
		if presigned {
			keep.Type = "aws-presigned-url"
		}
		keep.Note = fmt.Sprintf("%d temporary AWS credentials or pre-signed URLs", len(idx))
		if keep.Public {
			keep.Note += ", all expired"
		}
		out = append(out, keep)
	}
	return out
}

// noiseCounts counts the noise findings left out of the output, by type and by place (the
// repository for git history, else the kind of file), for the run's status line, and keeps the
// fingerprints of those values (all of whose copies are noise) for the noise summary.
type noiseCounts struct {
	total           int
	byType, byPlace map[string]int
	types           map[string]string // fingerprint -> type
}

func (n *noiseCounts) add(ev secretrisk.Evidence) {
	if n.byType == nil {
		n.byType, n.byPlace, n.types = map[string]int{}, map[string]int{}, map[string]string{}
	}
	place := ev.Repo
	if place == "" {
		place = ev.Kind
	}
	n.total++
	n.byType[ev.Type]++
	n.byPlace[place]++
	if t, ok := n.types[ev.Fingerprint]; !ok || ev.Type < t {
		n.types[ev.Fingerprint] = ev.Type
	}
}

// NoiseSummaryType is the resource type of the one finding that stands for the noise left out:
// its evidence maps every noise-only fingerprint to its type (noise_fingerprints), so the tracker
// can close items whose secret a corrected rule made noise without every copy being emitted.
const NoiseSummaryType = "noise_summary"

// summary is that finding; false when no noise was left out.
func (n noiseCounts) summary() (finding.Finding, bool) {
	if n.total == 0 {
		return finding.Finding{}, false
	}
	return finding.Finding{
		Account:  localAccount,
		Resource: finding.Resource{Type: NoiseSummaryType, ID: "noise", Name: "noise left out"},
		Kind:     finding.KindExposure,
		Severity: finding.SevInfo,
		Title:    fmt.Sprintf("%d noise matches left out (emit_noise: true lists them)", n.total),
		Evidence: map[string]any{"source": "noise", "total": n.total, "by_type": n.byType, "by_place": n.byPlace,
			"noise_fingerprints": n.types},
		Remediation: finding.Remediation{Summary: "Nothing to do: generic matches, public, expired or encrypted values, and copies that are not yours."},
	}, true
}

// maxNoisePlaces bounds the places listed in the status line; the rest are summed.
const maxNoisePlaces = 25

// String is the status-line part, "" when nothing was left out.
func (n noiseCounts) String() string {
	if n.total == 0 {
		return ""
	}
	types := topCounts(n.byType, 0)
	places := topCounts(n.byPlace, maxNoisePlaces)
	return fmt.Sprintf("; noise not emitted (emit_noise: true lists it): %d; by type: %s; by place: %s", n.total, types, places)
}

// topCounts lists "key n" pairs, largest first, at most limit of them (0 for all) and the rest
// summed.
func topCounts(m map[string]int, limit int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var parts []string
	rest, restN := 0, 0
	for i, k := range keys {
		if limit > 0 && i >= limit {
			rest += m[k]
			restN++
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	if restN > 0 {
		parts = append(parts, fmt.Sprintf("%d more places %d", restN, rest))
	}
	return strings.Join(parts, ", ")
}
