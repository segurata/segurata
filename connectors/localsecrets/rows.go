package localsecrets

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

func fileValueKey(ev secretrisk.Evidence) string { return ev.Path + "\x00" + ev.Fingerprint }

// inheritForkUpstream makes a fork's working copy inherited when history shows that value at that
// path in an upstream commit.
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

// markReused flags third-party copies of a value one of the owner's config or repository files
// holds. A trail copy does not make it the owner's: an agent may have read a third-party file.
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

// collapseTemporaryAWS reports a file's temporary key ids and pre-signed URLs as one finding (a
// page of signed links is one cleanup, not hundreds of rotations), kept under the smallest
// fingerprint so it is stable across runs, expired only when all are. folded maps it to the rows
// it stands for, which the noise summary still names.
func collapseTemporaryAWS(evs []secretrisk.Evidence) (out []secretrisk.Evidence, folded map[string][]secretrisk.Evidence) {
	groups := map[string][]int{}
	folded = map[string][]secretrisk.Evidence{}
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
		for _, i := range idx[1:] {
			folded[keep.Fingerprint] = append(folded[keep.Fingerprint], evs[i])
		}
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
	return out, folded
}

// noiseCounts counts the noise left out, by type and place (repository or kind of file), and keeps
// the types of the noise-only fingerprints for the summary.
type noiseCounts struct {
	total           int
	byType, byPlace map[string]int
	types           map[string]string // fingerprint -> type
}

func (n *noiseCounts) add(ev secretrisk.Evidence) {
	if n.byType == nil {
		n.byType, n.byPlace = map[string]int{}, map[string]int{}
	}
	place := ev.Repo
	if place == "" {
		place = ev.Kind
	}
	n.total++
	n.byType[ev.Type]++
	n.byPlace[place]++
	n.name(ev)
}

// name records a noise-only fingerprint without counting it: a folded row, already counted.
func (n *noiseCounts) name(ev secretrisk.Evidence) {
	if n.types == nil {
		n.types = map[string]string{}
	}
	if t, ok := n.types[ev.Fingerprint]; !ok || ev.Type < t {
		n.types[ev.Fingerprint] = ev.Type
	}
}

func (n noiseCounts) summary() (finding.Finding, bool) {
	if n.total == 0 {
		return finding.Finding{}, false
	}
	return finding.Finding{
		Account:  localAccount,
		Resource: finding.Resource{Type: secretrisk.NoiseSummaryType, ID: "noise", Name: "noise left out"},
		Kind:     finding.KindExposure,
		Severity: finding.SevInfo,
		Title:    fmt.Sprintf("%d noise matches left out (emit_noise: true lists them)", n.total),
		Evidence: map[string]any{"source": "noise", "total": n.total, "by_type": n.byType, "by_place": n.byPlace,
			secretrisk.NoiseFingerprints: n.types},
		Remediation: finding.Remediation{Summary: "Nothing to do: generic matches, public, expired or encrypted values, and copies that are not yours."},
	}, true
}

const maxNoisePlaces = 25

func (n noiseCounts) String() string {
	if n.total == 0 {
		return ""
	}
	types := topCounts(n.byType, 0)
	places := topCounts(n.byPlace, maxNoisePlaces)
	return fmt.Sprintf("; noise not emitted (emit_noise: true lists it): %d; by type: %s; by place: %s", n.total, types, places)
}

// topCounts lists "key n", largest first, at most limit (0: all) and the rest summed.
func topCounts(m map[string]int, limit int) string {
	keys := slices.SortedFunc(maps.Keys(m), func(a, b string) int { return cmp.Or(cmp.Compare(m[b], m[a]), cmp.Compare(a, b)) })
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
