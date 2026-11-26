package tracker

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// credential says which connector findings stand for a secret that local-secrets also found: the
// rotate item owns it, and the finding is proof the secret is live. See docs/architecture.md,
// "Correlation".
type credential struct {
	connector string
	resources []string
	services  []string
	hint      string
	path      string
	facts     bool
	spend     string
}

var credentials = []credential{
	{"aws", []string{"aws_local_credentials"}, []string{"aws"}, "key_id", "file", false, ""},
	{"aws", []string{"r2_local_credentials", "s3_local_credentials"}, nil, "key_id", "file", false, ""},
	{"gcp", []string{"local_credential"}, []string{"gcp", "google", "oauth", "private-key"}, "", "path", false, ""},
	{"openai", []string{"api_key"}, []string{"openai"}, "redacted", "", true, ""},
	{"openrouter", []string{"api_key"}, []string{"openrouter"}, "redacted", "", true, "usage_month"},
	{"anthropic", []string{"api_key"}, []string{"anthropic"}, "redacted", "", true, ""},
}

func credentialFor(f finding.Finding) *credential {
	for i := range credentials {
		if c := &credentials[i]; c.connector == f.Connector && slices.Contains(c.resources, f.Resource.Type) {
			return c
		}
	}
	return nil
}

// Ways a credential matched a secret, strongest first. byPossible fits several: merged into none.
const (
	byFingerprint = "fingerprint"
	byHint        = "hint"
	byPath        = "path"
	byPossible    = "possible"
)

// How sure a match is: certain by fingerprint, high by a hint with four or more tail characters
// and the same length on both sides, medium otherwise.
const (
	confCertain = "certain"
	confHigh    = "high"
	confMedium  = "medium"
)

var confRank = map[string]int{confMedium: 1, confHigh: 2, confCertain: 3}

func hintConfidence(a, b secretrisk.Hint) string {
	if a.Len > 0 && b.Len > 0 && min(len(a.Tail), len(b.Tail)) >= 4 {
		return confHigh
	}
	return confMedium
}

// claim is a connector finding, or a secret a connector signs in with, that is a rotate item's.
type claim struct {
	item *Item
	ref  FindingRef
}

type secretIndex struct {
	byFP      map[string]*Item
	byPath    map[string][]*Item
	byService map[string][]*Item
}

func (t *Tracker) secretIndex() secretIndex {
	x := secretIndex{byFP: map[string]*Item{}, byPath: map[string][]*Item{}, byService: map[string][]*Item{}}
	for _, it := range t.Items {
		if it.Kind != KindRotate || it.Secret == nil || it.Status == Reclassified {
			continue
		}
		x.byFP[it.Fingerprint] = it
		x.byService[it.Secret.Service] = append(x.byService[it.Secret.Service], it)
		seen := map[string]bool{}
		for _, l := range it.Secret.Locations {
			if !l.Gone && !seen[l.Path] {
				seen[l.Path] = true
				x.byPath[l.Path] = append(x.byPath[l.Path], it)
			}
		}
	}
	return x
}

type candidate struct {
	item       *Item
	confidence string
}

// match finds the rotate items a credential finding may stand for: by fingerprint only, when it
// has one (the key in the file may have been rotated since the leak); else by a hint showing three
// or more tail characters; else the most urgent secret in its file, since a file can hold several
// parts of one credential. Only a hint gives several candidates.
func (x secretIndex) match(f finding.Finding, c *credential) ([]candidate, string) {
	str := func(k string) string { s, _ := f.Evidence[k].(string); return s }
	if fp := str("fingerprint"); fp != "" {
		if it := x.byFP[fp]; it != nil {
			return []candidate{{it, confCertain}}, byFingerprint
		}
		return nil, ""
	}
	hint, hasHint := secretrisk.ReadHint(str(c.hint))
	serviceOK := func(it *Item) bool { return len(c.services) == 0 || slices.Contains(c.services, it.Secret.Service) }
	if hasHint && len(hint.Tail) >= 3 {
		var hits []candidate
		for _, s := range c.services {
			for _, it := range x.byService[s] {
				if h, ok := secretrisk.ParseHint(it.Secret.Redacted); ok && h.Agrees(hint) {
					hits = append(hits, candidate{it, hintConfidence(h, hint)})
				}
			}
		}
		switch {
		case len(hits) == 1:
			return hits, byHint
		case len(hits) > 1:
			sort.Slice(hits, func(i, j int) bool { return hits[i].item.ID < hits[j].item.ID })
			return hits, byPossible
		}
	}
	if p := homePath(str(c.path)); p != "" {
		var hits []*Item
		for _, it := range x.byPath[p] {
			if !serviceOK(it) || it.Priority == "" {
				continue
			}
			if h, ok := secretrisk.ParseHint(it.Secret.Redacted); hasHint && ok && !h.Agrees(hint) {
				continue
			}
			hits = append(hits, it)
		}
		if it := mostUrgent(hits); it != nil {
			return []candidate{{it, confMedium}}, byPath
		}
	}
	return nil, ""
}

func mostUrgent(items []*Item) *Item {
	if len(items) == 0 {
		return nil
	}
	items = slices.Clone(items)
	Sort(items)
	return items[0]
}

// correlate finds the credential findings and connector sign-ins that are a rotate item's secret.
// A finding whose item the owner accepted stays there.
func (t *Tracker) correlate(folded map[string]*run) (claims map[string]claim, possible []claim) {
	x := t.secretIndex()
	accepted := map[string]bool{}
	for _, it := range t.Items {
		if it.Kind != KindRotate && it.Status == Accepted {
			for _, r := range it.Findings {
				accepted[r.ID] = true
			}
		}
	}
	claims = map[string]claim{}
	for _, r := range folded {
		for _, f := range r.findings {
			c := credentialFor(f)
			if c == nil || accepted[f.ID] {
				continue
			}
			hits, how := x.match(f, c)
			for _, h := range hits {
				ref := refOf(f)
				ref.Match, ref.Confidence, ref.Key = how, h.confidence, keyFactsOf(f, c)
				if how == byPossible {
					ref.Title += fmt.Sprintf(" (its hint fits %d secrets)", len(hits))
					possible = append(possible, claim{item: h.item, ref: ref})
				} else {
					claims[f.ID] = claim{item: h.item, ref: ref}
				}
			}
		}
		for _, name := range slices.Sorted(maps.Keys(r.fingerprints)) {
			it := x.byFP[r.fingerprints[name]]
			if it == nil {
				continue
			}
			conn, inst, _ := strings.Cut(r.label, ":")
			title := fmt.Sprintf("segurata's %s connector signs in with it (%s)", r.label, name)
			if r.failed == "" {
				title += " and its run of " + r.at.Format(time.DateOnly) + " worked"
			}
			id := "uses:" + r.label + ":" + name
			claims[id] = claim{item: it, ref: FindingRef{ID: id, Connector: conn, Instance: inst, Title: title, LastSeen: r.at,
				Match: byFingerprint, Confidence: confCertain}}
		}
	}
	return claims, possible
}

func keyFactsOf(f finding.Finding, c *credential) *KeyFacts {
	if !c.facts {
		return nil
	}
	k := &KeyFacts{Name: f.Resource.Name, LastUsed: f.LastUsedAt}
	if v, ok := f.Evidence[c.spend].(float64); c.spend != "" && ok {
		k.SpendMonthUSD = &v
	}
	return k
}

// attachLive puts this sync's claims on the rotate items, replacing those of the folded instances.
func (t *Tracker) attachLive(claims map[string]claim, possible []claim, folded map[string]*run) {
	live, maybe := map[*Item][]FindingRef{}, map[*Item][]FindingRef{}
	for _, c := range claims {
		live[c.item] = append(live[c.item], c.ref)
	}
	for _, c := range possible {
		maybe[c.item] = append(maybe[c.item], c.ref)
	}
	for _, it := range t.Items {
		if it.Kind != KindRotate {
			continue
		}
		it.Findings = replaceRefs(it.Findings, live[it], folded)
		it.Possible = replaceRefs(it.Possible, maybe[it], folded)
		it.derive()
	}
}

func replaceRefs(old, now []FindingRef, folded map[string]*run) []FindingRef {
	kept := old[:0]
	for _, r := range old {
		if _, ok := folded[r.Label()]; !ok {
			kept = append(kept, r)
		}
	}
	refs := append(kept, now...)
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	if len(refs) == 0 {
		return nil
	}
	return refs
}

func claimedBy(claims map[string]claim) map[string]string {
	out := make(map[string]string, len(claims))
	for id, c := range claims {
		out[id] = c.item.ID
	}
	return out
}

// moveRefs takes out the findings another item now owns (moved: finding id to item id); an item
// left with nothing reported merges into the one that took them.
func (it *Item) moveRefs(moved map[string]string, now time.Time) bool {
	into := ""
	kept := it.Findings[:0]
	for _, r := range it.Findings {
		if to, ok := moved[r.ID]; ok && to != it.ID {
			if into == "" {
				into = to
			}
			continue
		}
		kept = append(kept, r)
	}
	it.Findings = kept
	if into == "" || it.reported() {
		return false
	}
	return it.mergeInto(into, now, "merged into "+into+", which owns it now")
}

// mergeInto closes the item as merged into into, unless it is closed already, and reports whether
// it merged.
func (it *Item) mergeInto(into string, now time.Time, detail string) bool {
	switch it.Status {
	case Open, InProgress, Snoozed, Done:
	default:
		return false
	}
	it.setStatus(now, Merged, EvMerged, actMerged, detail)
	it.MergedInto = into
	it.Next = &Next{Who: You, Action: "Nothing here: " + into + " owns this now.", Command: "segurata track show " + into}
	return true
}

func (it *Item) reopenMerged(now time.Time) {
	from := it.MergedInto
	it.setStatus(now, Open, EvReopened, actAutoReopen, "no longer part of "+from)
}

// reopenProvenLive opens a rotate item whose proof of life contradicts how it was closed, since
// the connector's own item merged into it: ignored (ignoring it again after the proof sticks), or
// done while a later run signs in with the old value itself. Only a fingerprint proves a done item
// live: the new key in the same file fits a hint or a path too.
func (it *Item) reopenProvenLive(now time.Time) {
	var proof []FindingRef
	var was string
	checked := it.checkedLive()
	switch it.Status {
	case Ignored:
		if it.ignoredAfterProof() {
			return
		}
		proof, was = it.live(), "it was ignored: "+it.lastDetail(actIgnore)
	case Done:
		for _, r := range it.live() {
			if r.Confidence == confCertain && r.LastSeen.After(it.StatusAt) {
				proof = append(proof, r)
			}
		}
		checked = checked && it.Secret.Liveness.CheckedAt.After(it.StatusAt)
		was = "after it was marked rotated"
		if note := it.lastDetail(actDone); note != "" {
			was += ": " + note
		}
		if it.closedDead() {
			was = "after it was closed: " + it.lastDetail(actDead)
		}
	default:
		return
	}
	var labels []string
	for _, r := range proof {
		if !slices.Contains(labels, r.Label()) {
			labels = append(labels, r.Label())
		}
	}
	if checked {
		labels = append(labels, "the liveness check of "+it.Secret.Liveness.CheckedAt.Format(time.DateOnly))
	}
	if len(labels) == 0 {
		return
	}
	it.setStatus(now, Open, EvReopened, actProvenLive, "proven live by "+strings.Join(labels, ", ")+"; "+was)
}

func (it *Item) ignoredAfterProof() bool {
	return it.latestOf(actProvenLive) != "" && it.latestOf(actIgnore, actProvenLive) == actIgnore
}

// live are the connector findings still reported on a rotate item: proof the secret works.
func (it *Item) live() []FindingRef {
	var out []FindingRef
	if it.Kind != KindRotate {
		return nil
	}
	for _, r := range it.Findings {
		if !r.Gone {
			out = append(out, r)
		}
	}
	return out
}

// liveAndLeaked reports whether the secret is proven live and a copy left the machine.
func (it *Item) liveAndLeaked() bool {
	return it.provenLive() && it.worst().Level == secretrisk.Remote
}
