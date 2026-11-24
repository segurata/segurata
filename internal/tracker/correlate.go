package tracker

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Correlation: a connector that reports a credential (the aws key in ~/.aws/credentials, a GCP
// service-account key file, an OpenAI or OpenRouter key) and local-secrets, which found the same
// secret (in that file, in git history, in a transcript), describe one problem. The rotate item owns
// it: the connector's finding is attached to it as evidence that the secret is live, raises its
// priority to the worse of the two, and the connector's own item closes as merged into it. A live
// key that also leaked out of the machine ranks first. See docs/architecture.md, "Correlation".

// credential says which connector findings stand for a secret, which rotate items they may match
// (by the secrets' service; empty matches any), the evidence keys holding the redacted hint and
// the file, and, for a provider's key, whether the finding names the key (facts) and the evidence
// key of its spend this month.
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

// Ways a credential matched a secret, strongest first. byPossible is a hint that fits more than
// one secret: recorded on each of them, merged into none.
const (
	byFingerprint = "fingerprint"
	byHint        = "hint"
	byPath        = "path"
	byPossible    = "possible"
)

// How sure a match is: certain by fingerprint; high by a hint that shows four or more characters of
// the value's end and the same known length on both sides; medium by a shorter tail, a length one
// side does not give, or the file.
const (
	confCertain = "certain"
	confHigh    = "high"
	confMedium  = "medium"
)

// confRank orders match confidences.
var confRank = map[string]int{confMedium: 1, confHigh: 2, confCertain: 3}

// hintConfidence is how sure a fit between two hints is.
func hintConfidence(a, b secretrisk.Hint) string {
	if a.Len > 0 && b.Len > 0 && min(len(a.Tail), len(b.Tail)) >= 4 {
		return confHigh
	}
	return confMedium
}

// claim is a connector finding (or a secret a connector signs in with) that stands for the secret
// of a rotate item.
type claim struct {
	item *Item
	ref  FindingRef
}

// secretIndex finds rotate items by fingerprint, location path and service.
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

// candidate is a rotate item a credential finding may stand for, and how sure that is.
type candidate struct {
	item       *Item
	confidence string
}

// match finds the rotate items a credential finding may stand for: the one with its fingerprint (a
// finding that carries one matches nothing else: the key in the file may have been rotated since
// the leak); else, among items of its services, those whose redacted hint fits the finding's and
// shows at least three characters of the value's end (enough to tell keys apart); else the most
// urgent of those in the file the finding names whose hint, when both have one, fits. Only a hint
// can give more than one candidate: two secrets whose hints both fit are told apart by nothing the
// provider shows, so the caller merges into neither. A file can hold several parts of one
// credential (ADC's client secret and refresh token), so there the most urgent stands for it.
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

// homePath writes an absolute path under the home directory as ~/…, the way locations are kept.
func homePath(p string) string {
	if p == "" || strings.HasPrefix(p, "~/") {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(p, home+"/") {
		return "~/" + strings.TrimPrefix(p, home+"/")
	}
	return p
}

// correlate finds, in the folded runs, every credential finding that stands for a rotate item's
// secret, and every secret a connector signed in with (run_end's secret fingerprints) that is one.
// A finding whose hint fits several secrets is merged into none: it comes back in possible, once
// per secret it may be. A finding whose item the owner accepted stays there: that risk was kept on
// purpose.
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
		for _, name := range sortedKeys(r.fingerprints) {
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

// keyFactsOf is what a provider's key finding says about the key: its name, last use and spend
// this month. Nil for credentials that are not a provider's keys.
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

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// attachLive puts on each rotate item the claims and possible matches of this sync, replacing the
// ones the same connector instances made before; those of instances not folded now stay.
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

// replaceRefs keeps the refs of instances not folded now, adds this sync's, sorted by id; nil when
// none are left.
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

// claimedBy maps each claimed finding to the rotate item that took it.
func claimedBy(claims map[string]claim) map[string]string {
	out := make(map[string]string, len(claims))
	for id, c := range claims {
		out[id] = c.item.ID
	}
	return out
}

// moveRefs takes the findings that now belong to another item (moved: finding id to item id) out
// of this one: a rotate item that owns the same secret, or the group a finding's rule now puts it
// in. An item left with nothing reported closes as merged into the item that took its finding,
// unless the owner closed it already.
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
	switch it.Status {
	case Open, InProgress, Snoozed, Done:
	default:
		return false
	}
	it.setStatus(now, Merged, EvMerged, actMerged, "merged into "+into+", which owns it now")
	it.MergedInto = into
	it.Next = &Next{Who: You, Action: "Nothing here: " + into + " owns this now.", Command: "segurata track show " + into}
	return true
}

// reopenMerged opens a merged item whose finding no rotate item claims any more: the credential is
// not that secret now (the key in the file was rotated, the leaked copy is a different key).
func (it *Item) reopenMerged(now time.Time) {
	from := it.MergedInto
	it.setStatus(now, Open, EvReopened, actAutoReopen, "no longer part of "+from)
}

// reopenProvenLive opens an ignored rotate item that a connector claims (see correlate): the key
// works, which contradicts "not a real problem", and the connector's own item has merged into this
// one, so leaving it ignored would leave a live key with no open item. The owner ignoring it again
// after the proof sticks. Only ignored items give way: an accepted one is a risk kept on purpose
// (the proof still raises its priority), a done one is governed by its working-file sightings (see
// rotatedSeen), and a reclassified one is never claimed.
func (it *Item) reopenProvenLive(now time.Time) {
	live := it.live()
	if it.Status != Ignored || len(live) == 0 || it.ignoredAfterProof() {
		return
	}
	var labels []string
	for _, r := range live {
		if !slices.Contains(labels, r.Label()) {
			labels = append(labels, r.Label())
		}
	}
	it.setStatus(now, Open, EvReopened, actProvenLive, "proven live by "+strings.Join(labels, ", ")+"; it was ignored: "+it.lastDetail(actIgnore))
}

// ignoredAfterProof reports whether the item's latest ignore came after a proof that it is live.
func (it *Item) ignoredAfterProof() bool {
	ignored := false
	for i := len(it.History) - 1; i >= 0; i-- {
		switch it.History[i].Action {
		case actIgnore:
			ignored = true
		case actProvenLive:
			return ignored
		}
	}
	return false
}

// live are the connector findings attached to a rotate item that are still reported: evidence the
// secret works.
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

// LiveAndLeaked reports whether a connector shows the secret is live and a copy of it left the
// machine (pushed git history, an agent transcript): the most urgent kind of secret.
func (it *Item) LiveAndLeaked() bool {
	return len(it.live()) > 0 && it.worst().Level == secretrisk.Remote
}
