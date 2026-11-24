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
// (by the secrets' service; empty matches any) and the evidence keys holding the redacted hint and
// the file.
type credential struct {
	connector string
	resources []string
	services  []string
	hint      string
	path      string
}

var credentials = []credential{
	{"aws", []string{"aws_local_credentials"}, []string{"aws"}, "key_id", "file"},
	{"aws", []string{"r2_local_credentials", "s3_local_credentials"}, nil, "key_id", "file"},
	{"gcp", []string{"local_credential"}, []string{"gcp", "google", "oauth", "private-key"}, "", "path"},
	{"openai", []string{"api_key"}, []string{"openai"}, "redacted", ""},
	{"openrouter", []string{"api_key"}, []string{"openrouter"}, "redacted", ""},
	{"anthropic", []string{"api_key"}, []string{"anthropic"}, "redacted", ""},
}

func credentialFor(f finding.Finding) *credential {
	for i := range credentials {
		if c := &credentials[i]; c.connector == f.Connector && slices.Contains(c.resources, f.Resource.Type) {
			return c
		}
	}
	return nil
}

// Ways a credential matched a secret, strongest first.
const (
	byFingerprint = "fingerprint"
	byHint        = "hint"
	byPath        = "path"
)

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
			if !seen[l.Path] {
				seen[l.Path] = true
				x.byPath[l.Path] = append(x.byPath[l.Path], it)
			}
		}
	}
	return x
}

// match finds the rotate item a credential finding stands for: the one with its fingerprint (a
// finding that carries one matches nothing else: the key in the file may have been rotated since
// the leak); else, among items of its services, one whose redacted hint fits the finding's and shows at
// least three characters of the value's end (enough to tell keys apart); else one in the file the
// finding names whose hint, when both have one, fits. Among several, the most urgent wins.
func (x secretIndex) match(f finding.Finding, c *credential) (*Item, string) {
	str := func(k string) string { s, _ := f.Evidence[k].(string); return s }
	if fp := str("fingerprint"); fp != "" {
		if it := x.byFP[fp]; it != nil {
			return it, byFingerprint
		}
		return nil, ""
	}
	hint, hasHint := normalHint(str(c.hint))
	serviceOK := func(it *Item) bool { return len(c.services) == 0 || slices.Contains(c.services, it.Secret.Service) }
	if hasHint && len(hint.Tail) >= 3 {
		var hits []*Item
		for _, s := range c.services {
			for _, it := range x.byService[s] {
				if h, ok := normalHint(it.Secret.Redacted); ok && hintsFit(h, hint) {
					hits = append(hits, it)
				}
			}
		}
		if it := mostUrgent(hits); it != nil {
			return it, byHint
		}
	}
	if p := homePath(str(c.path)); p != "" {
		var hits []*Item
		for _, it := range x.byPath[p] {
			if !serviceOK(it) || it.Priority == "" {
				continue
			}
			if h, ok := normalHint(it.Secret.Redacted); hasHint && ok && !hintsFit(h, hint) {
				continue
			}
			hits = append(hits, it)
		}
		if it := mostUrgent(hits); it != nil {
			return it, byPath
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

// normalHint reads the redacted forms connectors use: segurata's own ("AKIA…(20)", "sk-or-v1-…d4d1(73)"),
// OpenRouter's ("sk-or-v1-27e...d4d") and OpenAI's ("sk-proj-****…xxkA"). Len is 0 when the form
// does not give it. ok is false when the text is not a hint of one value.
func normalHint(s string) (secretrisk.Hint, bool) {
	if h, ok := secretrisk.ParseHint(s); ok {
		return h, true
	}
	for _, sep := range []string{"...", "…"} {
		if i := strings.Index(s, sep); i > 0 {
			pre, tail := s[:i], s[i+len(sep):]
			return secretrisk.Hint{Prefix: strings.TrimRight(pre, "*"), Tail: strings.TrimLeft(tail, "*")}, true
		}
	}
	if i, j := strings.IndexByte(s, '*'), strings.LastIndexByte(s, '*'); i > 0 && j < len(s)-1 {
		return secretrisk.Hint{Prefix: s[:i], Tail: s[j+1:]}, true
	}
	return secretrisk.Hint{}, false
}

// hintsFit reports whether two hints can describe the same value: one prefix starts the other,
// one tail ends the other, and the lengths agree when both are known.
func hintsFit(a, b secretrisk.Hint) bool {
	if a.Len > 0 && b.Len > 0 && a.Len != b.Len {
		return false
	}
	return (strings.HasPrefix(a.Prefix, b.Prefix) || strings.HasPrefix(b.Prefix, a.Prefix)) &&
		(strings.HasSuffix(a.Tail, b.Tail) || strings.HasSuffix(b.Tail, a.Tail))
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
// A finding whose item the owner accepted stays there: that risk was kept on purpose.
func (t *Tracker) correlate(folded map[string]*run) map[string]claim {
	x := t.secretIndex()
	accepted := map[string]bool{}
	for _, it := range t.Items {
		if it.Kind != KindRotate && it.Status == Accepted {
			for _, r := range it.Findings {
				accepted[r.ID] = true
			}
		}
	}
	out := map[string]claim{}
	for _, r := range folded {
		for _, f := range r.findings {
			c := credentialFor(f)
			if c == nil || accepted[f.ID] {
				continue
			}
			if it, how := x.match(f, c); it != nil {
				ref := refOf(f)
				ref.Match = how
				out[f.ID] = claim{item: it, ref: ref}
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
			out[id] = claim{item: it, ref: FindingRef{ID: id, Connector: conn, Instance: inst, Title: title, LastSeen: r.at, Match: byFingerprint}}
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// attachLive puts on each rotate item the claims of this sync, replacing the ones the same
// connector instances made before; claims of instances not folded now stay.
func (t *Tracker) attachLive(claims map[string]claim, folded map[string]*run) {
	by := map[*Item][]FindingRef{}
	for _, c := range claims {
		by[c.item] = append(by[c.item], c.ref)
	}
	for _, it := range t.Items {
		if it.Kind != KindRotate {
			continue
		}
		kept := it.Findings[:0]
		for _, r := range it.Findings {
			if _, now := folded[r.Label()]; !now {
				kept = append(kept, r)
			}
		}
		refs := append(kept, by[it]...)
		sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
		if len(refs) == 0 {
			refs = nil
		}
		it.Findings = refs
		it.derive()
	}
}

// mergeClaimed takes the claimed findings out of a connector item: they belong to the rotate item
// now. An item left with nothing reported closes as merged into the rotate item that took its
// finding, unless the owner closed it already.
func (it *Item) mergeClaimed(claims map[string]claim, now time.Time) bool {
	into := ""
	kept := it.Findings[:0]
	for _, r := range it.Findings {
		if c, ok := claims[r.ID]; ok {
			if into == "" {
				into = c.item.ID
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
	it.setStatus(now, Merged, EvMerged, actMerged, "the same secret as "+into+", which owns it now")
	it.MergedInto = into
	it.Next = &Next{Who: You, Action: "Nothing here: " + into + " owns this secret; rotate it there.", Command: "segurata track show " + into}
	return true
}

// reopenMerged opens a merged item whose finding no rotate item claims any more: the credential is
// not that secret now (the key in the file was rotated, the leaked copy is a different key).
func (it *Item) reopenMerged(now time.Time) {
	from := it.MergedInto
	it.setStatus(now, Open, EvReopened, actAutoReopen, "no longer the same secret as "+from)
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
