package tracker

import (
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

// Decisions with effects: answering a decision can add rules that every sync applies, so the
// items in scope close (ignored or accepted, with a reason naming the decision) and findings in
// scope found later never open an item. See docs/architecture.md, "Decisions and rules".

// Effects a rule can have.
const (
	effectIgnore = "ignore"
	effectAccept = "accept"
)

// Scope kinds a rule can name.
var scopeKinds = []string{"path", "repo", "account", "gcp-project"}

// Rule closes the items in its scope at every sync.
type Rule struct {
	Effect string `json:"effect"` // ignore or accept
	Scope  string `json:"scope"`  // path:~/src/old | repo:owner/name | account:<glob> | gcp-project:<id>
	// Owners, when set, narrow the rule to rotate items attributed to one of these owners
	// ("not-mine": rotate my secrets, ignore the rest). Other items in scope stay open.
	Owners   []attribution.Owner `json:"owners,omitempty"`
	Reason   string              `json:"reason"`
	Decision string              `json:"decision,omitempty"` // the decide item whose answer added it
	At       time.Time           `json:"at"`
}

// OptionEffect is the rule an answer to a decision would add: the option's label, the effect and
// the scope.
type OptionEffect struct {
	Option string              `json:"option"`
	Effect string              `json:"effect"`
	Scope  string              `json:"scope"`
	Owners []attribution.Owner `json:"owners,omitempty"`
}

// parseEffect reads "ignore:path:~/src/legacyco", or "ignore@not-mine:path:~/src/legacyco" for a rule that
// closes only rotate items attributed to those owners, into its effect, scope and owners.
func parseEffect(spec string) (effect, scope string, owners []attribution.Owner, err error) {
	effect, scope, _ = strings.Cut(strings.TrimSpace(spec), ":")
	effect, who, narrowed := strings.Cut(effect, "@")
	if effect != effectIgnore && effect != effectAccept {
		return "", "", nil, fmt.Errorf("effect %q: use ignore:<scope> or accept:<scope>, optionally ignore@<owners>:<scope>", spec)
	}
	if narrowed {
		if owners, err = attribution.ParseOwners(who); err != nil {
			return "", "", nil, fmt.Errorf("effect %q: %w", spec, err)
		}
	}
	return effect, scope, owners, checkScope(scope)
}

// checkScope validates "kind:value".
func checkScope(scope string) error {
	kind, value, ok := strings.Cut(scope, ":")
	switch {
	case !ok || strings.TrimSpace(value) == "":
		return fmt.Errorf("scope %q: use path:<dir>, repo:<owner/name>, account:<glob> or gcp-project:<id>", scope)
	case !slices.Contains(scopeKinds, kind):
		return fmt.Errorf("scope kind %q: use %s", kind, strings.Join(scopeKinds, ", "))
	case kind == "account":
		if _, err := path.Match(value, ""); err != nil {
			return fmt.Errorf("scope %q: %w", scope, err)
		}
	}
	return nil
}

// parseOption reads a decision option: "label" or "label=effect:kind:value".
func parseOption(s string) (label string, eff *OptionEffect, err error) {
	label, spec, ok := strings.Cut(s, "=")
	label = strings.TrimSpace(label)
	if label == "" {
		return "", nil, fmt.Errorf("option %q has no label", s)
	}
	if !ok {
		return label, nil, nil
	}
	effect, scope, owners, err := parseEffect(spec)
	if err != nil {
		return "", nil, fmt.Errorf("option %q: %w", s, err)
	}
	return label, &OptionEffect{Option: label, Effect: effect, Scope: scope, Owners: owners}, nil
}

func (r Rule) validate() error {
	if r.Effect != effectIgnore && r.Effect != effectAccept {
		return fmt.Errorf("rule effect %q", r.Effect)
	}
	for _, o := range r.Owners {
		if !slices.Contains(attribution.Owners, o) {
			return fmt.Errorf("rule owner %q", o)
		}
	}
	return checkScope(r.Scope)
}

// spec is the rule as the command line writes it: "ignore path:~/src/legacyco", "ignore@not-mine
// path:~/src/legacyco".
func (r Rule) spec() string {
	return r.Effect + ownersSuffix(r.Owners) + " " + r.Scope
}

func ownersSuffix(owners []attribution.Owner) string {
	if len(owners) == 0 {
		return ""
	}
	parts := make([]string, len(owners))
	for i, o := range owners {
		parts[i] = string(o)
	}
	return "@" + strings.Join(parts, ",")
}

// homePath writes a path inside the home directory as ~/…, as findings report paths.
func homePath(p string) string {
	if home, err := os.UserHomeDir(); err == nil && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + p[len(home):]
	}
	return p
}

// under reports whether p is prefix or inside it; both are compared as HomePath writes them.
func under(p, prefix string) bool {
	p, prefix = homePath(p), strings.TrimSuffix(homePath(prefix), "/")
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// liesUnder reports whether the item lies entirely under a path: every current location of a rotate
// item, or every finding still reported of another item, has a path inside prefix. An item with
// none does not.
func (it *Item) liesUnder(prefix string) bool {
	return it.allIn(func(p string) bool { return under(p, prefix) }, func(r FindingRef) string { return r.Path })
}

// allIn applies in to the path of every current location of a rotate item, or to what field reads
// from every finding still reported of another item; false when there is nothing to test or a value
// is empty.
func (it *Item) allIn(in func(string) bool, field func(FindingRef) string) bool {
	var values []string
	if it.Secret != nil {
		for _, l := range it.current() {
			values = append(values, l.Path)
		}
	} else {
		for _, r := range it.Findings {
			if !r.Gone {
				values = append(values, field(r))
			}
		}
	}
	if len(values) == 0 {
		return false
	}
	for _, v := range values {
		if v == "" || !in(v) {
			return false
		}
	}
	return true
}

// matches reports whether a rule covers the whole item: its scope does and, for a rule narrowed
// to owners, the item is a rotate item attributed to one of them.
func (r Rule) matches(it *Item) bool {
	return r.inScope(it) && r.ownerMatches(it)
}

// ownerMatches reports whether the item's attribution is one of the rule's owners; true for a rule
// not narrowed to owners. Items without attribution never match a narrowed rule.
func (r Rule) ownerMatches(it *Item) bool {
	return len(r.Owners) == 0 || slices.Contains(r.Owners, it.Owner())
}

// Owner is a rotate item's attribution, or "" for items that have none.
func (it *Item) Owner() attribution.Owner {
	if it.Secret == nil || it.Secret.Attribution == nil {
		return ""
	}
	return it.Secret.Attribution.Owner
}

// inScope reports whether a rule's scope covers the whole item, whoever owns it. Decisions and
// setup items are never in scope; path scopes cover rotate items by their locations.
func (r Rule) inScope(it *Item) bool {
	if it.Kind == KindDecide || it.Kind == KindSetup {
		return false
	}
	kind, value, _ := strings.Cut(r.Scope, ":")
	switch kind {
	case "path":
		return it.liesUnder(value)
	case "repo":
		return it.Secret == nil && it.allIn(func(v string) bool { return strings.EqualFold(v, value) }, func(f FindingRef) string { return f.Repo })
	case "account":
		return it.Secret == nil && it.allIn(func(v string) bool { ok, _ := path.Match(value, v); return ok }, func(f FindingRef) string { return f.Account })
	case "gcp-project":
		return it.Secret == nil && it.allIn(func(v string) bool { return v == value }, func(f FindingRef) string { return f.Project })
	}
	return false
}

// applyRules closes, with the first rule that covers it, every open, in-progress or snoozed item
// in a rule's scope, and returns how many it closed. An item reopened after the rule was added, by
// hand or because a connector proved its secret live, is left alone: the owner or the evidence
// overrode it. An item a rule narrowed to owners closed opens again (auto-reopen) once its
// attribution is no longer one of them: a key that turned out to be the owner's is rotated after
// all. An ignored secret a connector proves live opens again too (see reopenProvenLive).
func (t *Tracker) applyRules(now time.Time) int {
	n := 0
	for _, it := range t.Items {
		t.reopenReattributed(it, now)
		it.reopenProvenLive(now)
		it.reopenUndead(now)
		it.closeDead(now)
		if it.Status != Open && it.Status != InProgress && it.Status != Snoozed {
			continue
		}
		for _, r := range t.Rules {
			if !r.matches(it) || it.reopenedSince(r.At) {
				continue
			}
			reason := r.closing()
			if a := it.Secret; len(r.Owners) > 0 && a != nil && a.Attribution != nil {
				reason += "; attributed " + string(a.Attribution.Owner)
				if len(a.Attribution.Reasons) > 0 {
					reason += ": " + a.Attribution.Reasons[0]
				}
			}
			if r.Effect == effectAccept {
				_ = it.accept(now, reason, "")
				it.Next = acceptedNext()
			} else {
				_ = it.ignore(now, reason)
			}
			n++
			break
		}
	}
	return n
}

// closing is the reason a rule gives the items it closes, before any attribution detail.
func (r Rule) closing() string {
	if r.Decision != "" {
		return "by decision " + r.Decision + ": " + r.Reason
	}
	return r.Reason
}

// reopenReattributed opens an item that a rule narrowed to owners ignored or accepted when the item
// is no longer attributed to one of them.
func (t *Tracker) reopenReattributed(it *Item, now time.Time) {
	var detail string
	switch it.Status {
	case Ignored:
		detail = it.lastDetail(actIgnore)
	case Accepted:
		detail = it.lastDetail(actAccept)
	default:
		return
	}
	for _, r := range t.Rules {
		if len(r.Owners) == 0 || !strings.HasPrefix(detail, r.closing()+"; attributed ") || !r.inScope(it) || r.ownerMatches(it) {
			continue
		}
		it.Accepted = nil
		it.setStatus(now, Open, EvReopened, actAutoReopen, "now attributed "+string(it.Owner())+", which "+r.spec()+" leaves open")
		return
	}
}

// reopenedSince reports whether the item was reopened by hand, or by proof that its secret is live,
// after at.
func (it *Item) reopenedSince(at time.Time) bool {
	return slices.ContainsFunc(it.History, func(e Event) bool {
		return (e.Action == actReopen || e.Action == actProvenLive) && e.At.After(at)
	})
}

// decideWithEffects answers a decision, adds the rules its answer carries (the matching option's
// effect, and every --ignore-scope and --accept-scope given) and applies them at once; it returns
// the rules added and how many items they closed.
//
// owners, when given, narrow the rules of the scopes given here (not those of the options, which
// carry their own) to rotate items attributed to those owners.
//
// A decision answered before is answered again: the new answer replaces the old one and its rules,
// as reopening and answering would; the items the old rules closed stay as they are.
func (t *Tracker) decideWithEffects(it *Item, at time.Time, answer string, ignore, accept []string, owners []attribution.Owner) ([]Rule, int, error) {
	add, err := t.decisionRules(it, at, answer, ignore, accept, owners)
	if err != nil {
		return nil, 0, err
	}
	prev := it.Decision.Answer
	if err := it.decide(at, answer); err != nil {
		return nil, 0, err
	}
	if prev != "" {
		n := t.dropRules(it.ID)
		it.Log(at, EvDecided, actReanswer, fmt.Sprintf("replaces the answer %q; %s of it removed, the items they closed stay as they are",
			prev, textfmt.Count(n, "rule", "rules")))
	}
	t.Rules = append(t.Rules, add...)
	for _, r := range add {
		it.Log(at, EvDecided, actRule, r.spec())
	}
	return add, t.applyRules(at), nil
}

// decisionRules are the rules answering a decision would add, without adding them.
func (t *Tracker) decisionRules(it *Item, at time.Time, answer string, ignore, accept []string, owners []attribution.Owner) ([]Rule, error) {
	if it.Decision == nil {
		return nil, fmt.Errorf("%s is not a decision", it.ID)
	}
	reason := it.Decision.Question + " " + strings.TrimSpace(answer)
	var add []Rule
	newRule := func(effect, scope string, owners []attribution.Owner) error {
		if err := checkScope(scope); err != nil {
			return err
		}
		add = append(add, Rule{Effect: effect, Scope: scope, Owners: owners, Reason: reason, Decision: it.ID, At: at.UTC()})
		return nil
	}
	for _, e := range it.Decision.Effects {
		if answers(answer, e.Option) {
			if err := newRule(e.Effect, e.Scope, e.Owners); err != nil {
				return nil, err
			}
		}
	}
	for _, s := range ignore {
		if err := newRule(effectIgnore, s, owners); err != nil {
			return nil, err
		}
	}
	for _, s := range accept {
		if err := newRule(effectAccept, s, owners); err != nil {
			return nil, err
		}
	}
	return add, nil
}

// previewDecision says what answering would do, without changing anything: one leverage line per
// rule the answer adds.
func (t *Tracker) previewDecision(it *Item, now time.Time, answer string, ignore, accept []string, owners []attribution.Owner) ([]string, error) {
	rules, err := t.decisionRules(it, now, answer, ignore, accept, owners)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, t.leverage(r, now)+" by "+r.spec())
	}
	return out, nil
}

// answers reports whether an answer picks an option: the label itself, or the label followed by
// ":" or a space ("yes: archive them").
func answers(answer, option string) bool {
	a, o := strings.ToLower(strings.TrimSpace(answer)), strings.ToLower(option)
	return a == o || strings.HasPrefix(a, o+":") || strings.HasPrefix(a, o+" ")
}

// dropRules removes the rules a decision added, when it is reopened; the items they closed stay
// as they are.
func (t *Tracker) dropRules(decision string) int {
	n := len(t.Rules)
	t.Rules = slices.DeleteFunc(t.Rules, func(r Rule) bool { return r.Decision == decision })
	return n - len(t.Rules)
}

// optionLeverage says, per option with an effect, how many open items answering it would close:
// `answering "yes" closes 128 items (P0 120, P1 8)`.
func (t *Tracker) optionLeverage(it *Item, now time.Time) []string {
	if it.Decision == nil {
		return nil
	}
	var out []string
	for _, e := range it.Decision.Effects {
		r := Rule{Effect: e.Effect, Scope: e.Scope, Owners: e.Owners}
		out = append(out, fmt.Sprintf("answering %q %s by %s", e.Option, t.leverage(r, now), r.spec()))
	}
	return out
}

// leverage says how many open items a rule would close, by priority, and for a rule narrowed to
// owners how many in its scope it keeps open, by attribution: "closes 120 open items (P0 100, P1
// 20) attributed not-mine, keeps 8 open (mine 5, unknown 3)".
func (t *Tracker) leverage(r Rule, now time.Time) string {
	by := map[secretrisk.Priority]int{}
	kept := map[attribution.Owner]int{}
	n, k := 0, 0
	for _, x := range t.Items {
		switch {
		case !x.Active(now) || !r.inScope(x):
		case r.ownerMatches(x):
			by[x.EffectivePriority()]++
			n++
		default:
			kept[x.Owner()]++
			k++
		}
	}
	var parts []string
	for _, p := range append(prios, "") {
		if by[p] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", textfmt.OrDash(string(p)), by[p]))
		}
	}
	s := "closes " + textfmt.Count(n, "open item", "open items")
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	if len(r.Owners) == 0 {
		return s
	}
	s += " attributed " + strings.TrimPrefix(ownersSuffix(r.Owners), "@")
	var keptParts []string
	for _, o := range append(attribution.Owners, "") {
		if kept[o] > 0 {
			name := string(o)
			if o == "" {
				name = "not secrets" // items other than rotate items carry no attribution
			}
			keptParts = append(keptParts, fmt.Sprintf("%s %d", name, kept[o]))
		}
	}
	s += ", keeps " + textfmt.Count(k, "open", "open")
	if len(keptParts) > 0 {
		s += " (" + strings.Join(keptParts, ", ") + ")"
	}
	return s
}
