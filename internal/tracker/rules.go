package tracker

import (
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/homepath"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

const (
	effectIgnore = "ignore"
	effectAccept = "accept"
)

var scopeKinds = []string{"path", "repo", "account", "gcp-project"}

// Rule closes the items in its scope at every sync. Answering a decision adds them; see
// docs/architecture.md, "Decisions and rules".
type Rule struct {
	Effect string `json:"effect"` // ignore or accept
	Scope  string `json:"scope"`  // path:~/src/old | repo:owner/name | account:<glob> | gcp-project:<id>
	// Owners narrow the rule to rotate items attributed to them; other items in scope stay open.
	Owners   []attribution.Owner `json:"owners,omitempty"`
	Reason   string              `json:"reason"`
	Decision string              `json:"decision,omitempty"` // the decide item whose answer added it
	At       time.Time           `json:"at"`
}

// OptionEffect is the rule answering a decision with Option adds.
type OptionEffect struct {
	Option string              `json:"option"`
	Effect string              `json:"effect"`
	Scope  string              `json:"scope"`
	Owners []attribution.Owner `json:"owners,omitempty"`
}

// parseEffect reads "ignore:path:~/src/old" or "ignore@not-mine:path:~/src/old".
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

// parseOption reads "label" or "label=effect:kind:value".
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

// spec is the rule as the command line writes it: "ignore@not-mine path:~/src/old".
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

// homePath writes a path inside the home directory as ~/…, as findings and locations keep paths.
func homePath(p string) string {
	home, _ := os.UserHomeDir()
	return homepath.Shorten(p, home)
}

func under(p, prefix string) bool {
	p, prefix = homePath(p), strings.TrimSuffix(homePath(prefix), "/")
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// liesUnder reports whether every current location, or every finding still reported, lies under
// prefix.
func (it *Item) liesUnder(prefix string) bool {
	return it.allIn(func(p string) bool { return under(p, prefix) }, func(r FindingRef) string { return r.Path })
}

// allIn reports whether in holds for the path of every current location of a rotate item, or the
// field of every finding still reported of another; false for none or an empty value.
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

func (r Rule) matches(it *Item) bool {
	return r.inScope(it) && r.ownerMatches(it)
}

func (r Rule) ownerMatches(it *Item) bool {
	return len(r.Owners) == 0 || slices.Contains(r.Owners, it.Owner())
}

// Owner is a rotate item's attribution, or "".
func (it *Item) Owner() attribution.Owner {
	if it.Secret == nil || it.Secret.Attribution == nil {
		return ""
	}
	return it.Secret.Attribution.Owner
}

// inScope reports whether the rule's scope covers the whole item, whoever owns it.
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

// applyRules closes every active item a rule covers, and returns how many. An item reopened after
// the rule, by hand or by proof of life, is left alone: the owner or the evidence overrode it.
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

func (r Rule) closing() string {
	if r.Decision != "" {
		return "by decision " + r.Decision + ": " + r.Reason
	}
	return r.Reason
}

// reopenReattributed opens an item a rule narrowed to owners closed, once its attribution is no
// longer one of them.
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

func (it *Item) reopenedSince(at time.Time) bool {
	return slices.ContainsFunc(it.History, func(e Event) bool {
		return (e.Action == actReopen || e.Action == actProvenLive) && e.At.After(at)
	})
}

// decideWithEffects answers a decision, adds the rules its answer carries and applies them; it
// returns them and how many items they closed. owners narrow the scopes given here, not the
// options'. A new answer replaces the old one and its rules; what they closed stays closed.
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

// answers reports whether an answer picks an option: the label, or the label and ":" or a space.
func answers(answer, option string) bool {
	a, o := strings.ToLower(strings.TrimSpace(answer)), strings.ToLower(option)
	return a == o || strings.HasPrefix(a, o+":") || strings.HasPrefix(a, o+" ")
}

func (t *Tracker) dropRules(decision string) int {
	n := len(t.Rules)
	t.Rules = slices.DeleteFunc(t.Rules, func(r Rule) bool { return r.Decision == decision })
	return n - len(t.Rules)
}

// optionLeverage is, per option with an effect, `answering "yes" closes 128 items (P0 120, P1 8)`.
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

// leverage is "closes 120 open items (P0 100, P1 20) attributed not-mine, keeps 8 open (mine 5,
// unknown 3)".
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
				name = "not secrets"
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
