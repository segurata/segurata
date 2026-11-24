package tracker

import (
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

// Decisions with effects: answering a decision can add rules that every sync applies, so the
// items in scope close (ignored or accepted, with a reason naming the decision) and findings in
// scope found later never open an item. See docs/architecture.md, "Decisions and rules".

// Effects a rule can have.
const (
	EffectIgnore = "ignore"
	EffectAccept = "accept"
)

// Scope kinds a rule can name.
var scopeKinds = []string{"path", "repo", "account", "gcp-project"}

// Rule closes the items in its scope at every sync.
type Rule struct {
	Effect   string    `json:"effect"` // ignore or accept
	Scope    string    `json:"scope"`  // path:~/src/old | repo:owner/name | account:<glob> | gcp-project:<id>
	Reason   string    `json:"reason"`
	Decision string    `json:"decision,omitempty"` // the decide item whose answer added it
	At       time.Time `json:"at"`
}

// OptionEffect is the rule an answer to a decision would add: the option's label, the effect and
// the scope.
type OptionEffect struct {
	Option string `json:"option"`
	Effect string `json:"effect"`
	Scope  string `json:"scope"`
}

// ParseEffect reads "ignore:path:~/src/i4a" into its effect and scope.
func ParseEffect(spec string) (effect, scope string, err error) {
	effect, scope, _ = strings.Cut(strings.TrimSpace(spec), ":")
	if effect != EffectIgnore && effect != EffectAccept {
		return "", "", fmt.Errorf("effect %q: use ignore:<scope> or accept:<scope>", spec)
	}
	return effect, scope, checkScope(scope)
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

// ParseOption reads a decision option: "label" or "label=effect:kind:value".
func ParseOption(s string) (label string, eff *OptionEffect, err error) {
	label, spec, ok := strings.Cut(s, "=")
	label = strings.TrimSpace(label)
	if label == "" {
		return "", nil, fmt.Errorf("option %q has no label", s)
	}
	if !ok {
		return label, nil, nil
	}
	effect, scope, err := ParseEffect(spec)
	if err != nil {
		return "", nil, fmt.Errorf("option %q: %w", s, err)
	}
	return label, &OptionEffect{Option: label, Effect: effect, Scope: scope}, nil
}

func (r Rule) validate() error {
	if r.Effect != EffectIgnore && r.Effect != EffectAccept {
		return fmt.Errorf("rule effect %q", r.Effect)
	}
	return checkScope(r.Scope)
}

// HomePath writes a path inside the home directory as ~/…, as findings report paths.
func HomePath(p string) string {
	if home, err := os.UserHomeDir(); err == nil && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + p[len(home):]
	}
	return p
}

// under reports whether p is prefix or inside it; both are compared as HomePath writes them.
func under(p, prefix string) bool {
	p, prefix = HomePath(p), strings.TrimSuffix(HomePath(prefix), "/")
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// Under reports whether the item lies entirely under a path: every location of a rotate item, or
// every finding still reported of another item, has a path inside prefix. An item with none
// does not.
func (it *Item) Under(prefix string) bool {
	return it.allIn(func(p string) bool { return under(p, prefix) }, func(r FindingRef) string { return r.Path })
}

// allIn applies in to the path of every location of a rotate item, or to what field reads from
// every finding still reported of another item; false when there is nothing to test or a value is
// empty.
func (it *Item) allIn(in func(string) bool, field func(FindingRef) string) bool {
	var values []string
	if it.Secret != nil {
		for _, l := range it.Secret.Locations {
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

// Matches reports whether a rule's scope covers the whole item. Decisions and setup items are
// never in scope; path scopes cover rotate items by their locations.
func (r Rule) Matches(it *Item) bool {
	if it.Kind == KindDecide || it.Kind == KindSetup {
		return false
	}
	kind, value, _ := strings.Cut(r.Scope, ":")
	switch kind {
	case "path":
		return it.Under(value)
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
// in a rule's scope, and returns how many it closed. An item reopened by hand after the rule was
// added is left alone: the owner overrode it.
func (t *Tracker) applyRules(now time.Time) int {
	n := 0
	for _, it := range t.Items {
		if it.Status != Open && it.Status != InProgress && it.Status != Snoozed {
			continue
		}
		for _, r := range t.Rules {
			if !r.Matches(it) || it.reopenedByHandSince(r.At) {
				continue
			}
			reason := r.Reason
			if r.Decision != "" {
				reason = "by decision " + r.Decision + ": " + reason
			}
			if r.Effect == EffectAccept {
				_ = it.Accept(now, reason, "")
				it.Next = acceptedNext()
			} else {
				_ = it.Ignore(now, reason)
			}
			n++
			break
		}
	}
	return n
}

func (it *Item) reopenedByHandSince(at time.Time) bool {
	return slices.ContainsFunc(it.History, func(e Event) bool { return e.Action == actReopen && e.At.After(at) })
}

// DecideWithEffects answers a decision, adds the rules its answer carries (the matching option's
// effect, and every --ignore-scope and --accept-scope given) and applies them at once; it returns
// the rules added and how many items they closed.
func (t *Tracker) DecideWithEffects(it *Item, at time.Time, answer string, ignore, accept []string) ([]Rule, int, error) {
	if it.Decision == nil {
		return nil, 0, fmt.Errorf("%s is not a decision", it.ID)
	}
	reason := it.Decision.Question + " " + strings.TrimSpace(answer)
	var add []Rule
	newRule := func(effect, scope string) error {
		if err := checkScope(scope); err != nil {
			return err
		}
		add = append(add, Rule{Effect: effect, Scope: scope, Reason: reason, Decision: it.ID, At: at.UTC()})
		return nil
	}
	for _, e := range it.Decision.Effects {
		if answers(answer, e.Option) {
			if err := newRule(e.Effect, e.Scope); err != nil {
				return nil, 0, err
			}
		}
	}
	for _, s := range ignore {
		if err := newRule(EffectIgnore, s); err != nil {
			return nil, 0, err
		}
	}
	for _, s := range accept {
		if err := newRule(EffectAccept, s); err != nil {
			return nil, 0, err
		}
	}
	if err := it.Decide(at, answer); err != nil {
		return nil, 0, err
	}
	t.Rules = append(t.Rules, add...)
	for _, r := range add {
		it.Log(at, EvDecided, actRule, r.Effect+" "+r.Scope)
	}
	return add, t.applyRules(at), nil
}

// answers reports whether an answer picks an option: the label itself, or the label followed by
// ":" or a space ("yes: archive them").
func answers(answer, option string) bool {
	a, o := strings.ToLower(strings.TrimSpace(answer)), strings.ToLower(option)
	return a == o || strings.HasPrefix(a, o+":") || strings.HasPrefix(a, o+" ")
}

// DropRules removes the rules a decision added, when it is reopened; the items they closed stay
// as they are.
func (t *Tracker) DropRules(decision string) int {
	n := len(t.Rules)
	t.Rules = slices.DeleteFunc(t.Rules, func(r Rule) bool { return r.Decision == decision })
	return n - len(t.Rules)
}

// Leverage says, per option with an effect, how many open items answering it would close:
// `answering "yes" closes 128 items (P0 120, P1 8)`.
func (t *Tracker) Leverage(it *Item, now time.Time) []string {
	if it.Decision == nil {
		return nil
	}
	var out []string
	for _, e := range it.Decision.Effects {
		r := Rule{Effect: e.Effect, Scope: e.Scope}
		by := map[secretrisk.Priority]int{}
		n := 0
		for _, x := range t.Items {
			if x.Active(now) && r.Matches(x) {
				by[x.EffectivePriority()]++
				n++
			}
		}
		var parts []string
		for _, p := range append(prios, "") {
			if by[p] > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", textfmt.OrDash(string(p)), by[p]))
			}
		}
		s := fmt.Sprintf("answering %q closes %s", e.Option, count(n, "open item", "open items"))
		if len(parts) > 0 {
			s += " (" + strings.Join(parts, ", ") + ")"
		}
		out = append(out, s+" by "+e.Effect+" "+e.Scope)
	}
	return out
}
