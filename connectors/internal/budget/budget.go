// Package budget judges spend budgets with rules that do not depend on the provider. A connector
// maps its provider's budgets to Budget, describes the container that holds them (a billing
// account, an account, a subscription) and the spend risks it found there, and gets back findings
// that mean the same on every provider. See docs/connectors.md, "Spend and budgets".
package budget

import (
	"cmp"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

// Threshold is one alert rule of a budget.
type Threshold struct {
	Percent  float64 // of the budget amount: 100 is the whole amount
	Forecast bool    // fires on forecasted spend instead of actual spend
}

// Scope is what spend a budget counts. Units empty means every unit of the container.
type Scope struct {
	Units   []string // units of the container (GCP projects) the budget is limited to
	Filters []string // any other narrowing, worded for people ("2 services"); part of the identity
}

// Budget is one provider budget in neutral terms.
type Budget struct {
	ID         string // provider id, stable across runs
	Name       string
	Amount     float64
	Currency   string // ISO code, "" when the provider does not say
	Period     string // PeriodMonth, PeriodQuarter, PeriodYear, PeriodDay or PeriodCustom
	LastPeriod bool   // the amount follows the last period's spend
	Thresholds []Threshold
	Scope      Scope
	Notifies   []string // who or what is told when a threshold fires: NotifyAdmins, NotifyEmails…
	Actions    []string // automatic hooks that can stop spend: ActionPubSub, ActionSpendCap…
}

const (
	PeriodDay     = "day"
	PeriodMonth   = "month"
	PeriodQuarter = "quarter"
	PeriodYear    = "year"
	PeriodCustom  = "custom"
)

// Notification channels. A budget with none of them and no action alerts nobody.
const (
	NotifyAdmins      = "email-admins"       // the provider's default billing recipients
	NotifyEmails      = "email-list"         // addresses set on the budget
	NotifyRoles       = "email-roles"        // everyone holding named roles
	NotifyProject     = "email-project"      // owners of the one project the budget covers
	NotifyMonitoring  = "monitoring"         // monitoring notification channels
	NotifySubscribers = "subscribers"        // provider subscribers whose kind is not read
	NotifyPubSub      = "pubsub"             // a message topic
	NotifyActionGroup = "action-group"       // an alerting group that can call code
	ActionPubSub      = "pubsub-topic"       // GCP: a topic a function can act on
	ActionSpendCap    = "spend-cap"          // GCP: the budget's own spend cap
	ActionBudget      = "budget-action"      // AWS: an IAM, SCP or instance action
	ActionActionGroup = "azure-action-group" // Azure: an action group on an alert
)

// Risk is a count of credentials or settings that let someone run spend up, found in one unit
// of the container ("" for the container as a whole).
type Risk struct {
	Unit  string
	What  string // singular noun phrase, "unrestricted API key"; the plural adds an s
	Count int
}

// Container is the billing scope the budgets belong to.
type Container struct {
	ID    string   // stable id, part of every finding's resource id
	Label string   // how titles name it: "billing account 0000-…", "account prod"
	Units []string // units billed to it (GCP projects), when the provider has them
	Risks []Risk
	// ActionsUnknown skips the enforcement rule when the provider could not say whether any
	// automatic action exists (a denied read).
	ActionsUnknown bool
	// NoBudget is the resource of the container-level finding: no budget with alerts, or the
	// summary when there are budgets. Connectors keep the one earlier versions used, so its id
	// and any acceptance of it survive.
	NoBudget finding.Resource
}

// Wording is what a provider supplies so the findings speak its terms.
type Wording struct {
	UnitNoun   string // "project"; "" when the container has no units
	AllScope   string // scope of an unfiltered budget: "all projects", "whole account"
	ConsoleURL string // where this container's budgets are edited; DocsURL when empty
	DocsURL    string // how to create a budget with alerts
	ActionNoun string // the automatic hook: "a Pub/Sub topic or a spend cap"
	CapHowTo   string // how to make a budget stop spend, one or two sentences
	CapURL     string
	RisksWhere string // where the risks live: "in projects billed here"
}

// Alerting reports whether the budget tells anyone when a threshold is crossed.
func (b Budget) Alerting() bool {
	return len(b.Thresholds) > 0 && (len(b.Notifies) > 0 || len(b.Actions) > 0)
}

// Covers reports whether the budget counts the unit's spend.
func (b Budget) Covers(unit string) bool {
	return len(b.Scope.Units) == 0 || slices.Contains(b.Scope.Units, unit)
}

func (b Budget) hasActual(min float64) bool {
	return slices.ContainsFunc(b.Thresholds, func(t Threshold) bool { return !t.Forecast && t.Percent >= min })
}

func (b Budget) hasForecast() bool {
	return slices.ContainsFunc(b.Thresholds, func(t Threshold) bool { return t.Forecast })
}

// Evaluate applies every rule to the container's budgets. Findings carry no account or scope:
// the connector stamps them.
func Evaluate(c Container, budgets []Budget, w Wording) []finding.Finding {
	j := judge{c: c, w: w}
	var alerting []Budget
	for _, b := range budgets {
		if b.Alerting() {
			alerting = append(alerting, b)
		}
	}
	if len(alerting) == 0 {
		return []finding.Finding{j.noBudget(len(budgets))}
	}
	out := []finding.Finding{j.summary(budgets)}
	for _, b := range alerting {
		if f, ok := j.thresholds(b); ok {
			out = append(out, f)
		}
	}
	out = append(out, j.duplicates(budgets)...)
	if f, ok := j.enforcement(budgets); ok {
		out = append(out, f)
	}
	out = append(out, j.scopeGaps(alerting)...)
	out = append(out, j.uncovered(alerting)...)
	return out
}

type judge struct {
	c Container
	w Wording
}

func (j judge) finding(res finding.Resource, sev finding.Severity, title string, ev map[string]any, rem finding.Remediation) finding.Finding {
	return finding.Finding{Resource: res, Kind: finding.KindSpend, Severity: sev, Title: title, Evidence: ev, Remediation: rem}
}

func (j judge) console() string {
	if j.w.ConsoleURL != "" {
		return j.w.ConsoleURL
	}
	return j.w.DocsURL
}

func (j judge) budgetRes(kind string, b Budget) finding.Resource {
	return finding.Resource{Type: kind, ID: j.c.ID + "/" + b.ID, Name: b.Name}
}

func (j judge) noBudget(total int) finding.Finding {
	return j.finding(j.c.NoBudget, finding.SevHigh,
		upperFirst(j.c.Label)+" has no budget with alerts: nothing warns you when spend runs away",
		map[string]any{"budgets": total, "units": j.c.Units},
		finding.Remediation{
			Summary: "Create a budget with alerts at 50%, 90% and 100% of actual spend and at 100% of forecasted spend. " + j.w.CapHowTo,
			URL:     j.w.DocsURL,
		})
}

// summary lists the budgets, so the inventory shows what is configured and not only what is wrong.
func (j judge) summary(budgets []Budget) finding.Finding {
	const shown = 3
	parts := make([]string, 0, shown)
	list := make([]any, 0, len(budgets))
	for i, b := range budgets {
		if i < shown {
			parts = append(parts, fmt.Sprintf("'%s' %s", b.Name, j.describe(b)))
		}
		list = append(list, evidence(b))
	}
	title := fmt.Sprintf("%s has %s: %s", upperFirst(j.c.Label), plural(len(budgets), "budget"), strings.Join(parts, "; "))
	if n := len(budgets) - shown; n > 0 {
		title += fmt.Sprintf("; and %d more", n)
	}
	return j.finding(j.c.NoBudget, finding.SevInfo, title, map[string]any{"budgets": list},
		finding.Remediation{Summary: "Nothing to do; the other budget findings say what to change.", URL: j.console()})
}

// thresholds: no alert at or above 100% of actual spend is medium (the bill can pass the budget
// in silence); a budget that has one but no forecasted threshold is low (no early warning).
func (j judge) thresholds(b Budget) (finding.Finding, bool) {
	ev := evidence(b)
	head := fmt.Sprintf("Budget '%s' (%s)", b.Name, j.describe(b))
	if !b.hasActual(100) {
		var add []string
		if !b.hasActual(90) {
			add = append(add, "90%")
		}
		add = append(add, "100%")
		if !b.hasForecast() {
			add = append(add, "a forecasted threshold")
		}
		return j.finding(j.budgetRes("budget_thresholds", b), finding.SevMedium,
			fmt.Sprintf("%s %s: add %s", head, thresholdPhrase(b.Thresholds), join(add)), ev,
			finding.Remediation{
				Summary: "Edit the budget's thresholds: without one at 100% of actual spend, nobody hears when the budget is spent. " +
					"Add 90% and 100% of actual spend and 100% of forecasted spend.",
				URL: j.console(),
			}), true
	}
	if !b.hasForecast() {
		return j.finding(j.budgetRes("budget_thresholds", b), finding.SevLow,
			fmt.Sprintf("%s has no forecasted threshold: add one at 100%% to hear before the money is spent", head), ev,
			finding.Remediation{
				Summary: "Add a threshold at 100% of forecasted spend: it fires when the period is on course to pass the budget, days before actual spend does.",
				URL:     j.console(),
			}), true
	}
	return finding.Finding{}, false
}

// duplicates groups budgets with the same scope, amount and period: each group is one low
// finding naming them, since every copy sends the same alerts.
func (j judge) duplicates(budgets []Budget) []finding.Finding {
	groups := map[string][]Budget{}
	for _, b := range budgets {
		groups[identity(b)] = append(groups[identity(b)], b)
	}
	var out []finding.Finding
	for _, key := range slices.Sorted(maps.Keys(groups)) {
		g := groups[key]
		if len(g) < 2 {
			continue
		}
		ids, names := make([]string, len(g)), make([]string, len(g))
		list := make([]any, len(g))
		for i, b := range g {
			ids[i], names[i], list[i] = b.ID, b.Name, evidence(b)
		}
		slices.Sort(ids)
		who := fmt.Sprintf("%d budgets named '%s'", len(g), g[0].Name)
		if slices.ContainsFunc(names, func(n string) bool { return n != g[0].Name }) {
			quoted := make([]string, len(names))
			for i, n := range names {
				quoted[i] = "'" + n + "'"
			}
			who = "Budgets " + join(quoted)
		}
		fix := "delete one"
		if len(g) > 2 {
			fix = "keep one"
		}
		out = append(out, j.finding(finding.Resource{Type: "budget_duplicates", ID: j.c.ID + "/" + strings.Join(ids, "+"), Name: g[0].Name},
			finding.SevLow,
			fmt.Sprintf("%s on %s are the same (%s): %s", upperFirst(who), j.c.Label, j.describe(g[0]), fix),
			map[string]any{"budgets": list},
			finding.Remediation{
				Summary: "These budgets count the same spend against the same amount, so each alert arrives once per copy. " +
					"Keep the one with the best thresholds and delete the rest. Providers create some budgets on their own " +
					"(Google adds one when Maps Platform is set up), which is how copies appear.",
				URL: j.console(),
			}))
	}
	return out
}

// enforcement: budgets notify, they do not stop spend. When no budget is wired to an automatic
// action, one finding for the container says how to cap spend: info, medium when this run found
// credentials or settings there that let someone run spend up.
func (j judge) enforcement(budgets []Budget) (finding.Finding, bool) {
	if j.c.ActionsUnknown || slices.ContainsFunc(budgets, func(b Budget) bool { return len(b.Actions) > 0 }) {
		return finding.Finding{}, false
	}
	title := fmt.Sprintf("Budgets on %s only notify: none is wired to %s, so nothing stops spend", j.c.Label, j.w.ActionNoun)
	sev := finding.SevInfo
	ev := map[string]any{"budgets": len(budgets)}
	if risks := totalRisks(j.c.Risks); len(risks) > 0 {
		sev = finding.SevMedium
		title += "; " + risks + " " + j.w.RisksWhere
		ev["risks"] = riskEvidence(j.c.Risks)
	}
	return j.finding(finding.Resource{Type: "budget_enforcement", ID: j.c.ID, Name: j.c.Label}, sev, title, ev,
		finding.Remediation{Summary: j.w.CapHowTo, URL: j.w.CapURL}), true
}

// scopeGaps: a budget limited to some units leaves out units with spend risks. Low per budget,
// and only when no unfiltered budget watches the whole container.
func (j judge) scopeGaps(alerting []Budget) []finding.Finding {
	if len(j.c.Units) == 0 || slices.ContainsFunc(alerting, func(b Budget) bool { return len(b.Scope.Units) == 0 }) {
		return nil
	}
	byUnit := map[string][]Risk{}
	for _, r := range j.c.Risks {
		if r.Unit != "" && r.Count > 0 {
			byUnit[r.Unit] = append(byUnit[r.Unit], r)
		}
	}
	var out []finding.Finding
	for _, b := range alerting {
		var left []string
		ev := map[string]any{}
		for _, u := range j.c.Units {
			if rs := byUnit[u]; len(rs) > 0 && !b.Covers(u) {
				left = append(left, fmt.Sprintf("%s (%s)", u, totalRisks(rs)))
				ev[u] = riskEvidence(rs)
			}
		}
		if len(left) == 0 {
			continue
		}
		out = append(out, j.finding(j.budgetRes("budget_scope", b), finding.SevLow,
			fmt.Sprintf("Budget '%s' (%s) leaves out %s", b.Name, j.describe(b), join(left)),
			map[string]any{"budget": evidence(b), "left_out": ev},
			finding.Remediation{
				Summary: fmt.Sprintf("Add these %ss to the budget's scope, or create a budget that covers them: "+
					"their credentials can run up spend that this budget never sees.", j.w.UnitNoun),
				URL: j.console(),
			}))
	}
	return out
}

// uncovered: each unit billed to the container that no alerting budget counts is high.
func (j judge) uncovered(alerting []Budget) []finding.Finding {
	var out []finding.Finding
	for _, u := range j.c.Units {
		if slices.ContainsFunc(alerting, func(b Budget) bool { return b.Covers(u) }) {
			continue
		}
		out = append(out, j.finding(finding.Resource{Type: j.w.UnitNoun + "_budget", ID: j.c.ID + "/" + u, Name: u}, finding.SevHigh,
			fmt.Sprintf("%s %s is billed to %s but no budget with alerts covers it", upperFirst(j.w.UnitNoun), u, j.c.Label),
			map[string]any{j.w.UnitNoun: u},
			finding.Remediation{
				Summary: fmt.Sprintf("Add this %s to an existing budget's scope, or create a budget for it with threshold alerts.", j.w.UnitNoun),
				URL:     j.console(),
			}))
	}
	return out
}

// describe is the parenthesised part of a title: amount, currency, period and scope.
func (j judge) describe(b Budget) string {
	amount := number(b.Amount)
	if b.Currency != "" {
		amount += " " + b.Currency
	}
	switch {
	case b.LastPeriod && b.Period == PeriodCustom:
		amount = "last period's spend"
	case b.LastPeriod:
		amount = "last " + b.Period + "'s spend"
	case b.Period == PeriodCustom || b.Period == "":
		amount += ", custom period"
	default:
		amount += "/" + b.Period
	}
	var scope []string
	switch n := len(b.Scope.Units); {
	case n == 0:
		scope = append(scope, j.w.AllScope)
	case n == 1:
		scope = append(scope, b.Scope.Units[0])
	default:
		scope = append(scope, plural(n, j.w.UnitNoun))
	}
	scope = append(scope, b.Scope.Filters...)
	return amount + ", " + strings.Join(scope, ", ")
}

// identity is what makes two budgets the same: scope, amount and period.
func identity(b Budget) string {
	units, filters := slices.Sorted(slices.Values(b.Scope.Units)), slices.Sorted(slices.Values(b.Scope.Filters))
	return strings.Join([]string{number(b.Amount), b.Currency, b.Period, strconv.FormatBool(b.LastPeriod),
		strings.Join(units, "\x00"), strings.Join(filters, "\x00")}, "\x01")
}

func evidence(b Budget) map[string]any {
	ts := make([]any, len(b.Thresholds))
	for i, t := range b.Thresholds {
		ts[i] = map[string]any{"percent": t.Percent, "forecast": t.Forecast}
	}
	return map[string]any{"id": b.ID, "name": b.Name, "amount": b.Amount, "currency": b.Currency, "period": b.Period,
		"last_period": b.LastPeriod, "thresholds": ts, "units": b.Scope.Units, "filters": b.Scope.Filters,
		"notifies": b.Notifies, "actions": b.Actions}
}

// thresholdPhrase says when a budget alerts: "alerts only at 50%", "alerts at 50% and 80% forecasted".
func thresholdPhrase(ts []Threshold) string {
	sorted := slices.Clone(ts)
	slices.SortStableFunc(sorted, func(a, b Threshold) int {
		if a.Forecast != b.Forecast {
			if a.Forecast {
				return 1
			}
			return -1
		}
		return cmp.Compare(a.Percent, b.Percent)
	})
	parts := make([]string, len(sorted))
	for i, t := range sorted {
		parts[i] = number(t.Percent) + "%"
		if t.Forecast {
			parts[i] += " forecasted"
		}
	}
	switch len(parts) {
	case 0:
		return "has no thresholds"
	case 1:
		return "alerts only at " + parts[0]
	}
	return "alerts at " + join(parts)
}

// totalRisks adds the risks up by kind: "2 unrestricted API keys and 1 user-managed key".
func totalRisks(rs []Risk) string {
	sums := map[string]int{}
	var order []string
	for _, r := range rs {
		if r.Count <= 0 {
			continue
		}
		if _, ok := sums[r.What]; !ok {
			order = append(order, r.What)
		}
		sums[r.What] += r.Count
	}
	parts := make([]string, len(order))
	for i, w := range order {
		parts[i] = plural(sums[w], w)
	}
	return join(parts)
}

func riskEvidence(rs []Risk) []any {
	var out []any
	for _, r := range rs {
		if r.Count > 0 {
			out = append(out, map[string]any{"unit": r.Unit, "what": r.What, "count": r.Count})
		}
	}
	return out
}

// number prints 110 as "110" and 12.5 as "12.5".
func number(f float64) string {
	return strconv.FormatFloat(math.Round(f*100)/100, 'f', -1, 64)
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// join lists items as "a", "a and b", "a, b and c".
func join(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
