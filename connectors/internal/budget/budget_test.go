package budget

import (
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

var wording = Wording{
	UnitNoun:   "project",
	AllScope:   "all projects",
	ConsoleURL: "https://console.example/budgets",
	DocsURL:    "https://docs.example/budgets",
	ActionNoun: "a topic",
	CapHowTo:   "Budgets only notify. Wire a topic to a function that stops billing.",
	CapURL:     "https://docs.example/cap",
	RisksWhere: "in projects billed here",
}

func container(units ...string) Container {
	return Container{ID: "BA-1", Label: "billing account BA-1", Units: units,
		NoBudget: finding.Resource{Type: "billing_account", ID: "BA-1", Name: "BA-1"}}
}

func monthly(id, name string, amount float64, ts ...Threshold) Budget {
	return Budget{ID: id, Name: name, Amount: amount, Currency: "EUR", Period: PeriodMonth, Thresholds: ts, Notifies: []string{NotifyAdmins}}
}

func actual(p float64) Threshold   { return Threshold{Percent: p} }
func forecast(p float64) Threshold { return Threshold{Percent: p, Forecast: true} }

func titles(fs []finding.Finding) map[string]finding.Finding {
	m := map[string]finding.Finding{}
	for _, f := range fs {
		m[f.Title] = f
	}
	return m
}

func expect(t *testing.T, fs []finding.Finding, want map[string]finding.Severity) {
	t.Helper()
	got := titles(fs)
	for title, sev := range want {
		f, ok := got[title]
		if !ok {
			var all []string
			for k := range got {
				all = append(all, k)
			}
			t.Errorf("missing %q in:\n  %s", title, strings.Join(all, "\n  "))
			continue
		}
		if f.Severity != sev || f.Kind != finding.KindSpend {
			t.Errorf("%q: %s %s, want %s spend", title, f.Kind, f.Severity, sev)
		}
		// A budget's finding is about money; the container's says what its connector declared.
		if blast := finding.BlastMoney; f.Resource.Type == "billing_account" && f.Blast != "" || f.Resource.Type != "billing_account" && f.Blast != blast {
			t.Errorf("%q: blast %q", title, f.Blast)
		}
	}
	if len(fs) != len(want) {
		t.Errorf("got %d findings, want %d", len(fs), len(want))
	}
}

func TestNoAlertingBudgetIsOneHighFinding(t *testing.T) {
	silent := monthly("b1", "Silent", 50, actual(100))
	silent.Notifies = nil
	fs := Evaluate(container("shop"), []Budget{silent, monthly("b2", "No thresholds", 20)}, wording)
	expect(t, fs, map[string]finding.Severity{
		"Billing account BA-1 has no budget with alerts: nothing warns you when spend runs away": finding.SevHigh,
	})
	if fs[0].Resource.Type != "billing_account" || !strings.Contains(fs[0].Remediation.Summary, "stops billing") {
		t.Errorf("no-budget finding keeps the container resource and says how to cap: %+v", fs[0])
	}
	c := container("shop")
	c.Blast = finding.BlastMoney
	if f := Evaluate(c, nil, wording)[0]; f.Blast != finding.BlastMoney {
		t.Errorf("the container's blast: %q", f.Blast)
	}
}

func TestThresholdRules(t *testing.T) {
	budgets := []Budget{
		monthly("b1", "Total", 110, actual(50)),
		monthly("b2", "Steady", 200, actual(50), actual(90), actual(100)),
		monthly("b3", "Good", 300, actual(95), actual(120), forecast(100)),
		monthly("b4", "Forecast only", 40, forecast(100), actual(50)),
	}
	budgets[3].Actions = []string{ActionPubSub}
	fs := Evaluate(container(), budgets, wording)
	expect(t, fs, map[string]finding.Severity{
		"Billing account BA-1 has 4 budgets: 'Total' 110 EUR/month, all projects; 'Steady' 200 EUR/month, all projects; 'Good' 300 EUR/month, all projects; and 1 more": finding.SevInfo,
		"Budget 'Total' (110 EUR/month, all projects) alerts only at 50%: add 90%, 100% and a forecasted threshold":                                                     finding.SevMedium,
		"Budget 'Steady' (200 EUR/month, all projects) has no forecasted threshold: add one at 100% to hear before the money is spent":                                  finding.SevLow,
		"Budget 'Forecast only' (40 EUR/month, all projects) alerts at 50% and 100% forecasted: add 90% and 100%":                                                       finding.SevMedium,
	})
	f := titles(fs)["Budget 'Total' (110 EUR/month, all projects) alerts only at 50%: add 90%, 100% and a forecasted threshold"]
	if f.Resource.ID != "BA-1/b1" || f.Remediation.URL != wording.ConsoleURL {
		t.Errorf("per-budget resource and console URL: %+v", f)
	}
}

func TestDuplicatesGroupSameScopeAmountAndPeriod(t *testing.T) {
	ok := []Threshold{actual(50), actual(100), forecast(100)}
	maps1, maps2 := monthly("m1", "Maps", 75, ok...), monthly("m2", "Maps", 75, ok...)
	other := monthly("o1", "Other name", 75, actual(100), forecast(100))
	quarterly := monthly("q1", "Maps", 75, ok...)
	quarterly.Period = PeriodQuarter
	scoped := monthly("s1", "Maps", 75, ok...)
	scoped.Scope.Units = []string{"shop"}
	narrowed := monthly("n1", "Maps", 75, ok...)
	narrowed.Scope.Detail = "services/AAAA,services/BBBB,services/CCCC"
	all := []Budget{maps1, maps2, other, quarterly, scoped, narrowed}
	for i := range all {
		all[i].Actions = []string{ActionPubSub}
	}
	fs := Evaluate(container("shop"), all, wording)
	got := titles(fs)
	group := got["Budgets 'Maps', 'Maps' and 'Other name' on billing account BA-1 are the same (75 EUR/month, all projects): keep one"]
	if group.Severity != finding.SevLow || group.Resource.ID != "BA-1/m1+m2+o1" {
		t.Fatalf("a copy with another name is still a copy, other periods, scopes and filter details are not:\n%v", got)
	}
	two := Evaluate(container(), []Budget{maps1, maps2}, wording)
	if _, ok := titles(two)["2 budgets named 'Maps' on billing account BA-1 are the same (75 EUR/month, all projects): delete one"]; !ok {
		t.Errorf("two copies: %v", titles(two))
	}
}

func TestEnforcementIsInfoUnlessRisksThenMedium(t *testing.T) {
	good := monthly("b1", "Good", 100, actual(50), actual(100), forecast(100))
	title := "Budgets on billing account BA-1 only notify: none is wired to a topic, so nothing stops spend"
	expect(t, Evaluate(container(), []Budget{good}, wording), map[string]finding.Severity{
		"Billing account BA-1 has 1 budget: 'Good' 100 EUR/month, all projects": finding.SevInfo,
		title: finding.SevInfo,
	})

	c := container("shop", "blog")
	c.Risks = []Risk{{Unit: "shop", What: "unrestricted API key", Count: 2}, {Unit: "blog", What: "unrestricted API key", Count: 1},
		{Unit: "blog", What: "user-managed service account key", Count: 1}, {Unit: "blog", What: "unused", Count: 0}}
	fs := Evaluate(c, []Budget{good}, wording)
	risky := title + "; 3 unrestricted API keys and 1 user-managed service account key in projects billed here"
	if f := titles(fs)[risky]; f.Severity != finding.SevMedium || f.Remediation.URL != wording.CapURL || f.Resource.Type != "budget_enforcement" {
		t.Errorf("risky container: %+v\n%v", f, titles(fs))
	}

	wired := good
	wired.Actions = []string{ActionSpendCap}
	c.ActionsUnknown = false
	if _, ok := titles(Evaluate(c, []Budget{good, wired}, wording))[risky]; ok {
		t.Errorf("one budget with an action is enough")
	}
	c.ActionsUnknown = true
	if _, ok := titles(Evaluate(c, []Budget{good}, wording))[risky]; ok {
		t.Errorf("unknown actions must not be reported as missing")
	}
}

func TestScopeGapsAndUncoveredUnits(t *testing.T) {
	ok := []Threshold{actual(50), actual(100), forecast(100)}
	blog := monthly("b1", "Blog only", 20, ok...)
	blog.Scope.Units = []string{"blog"}
	blog.Actions = []string{ActionPubSub}
	c := container("blog", "shop", "quiet")
	c.Risks = []Risk{{Unit: "shop", What: "unrestricted API key", Count: 2}}
	expect(t, Evaluate(c, []Budget{blog}, wording), map[string]finding.Severity{
		"Billing account BA-1 has 1 budget: 'Blog only' 20 EUR/month, blog":                   finding.SevInfo,
		"Budget 'Blog only' (20 EUR/month, blog) leaves out shop (2 unrestricted API keys)":   finding.SevLow,
		"Project shop is billed to billing account BA-1 but no budget with alerts covers it":  finding.SevHigh,
		"Project quiet is billed to billing account BA-1 but no budget with alerts covers it": finding.SevHigh,
	})

	whole := monthly("b2", "Whole", 200, ok...)
	fs := Evaluate(c, []Budget{blog, whole}, wording)
	for _, f := range fs {
		if f.Resource.Type == "budget_scope" || f.Resource.Type == "project_budget" {
			t.Errorf("an unfiltered budget watches every project: %s", f.Title)
		}
	}
}

func TestDescribe(t *testing.T) {
	j := judge{w: Wording{UnitNoun: "project", AllScope: "whole account"}}
	for _, c := range []struct {
		b    Budget
		want string
	}{
		{Budget{Amount: 12.5, Currency: "USD", Period: PeriodYear}, "12.5 USD/year, whole account"},
		{Budget{Amount: 10, Period: PeriodCustom}, "10, custom period, whole account"},
		{Budget{LastPeriod: true, Period: PeriodMonth, Scope: Scope{Units: []string{"a", "b"}, Filters: []string{"2 services"}}}, "last month's spend, 2 projects, 2 services"},
	} {
		if got := j.describe(c.b); got != c.want {
			t.Errorf("describe = %q, want %q", got, c.want)
		}
	}
	if got := thresholdPhrase(nil); got != "has no thresholds" {
		t.Errorf("no thresholds: %q", got)
	}
}

func TestAlertingAndCovers(t *testing.T) {
	b := Budget{Thresholds: []Threshold{actual(100)}}
	if b.Alerting() {
		t.Errorf("thresholds without recipients alert nobody")
	}
	b.Actions = []string{ActionPubSub}
	if !b.Alerting() || !b.Covers("any") {
		t.Errorf("an action receives alerts; no unit filter covers every unit")
	}
	b.Scope.Units = []string{"a"}
	if b.Covers("b") || !b.Covers("a") {
		t.Errorf("unit filter")
	}
}
