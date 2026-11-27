package gcp

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/docref"
	"github.com/segurata/segurata/internal/finding"
)

const (
	// ActionCreateBudget creates a budget with alerts on a billing account that has none, for the
	// amount in connectors.gcp.config.budget_amount.
	ActionCreateBudget = "gcp.budget.create"
	// ActionBudgetAlerts adds the thresholds a budget lacks: 100% of actual spend (90% too when
	// below it) and 100% of forecasted spend.
	ActionBudgetAlerts = "gcp.budget.alerts"
)

// budgetName is the display name of a budget segurata creates (the Budget API allows 60 characters).
const budgetName = "segurata: all projects"

// noStop is where the docs say what stops spend, since a budget does not.
const noStop = docref.Docs + "gcp-connector.md#budgets-alert-they-do-not-stop-spend"

// newBudgetID stands, in the undo shown before applying, for the id Google gives the new budget;
// the apply prints the exact undo once the budget exists.
const newBudgetID = "NEW_BUDGET_ID"

// billingFlags end every billing command: the account, and the configured quota project.
func (g *gcloud) billingFlags(account string) []string {
	flags := []string{"--account=" + account}
	if g.billingProject != "" {
		flags = append(flags, "--billing-project="+g.billingProject)
	}
	return flags
}

func (g *gcloud) budgets(ctx context.Context, billingID, account string) ([]gcpBudget, error) {
	var out []gcpBudget
	err := g.json(ctx, &out, append([]string{"billing", "budgets", "list", "--billing-account=" + billingID}, g.billingFlags(account)...)...)
	return out, err
}

// percent writes a 1.0-based threshold as gcloud takes it: 0.5, 1.0.
func percent(p float64) string {
	s := strconv.FormatFloat(p, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

func budgetAmountKey(billingID string) string {
	return `connectors.gcp.config.budget_amount."` + billingID + `" (or budget_amount.default)`
}

// budgetActions attaches the budget remediations to what the shared rules found.
func budgetActions(fs []finding.Finding, noBudget finding.Resource) {
	for i := range fs {
		f := &fs[i]
		switch {
		case f.Resource == noBudget && f.Severity == finding.SevHigh:
			f.Remediation.Action = ActionCreateBudget
			f.Remediation.Summary += " Set " + budgetAmountKey(noBudget.ID) + " and segurata remediate creates it."
		case f.Resource.Type == "budget_thresholds":
			f.Remediation.Action = ActionBudgetAlerts
		}
	}
}

func (r *remediator) budgetCreatePlan(ctx context.Context, g *gcloud, cfg settings, f finding.Finding) (connector.Plan, error) {
	id, err := evidenceString(f, "billing_account")
	if err != nil {
		return connector.Plan{}, err
	}
	amount, ok := cfg.budgetAmounts[id]
	if !ok {
		amount, ok = cfg.budgetAmounts[defaultAmount]
	}
	if !ok {
		return connector.Plan{}, fmt.Errorf("refused: no budget amount configured for billing account %s. Set %s to the monthly "+
			"amount, in the billing account's currency, that should alert you (segurata never guesses an amount), then plan again", id, budgetAmountKey(id))
	}
	budgets, err := g.budgets(ctx, id, f.Account)
	if err != nil {
		_, why := classify(err)
		return connector.Plan{}, fmt.Errorf("billing budgets list for %s: %s", id, why)
	}
	currency, _ := f.Evidence["currency"].(string)
	for _, b := range budgets {
		if nb := b.neutral(currency, nil); nb.Alerting() {
			return connector.Plan{}, fmt.Errorf("nothing to do: billing account %s now has budget %q with alerts", id, nb.Name)
		}
	}
	shown := strconv.FormatFloat(amount, 'f', -1, 64)
	create := append([]string{"billing", "budgets", "create", "--billing-account=" + id, "--display-name=" + budgetName,
		"--budget-amount=" + shown,
		"--threshold-rule=percent=0.5", "--threshold-rule=percent=0.9", "--threshold-rule=percent=1.0",
		"--threshold-rule=percent=1.0,basis=forecasted-spend"}, g.billingFlags(f.Account)...)
	create = append(create, "--format=value(name)")
	return connector.Plan{
		Action: ActionCreateBudget,
		Summary: fmt.Sprintf("Create budget %q of %s %s a month on billing account %s, for all its projects, alerting at 50%%, 90%% and 100%% of actual spend and 100%% of forecasted spend.",
			budgetName, shown, strings.TrimSpace(currency+" (the billing account's currency)"), id),
		Commands: []connector.Step{g.step(create...)},
		Undo:     []connector.Step{g.step(append([]string{"billing", "budgets", "delete", "billingAccounts/" + id + "/budgets/" + newBudgetID}, g.billingFlags(f.Account)...)...)},
		SideEffects: []string{
			"A budget alerts and does not stop spending: it emails the billing account's administrators and users. The hard stops are request caps (gcp.quota.cap) or a budget notification on Pub/Sub wired to code that disables billing: " + noStop,
			"Undo: " + newBudgetID + " is the id Google gives the budget; after applying, segurata prints the exact delete command.",
		},
	}, nil
}

// applyBudgetCreate runs the confirmed create, reads the new budget's name from what gcloud
// printed and prints the exact undo.
func (r *remediator) applyBudgetCreate(ctx context.Context, allow connector.Allowlist, p connector.Plan, out connector.IO) error {
	var name bytes.Buffer
	tee := out
	tee.Out = io.MultiWriter(out.Out, &name)
	if err := allow.Run(ctx, p, r.c.exec, tee); err != nil {
		return err
	}
	created := strings.TrimSpace(name.String())
	if !strings.HasPrefix(created, "billingAccounts/") || strings.ContainsAny(created, " \n") {
		fmt.Fprintf(out.Out, "Undo: find the budget %q at https://console.cloud.google.com/billing and delete it there.\n", budgetName)
		return nil
	}
	undo := slices.Clone(p.Undo[0].Argv)
	undo[slices.Index(undo, "delete")+1] = created
	fmt.Fprintf(out.Out, "Undo: %s\n", connector.Step{Argv: undo})
	return nil
}

// budgetRef splits a budget_thresholds resource id, billing account id/budget id.
func budgetRef(f finding.Finding) (billingID, budgetID string, err error) {
	billingID, budgetID, ok := strings.Cut(f.Resource.ID, "/")
	if !ok || billingID == "" || budgetID == "" {
		return "", "", fmt.Errorf("finding %s names no budget: run the inventory again", f.ID)
	}
	return billingID, budgetID, nil
}

func (r *remediator) budgetAlertsPlan(ctx context.Context, g *gcloud, f finding.Finding) (connector.Plan, error) {
	id, budgetID, err := budgetRef(f)
	if err != nil {
		return connector.Plan{}, err
	}
	budgets, err := g.budgets(ctx, id, f.Account)
	if err != nil {
		_, why := classify(err)
		return connector.Plan{}, fmt.Errorf("billing budgets list for %s: %s", id, why)
	}
	i := slices.IndexFunc(budgets, func(b gcpBudget) bool { return lastSegment(b.Name) == budgetID })
	if i < 0 {
		return connector.Plan{}, fmt.Errorf("nothing to do: budget %s no longer exists on billing account %s", budgetID, id)
	}
	b := budgets[i]
	var actual float64
	forecast := false
	var before []string
	for _, t := range b.ThresholdRules {
		rule := "--add-threshold-rule=percent=" + percent(t.ThresholdPercent)
		if t.SpendBasis == "FORECASTED_SPEND" {
			forecast = true
			rule += ",basis=forecasted-spend"
		} else {
			actual = max(actual, t.ThresholdPercent)
		}
		before = append(before, rule)
	}
	var add, named []string
	if actual < 1 {
		if actual < 0.9 {
			add, named = append(add, "--add-threshold-rule=percent=0.9"), append(named, "90% of actual spend")
		}
		add, named = append(add, "--add-threshold-rule=percent=1.0"), append(named, "100% of actual spend")
	}
	if !forecast {
		add, named = append(add, "--add-threshold-rule=percent=1.0,basis=forecasted-spend"), append(named, "100% of forecasted spend")
	}
	if len(add) == 0 {
		return connector.Plan{}, fmt.Errorf("nothing to do: budget %q already alerts at 100%% of actual and of forecasted spend", b.DisplayName)
	}
	name := "billingAccounts/" + id + "/budgets/" + budgetID
	update := append(append([]string{"billing", "budgets", "update", name}, add...), g.billingFlags(f.Account)...)
	undo := append(append([]string{"billing", "budgets", "update", name, "--clear-threshold-rules"}, before...), g.billingFlags(f.Account)...)
	return connector.Plan{
		Action:   ActionBudgetAlerts,
		Summary:  fmt.Sprintf("Add thresholds at %s to budget %q on billing account %s.", strings.Join(named, ", "), cmp.Or(b.DisplayName, budgetID), id),
		Commands: []connector.Step{g.step(update...)},
		Undo:     []connector.Step{g.step(undo...)},
		SideEffects: []string{
			"The budget's other thresholds, amount, scope and recipients stay as they are; gcloud adds the new rules to the existing ones.",
			"A budget alerts and does not stop spending: " + noStop,
			"Undo clears the thresholds and puts back exactly the ones the budget has now.",
		},
	}, nil
}
