// Package azure inventories Azure through the installed `az` CLI: consumption budgets per
// subscription and client secrets of app registrations that never expire or are about to.
// Read-only; the remediation in remediate.go deletes only after a confirmed plan. See
// docs/cloud-connectors.md.
package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/budget"
	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// readOnly lists every az command this connector runs. Anything else is refused before it reaches
// the CLI, so a bug cannot reset a credential, delete an app or change a subscription.
var readOnly = cli.Allowlist{
	"account show",
	"account list",
	"consumption budget list",
	"ad app list",
}

type Connector struct {
	// Run executes az commands after the read-only guard. Tests replace it with canned output.
	Run cli.Runner
	Now func() time.Time
	// Exec runs a confirmed remediation's allowlisted commands; nil is connector.System.
	Exec connector.Executor
}

func New() *Connector {
	return &Connector{Run: cli.Exec{Path: "az", Timeout: 3 * time.Minute}, Now: time.Now}
}

func init() { connector.Register(New()) }

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     "azure",
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "Budgets per subscription, app registration client secrets that never expire or expire soon",
		Needs:    []string{"cli:az"},
	}
}

func (c *Connector) call(ctx context.Context, out any, args ...string) error {
	raw, err := readOnly.Guard(c.Run).Run(ctx, append(args, "--output", "json", "--only-show-errors")...)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func classify(err error) finding.State {
	if errors.Is(err, exec.ErrNotFound) {
		return finding.StateUnsupported
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "az login"):
		return finding.StateSignedOut
	case strings.Contains(msg, "AADSTS") || strings.Contains(msg, "expired"):
		return finding.StateReauth
	}
	return finding.StateError
}

type account struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	State               string `json:"state"`
	TenantID            string `json:"tenantId"`
	TenantDefaultDomain string `json:"tenantDefaultDomain"`
	TenantDisplayName   string `json:"tenantDisplayName"`
}

func (a account) tenantLabel() string {
	for _, s := range []string{a.TenantDefaultDomain, a.TenantDisplayName, a.TenantID} {
		if s != "" {
			return s
		}
	}
	return "azure"
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	now := c.Now()
	var current account
	if err := c.call(ctx, &current, "account", "show"); err != nil {
		emit.Status(finding.Status{Account: "azure", State: classify(err), Detail: err.Error()})
		return nil
	}
	tenant := current.tenantLabel()
	var subs []account
	if err := c.call(ctx, &subs, "account", "list"); err != nil {
		emit.Status(finding.Status{Account: tenant, State: classify(err), Detail: err.Error()})
		return nil
	}
	// App secrets come first: the tenant's non-expiring ones are spend risks of its subscriptions.
	secrets := c.appSecrets(ctx, tenant, now, emit)
	for _, s := range subs {
		if s.State != "Enabled" {
			continue
		}
		var risks []budget.Risk
		if s.TenantID == current.TenantID {
			risks = []budget.Risk{{What: "non-expiring client secret", Count: secrets}}
		}
		c.subscription(ctx, s, risks, emit)
	}
	return nil
}

// azBudget is a consumption budget as `az consumption budget list` prints it: the CLI flattens
// the REST properties into the budget, and the REST shape nests them under properties.
type azBudget struct {
	Name string `json:"name"`
	budgetProps
	Properties *budgetProps `json:"properties"`
}

type budgetProps struct {
	Amount        float64                   `json:"amount"`
	Category      string                    `json:"category"`
	TimeGrain     string                    `json:"timeGrain"`
	CurrentSpend  *struct{ Unit string }    `json:"currentSpend"`
	Filter        *budgetFilter             `json:"filter"`
	Notifications map[string]azNotification `json:"notifications"`
}

type budgetFilter struct {
	And        []budgetFilter `json:"and"`
	Dimensions *struct {
		Name   string   `json:"name"`
		Values []string `json:"values"`
	} `json:"dimensions"`
	Tags *struct {
		Name   string   `json:"name"`
		Values []string `json:"values"`
	} `json:"tags"`
}

type azNotification struct {
	Enabled       bool     `json:"enabled"`
	Operator      string   `json:"operator"`
	Threshold     float64  `json:"threshold"`
	ThresholdType string   `json:"thresholdType"`
	ContactEmails []string `json:"contactEmails"`
	ContactRoles  []string `json:"contactRoles"`
	ContactGroups []string `json:"contactGroups"`
}

func (c *Connector) subscription(ctx context.Context, s account, risks []budget.Risk, emit connector.Emitter) {
	label := fmt.Sprintf("%s (%s)", s.Name, s.ID)
	var budgets []azBudget
	if err := c.call(ctx, &budgets, "consumption", "budget", "list", "--subscription", s.ID); err != nil {
		emit.Status(finding.Status{Account: label, State: classify(err), Detail: "budgets: " + err.Error()})
		return
	}
	for _, f := range budgetFindings(s.ID, label, budgets, risks) {
		f.Account = label
		emit.Finding(f)
	}
	emit.Status(finding.Status{Account: label, State: finding.StateOK})
}

type passwordCredential struct {
	DisplayName   string     `json:"displayName"`
	EndDateTime   *time.Time `json:"endDateTime"`
	StartDateTime *time.Time `json:"startDateTime"`
	Hint          string     `json:"hint"`
	KeyID         string     `json:"keyId"`
}

type app struct {
	AppID               string               `json:"appId"`
	DisplayName         string               `json:"displayName"`
	PasswordCredentials []passwordCredential `json:"passwordCredentials"`
}

// listApps reads every app registration with its client secrets (metadata only).
func (c *Connector) listApps(ctx context.Context) ([]app, error) {
	var apps []app
	query := "[].{appId:appId,displayName:displayName,passwordCredentials:passwordCredentials}"
	err := c.call(ctx, &apps, "ad", "app", "list", "--all", "--query", query)
	return apps, err
}

// appSecrets reports the tenant's client secrets and returns how many never expire.
func (c *Connector) appSecrets(ctx context.Context, tenant string, now time.Time, emit connector.Emitter) int {
	apps, err := c.listApps(ctx)
	if err != nil {
		emit.Status(finding.Status{Account: tenant, State: classify(err), Detail: "app registrations: " + err.Error()})
		return 0
	}
	lasting := 0
	for _, a := range apps {
		for _, p := range a.PasswordCredentials {
			f := secretFinding(a, p, now)
			f.Account = tenant
			if f.Severity == finding.SevHigh {
				lasting++
			}
			if f.Remediation.Action != "" {
				f.Remediation.Group = tenant
			}
			emit.Finding(f)
		}
	}
	emit.Status(finding.Status{Account: tenant, State: finding.StateOK})
	return lasting
}
