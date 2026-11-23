// Package azure inventories Azure through the installed `az` CLI: consumption budgets per
// subscription and client secrets of app registrations that never expire or are about to.
// Read-only. See docs/cloud-connectors.md.
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

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// Runner runs a CLI and returns its stdout. Tests replace it with canned output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// execRunner runs the real binary with a timeout, folding stderr into the error.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args[:min(3, len(args))], " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

type Connector struct {
	Run Runner
	Now func() time.Time
}

func New() *Connector { return &Connector{Run: execRunner, Now: time.Now} }

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
	raw, err := c.Run(ctx, "az", append(args, "--output", "json", "--only-show-errors")...)
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
	for _, s := range subs {
		if s.State == "Enabled" {
			c.subscription(ctx, s, emit)
		}
	}
	c.appSecrets(ctx, tenant, now, emit)
	return nil
}

type budget struct {
	Name          string  `json:"name"`
	Amount        float64 `json:"amount"`
	TimeGrain     string  `json:"timeGrain"`
	Notifications map[string]struct {
		Enabled bool `json:"enabled"`
	} `json:"notifications"`
}

func (b budget) enabledAlerts() int {
	n := 0
	for _, x := range b.Notifications {
		if x.Enabled {
			n++
		}
	}
	return n
}

func (c *Connector) subscription(ctx context.Context, s account, emit connector.Emitter) {
	label := fmt.Sprintf("%s (%s)", s.Name, s.ID)
	var budgets []budget
	if err := c.call(ctx, &budgets, "consumption", "budget", "list", "--subscription", s.ID); err != nil {
		emit.Status(finding.Status{Account: label, State: classify(err), Detail: "budgets: " + err.Error()})
		return
	}
	for _, f := range budgetFindings(s.ID, budgets) {
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

func (c *Connector) appSecrets(ctx context.Context, tenant string, now time.Time, emit connector.Emitter) {
	var apps []app
	query := "[].{appId:appId,displayName:displayName,passwordCredentials:passwordCredentials}"
	if err := c.call(ctx, &apps, "ad", "app", "list", "--all", "--query", query); err != nil {
		emit.Status(finding.Status{Account: tenant, State: classify(err), Detail: "app registrations: " + err.Error()})
		return
	}
	for _, a := range apps {
		for _, p := range a.PasswordCredentials {
			f := secretFinding(a, p, now)
			f.Account = tenant
			emit.Finding(f)
		}
	}
	emit.Status(finding.Status{Account: tenant, State: finding.StateOK})
}
