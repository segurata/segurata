package azure

import (
	"context"
	"fmt"
	"sort"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/textfmt"
)

// ActionDeleteExpiredSecrets deletes client secrets of app registrations that have already
// expired. One plan covers every such finding of a tenant.
const ActionDeleteExpiredSecrets = "azure.app-secret.delete-expired"

func deleteStep(appID, keyID string) connector.Step {
	return connector.Step{Argv: []string{"az", "ad", "app", "credential", "delete", "--id", appID, "--key-id", keyID, "--only-show-errors"}}
}

// expired is one client secret that has expired, as read now.
type expired struct {
	app  app
	cred passwordCredential
}

// secretsState is what a plan is built from: the tenant az is signed in to and, of the secrets
// the findings name, those still registered and expired now.
type secretsState struct {
	tenant  string
	expired []expired
	left    []string
}

func (c *Connector) readSecrets(ctx context.Context, fs []finding.Finding) (secretsState, error) {
	if len(fs) == 0 || fs[0].Remediation.Action != ActionDeleteExpiredSecrets {
		return secretsState{}, fmt.Errorf("azure has no such remediation")
	}
	var current account
	if err := c.call(ctx, &current, "account", "show"); err != nil {
		return secretsState{}, fmt.Errorf("az account show: %w", err)
	}
	st := secretsState{tenant: current.tenantLabel()}
	if want := fs[0].Remediation.Group; st.tenant != want {
		return secretsState{}, fmt.Errorf("az is signed in to tenant %s, but these findings are from %s: run `az login --tenant %s` first", st.tenant, want, want)
	}
	apps, err := c.listApps(ctx)
	if err != nil {
		return secretsState{}, fmt.Errorf("app registrations: %w", err)
	}
	type key struct{ app, cred string }
	live := map[key]expired{}
	for _, a := range apps {
		for _, p := range a.PasswordCredentials {
			live[key{a.AppID, p.KeyID}] = expired{app: a, cred: p}
		}
	}
	at := connector.Now(c.Now)
	for _, f := range fs {
		appID, _ := f.Evidence["app_id"].(string)
		keyID, _ := f.Evidence["key_id"].(string)
		e, ok := live[key{appID, keyID}]
		switch {
		case !ok:
			st.left = append(st.left, fmt.Sprintf("Left out: secret %s of app %s (no longer registered).", keyID, appID))
		case e.cred.EndDateTime == nil || !e.cred.EndDateTime.Before(at):
			st.left = append(st.left, fmt.Sprintf("Left out: secret %s of app %q (not expired now).", keyID, e.app.DisplayName))
		default:
			st.expired = append(st.expired, e)
		}
	}
	sort.Slice(st.expired, func(i, j int) bool {
		a, b := st.expired[i], st.expired[j]
		if a.app.DisplayName != b.app.DisplayName {
			return a.app.DisplayName < b.app.DisplayName
		}
		return a.cred.KeyID < b.cred.KeyID
	})
	return st, nil
}

func (st secretsState) plan() (connector.Plan, error) {
	if len(st.expired) == 0 {
		return connector.Plan{}, fmt.Errorf("nothing to do: none of these secrets is still registered and expired; run the inventory again")
	}
	apps := map[string]bool{}
	p := connector.Plan{Action: ActionDeleteExpiredSecrets}
	var deletes []string
	for _, e := range st.expired {
		apps[e.app.AppID] = true
		p.Commands = append(p.Commands, deleteStep(e.app.AppID, e.cred.KeyID))
		deletes = append(deletes, fmt.Sprintf("Deletes secret %s… of app %q, expired %s.", e.cred.Hint, e.app.DisplayName, day(*e.cred.EndDateTime)))
	}
	p.Summary = fmt.Sprintf("Delete %d expired client %s from %d app %s in tenant %s.",
		len(st.expired), textfmt.Plural(len(st.expired), "secret", "secrets"), len(apps), textfmt.Plural(len(apps), "registration", "registrations"), st.tenant)
	p.SideEffects = append([]string{
		"No undo: a deleted client secret cannot be restored. Each one has already expired, so nothing can sign in with it any more; an app that still needs a secret needs a new one either way.",
		"Only these password credentials go: the app registrations, their certificates and their other secrets stay.",
	}, deletes...)
	p.SideEffects = append(p.SideEffects, st.left...)
	return p, nil
}

// allowlist is a delete for every secret of these apps that is expired in the read, nothing else.
func (st secretsState) allowlist() remediate.Allowlist {
	allow := remediate.Allowlist{}
	for _, e := range st.expired {
		allow[ActionDeleteExpiredSecrets] = append(allow[ActionDeleteExpiredSecrets], deleteStep(e.app.AppID, e.cred.KeyID))
	}
	return allow
}

func (c *Connector) Plan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	return c.PlanGroup(ctx, []finding.Finding{f})
}

func (c *Connector) Apply(ctx context.Context, f finding.Finding, p connector.Plan, io connector.IO) error {
	return c.ApplyGroup(ctx, []finding.Finding{f}, p, io)
}

// PlanGroup reads the tenant's app registrations now and plans a delete for each secret of the
// group that is still registered and expired.
func (c *Connector) PlanGroup(ctx context.Context, fs []finding.Finding) (connector.Plan, error) {
	st, err := c.readSecrets(ctx, fs)
	if err != nil {
		return connector.Plan{}, err
	}
	return st.plan()
}

func (c *Connector) ApplyGroup(ctx context.Context, fs []finding.Finding, p connector.Plan, io connector.IO) error {
	st, err := c.readSecrets(ctx, fs)
	if err != nil {
		return err
	}
	return remediate.Run(ctx, p, st.allowlist(), c.Exec, io)
}
