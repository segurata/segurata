package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// Doctor asks each credentialed account for one project to tell whose credentials expired.
func (c *Connector) Doctor(ctx context.Context, req connector.Request) []connector.Check {
	cfg, err := parseSettings(req.Config)
	if err != nil {
		return []connector.Check{{Level: connector.Fail, What: "config", Detail: err.Error(), Fix: "fix the gcp section of the config"}}
	}
	g, err := c.gcloud(cfg)
	if err != nil {
		return []connector.Check{{Level: connector.Fail, What: "gcloud", Detail: err.Error(),
			Fix: "install the Google Cloud SDK (https://cloud.google.com/sdk/docs/install) or set gcloud_path"}}
	}
	accounts, _, err := c.accounts(ctx, g, cfg)
	if err != nil {
		_, why := classify(err)
		return []connector.Check{{Level: connector.Fail, What: "gcloud auth list", Detail: why, Fix: "gcloud auth login"}}
	}
	if len(accounts) == 0 {
		return []connector.Check{{Level: connector.Fail, What: "gcloud accounts", Detail: "gcloud has no credentialed accounts", Fix: "gcloud auth login"}}
	}
	checks := []connector.Check{{Level: connector.OK, What: "gcloud", Detail: fmt.Sprintf("%d credentialed account(s)", len(accounts))}}
	for _, a := range accounts {
		var projects []listedProject
		err := g.json(ctx, &projects, "projects", "list", "--account="+a, "--limit=1")
		what := "gcloud account " + a
		if err == nil {
			checks = append(checks, connector.Check{Level: connector.OK, What: what, Detail: "token valid"})
			if len(projects) > 0 {
				p := projects[0].ProjectID
				checks = append(checks, g.permissionCheck(ctx, a, "project "+p, cloudResourceManager,
					"/v3/projects/"+url.PathEscape(p)+":testIamPermissions", g.userProject(p), projectPermissions))
				checks = append(checks, g.billingPermissionChecks(ctx, a, g.userProject(p))...)
			}
			continue
		}
		switch state, why := classify(err); {
		case state == finding.StateReauth:
			checks = append(checks, connector.Check{Level: connector.Fail, What: what, Detail: "token expired", Fix: "gcloud auth login " + a})
		case errors.Is(err, context.DeadlineExceeded):
			checks = append(checks, connector.Check{Level: connector.Warn, What: what, Detail: "timed out listing projects", Fix: "run again; check the network"})
		default:
			checks = append(checks, connector.Check{Level: connector.Warn, What: what, Detail: why,
				Fix: "check the account's access with: gcloud projects list --account=" + a})
		}
	}
	return checks
}

// permission is one IAM permission a remediation needs beyond the inventory's reads, with the
// predefined role that grants it (cloud.google.com/iam/docs/roles-permissions).
type permission struct{ name, role, use string }

// projectPermissions are tested on the first project each account lists.
var projectPermissions = []permission{
	{"monitoring.timeSeries.list", "roles/monitoring.viewer", "read which APIs each API key called"},
	{"apikeys.keys.update", "roles/serviceusage.apiKeysAdmin", ActionRestrictKey},
}

// billingPermissions are tested on the first open billing account each account lists.
var billingPermissions []permission

const (
	cloudResourceManager = "cloudresourcemanager.googleapis.com"
	cloudBilling         = "cloudbilling.googleapis.com"
)

func (g *gcloud) billingPermissionChecks(ctx context.Context, account, userProject string) []connector.Check {
	if len(billingPermissions) == 0 {
		return nil
	}
	var list []billingAccount
	if err := g.json(ctx, &list, "billing", "accounts", "list", "--account="+account); err != nil {
		_, why := classify(err)
		return []connector.Check{{Level: connector.Warn, What: "remediation permissions of " + account + " on billing accounts", Detail: why,
			Fix: "check with: gcloud billing accounts list --account=" + account}}
	}
	for _, ba := range list {
		if ba.Open {
			id := strings.TrimPrefix(ba.Name, "billingAccounts/")
			return []connector.Check{g.permissionCheck(ctx, account, "billing account "+id, cloudBilling,
				"/v1/billingAccounts/"+url.PathEscape(id)+":testIamPermissions", userProject, billingPermissions)}
		}
	}
	return nil
}

// permissionCheck asks testIamPermissions, which Google documents only as POST and which changes
// nothing, which of perms account holds on the resource.
func (g *gcloud) permissionCheck(ctx context.Context, account, resource, host, path, userProject string, perms []permission) connector.Check {
	what := "remediation permissions of " + account + " on " + resource
	names := permissionNames(perms)
	granted, err := g.testPermissions(ctx, account, host, path, userProject, names)
	if err != nil {
		_, why := classify(err)
		return connector.Check{Level: connector.Warn, What: what, Detail: "cannot test them: " + why,
			Fix: "segurata remediate needs: " + permissionList(perms)}
	}
	var missing []permission
	for _, p := range perms {
		if !slices.Contains(granted, p.name) {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return connector.Check{Level: connector.OK, What: what, Detail: "holds " + strings.Join(names, ", ")}
	}
	return connector.Check{Level: connector.Warn, What: what, Detail: "missing " + permissionList(missing),
		Fix: "grant the roles named above to " + account + ", or leave those remediations to an account that has them; the inventory does not need them"}
}

func permissionNames(ps []permission) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.name
	}
	return out
}

func permissionList(ps []permission) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = fmt.Sprintf("%s (%s, for %s)", p.name, p.role, p.use)
	}
	return strings.Join(parts, "; ")
}

func (g *gcloud) testPermissions(ctx context.Context, account, host, path, userProject string, names []string) ([]string, error) {
	api, err := g.api(ctx, host, account, userProject)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{"permissions": names})
	code, answer, err := api.Fetch(ctx, http.MethodPost, path, nil, body)
	if err != nil {
		return nil, err
	}
	if code < 200 || code > 299 {
		return nil, fmt.Errorf("HTTP %d: %s", code, httpx.ErrorMessage(answer))
	}
	var out struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(answer, &out); err != nil {
		return nil, fmt.Errorf("testIamPermissions: unexpected response: %w", err)
	}
	return out.Permissions, nil
}
