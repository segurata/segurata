package gcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// ActionRestrictKey restricts an API key without API restrictions to the APIs Cloud Monitoring saw
// it call in the last 30 days.
const ActionRestrictKey = "gcp.apikey.restrict"

// WithCredentials binds the instance's config: the plans read quota_caps, budget_amount,
// billing_project and gcloud_path from it.
func (c *Connector) WithCredentials(cs connector.Credentials) connector.Remediator {
	return &remediator{c: c, req: cs.Request}
}

type remediator struct {
	c   *Connector
	req connector.Request
}

// Plan reads the live state with the read-only gcloud allowlist and states the exact commands.
func (r *remediator) Plan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	cfg, err := parseSettings(r.req.Config)
	if err != nil {
		return connector.Plan{}, err
	}
	g, err := r.c.gcloud(cfg)
	if err != nil {
		return connector.Plan{}, err
	}
	switch f.Remediation.Action {
	case ActionRestrictKey:
		return r.restrictPlan(ctx, g, f)
	}
	return connector.Plan{}, fmt.Errorf("gcp has no remediation %q", f.Remediation.Action)
}

// Apply runs only the commands a fresh read plans now: they are the whole allowlist.
func (r *remediator) Apply(ctx context.Context, f finding.Finding, p connector.Plan, io connector.IO) error {
	fresh, err := r.Plan(ctx, f)
	if err != nil {
		return err
	}
	return connector.Allowlist{fresh.Action: fresh.Commands}.Run(ctx, p, r.c.exec, io)
}

func (g *gcloud) step(args ...string) connector.Step {
	return connector.Step{Argv: append([]string{g.path}, args...)}
}

func evidenceString(f finding.Finding, key string) (string, error) {
	if s, _ := f.Evidence[key].(string); s != "" {
		return s, nil
	}
	return "", fmt.Errorf("finding %s has no %s in its evidence: run the inventory again", f.ID, key)
}

// keyLocation is the location segment of projects/P/locations/L/keys/K.
func keyLocation(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "locations" {
			return parts[i+1]
		}
	}
	return "global"
}

func (r *remediator) restrictPlan(ctx context.Context, g *gcloud, f finding.Finding) (connector.Plan, error) {
	project, err := evidenceString(f, "project")
	if err != nil {
		return connector.Plan{}, err
	}
	var keys []apiKey
	if err := g.json(ctx, &keys, "services", "api-keys", "list", "--project="+project, "--account="+f.Account); err != nil {
		_, why := classify(err)
		return connector.Plan{}, fmt.Errorf("services api-keys list in %s: %s", project, why)
	}
	i := -1
	for j, k := range keys {
		if apiKeyID(f.Account, project, k) == f.ID {
			i = j
		}
	}
	if i < 0 {
		return connector.Plan{}, fmt.Errorf("nothing to do: API key %q no longer exists in %s", f.Resource.Name, project)
	}
	k := keys[i]
	if apis := k.apiTargets(); len(apis) > 0 {
		return connector.Plan{}, fmt.Errorf("nothing to do: API key %q is already restricted to %s", f.Resource.Name, strings.Join(apis, ", "))
	}
	console := consoleURL("apis/credentials", project)
	u := g.usage(ctx, f.Account, project, g.userProject(project), []string{k.uid()}, r.c.now())[k.uid()]
	switch {
	case !u.known():
		_, why := classify(u.err)
		return connector.Plan{}, fmt.Errorf("refused: Cloud Monitoring could not be read, so the APIs key %q calls are unknown: %s", f.Resource.Name, why)
	case len(u.apis) == 0:
		return connector.Plan{}, fmt.Errorf("refused: no API was called with key %q in the last 30 days, so there is nothing to restrict it to. "+
			"It is a candidate for deletion: delete it at %s once you are sure nothing uses it", f.Resource.Name, console)
	}
	args := []string{"services", "api-keys", "update", lastSegment(k.Name), "--location=" + keyLocation(k.Name), "--project=" + project}
	for _, s := range u.apis {
		args = append(args, "--api-target=service="+s)
	}
	args = append(args, "--account="+f.Account)
	app := "Its application restriction (referrers, IP addresses or apps) stays as it is: gcloud updates only the API targets."
	if !k.appRestricted() {
		app = "It keeps no application restriction: which referrers, IP addresses or apps call it cannot be read from usage, so add one at " + console + "."
	}
	return connector.Plan{
		Action: ActionRestrictKey,
		Summary: fmt.Sprintf("Restrict API key %q in %s to the %d APIs it called in the last 30 days: %s.",
			f.Resource.Name, project, len(u.apis), strings.Join(u.apis, ", ")),
		Commands: []connector.Step{g.step(args...)},
		SideEffects: []string{
			"Calls with this key to any other API fail from now on. An API it last called more than 30 days ago is left out; if it is still needed, add it with another --api-target.",
			"gcloud first checks the key's traffic of the last 7 days (--check-existing-usage, on by default) and refuses a change that traffic would break.",
			app,
			"Undo: gcloud refuses to leave a key without API targets (\"API keys must have API target restrictions\"), so the undo is in the console: open " +
				console + ", edit the key and choose \"Don't restrict key\" under API restrictions.",
		},
	}, nil
}
