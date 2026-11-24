// Package supabase inventories Supabase through the Management API: organizations and their plan,
// projects, and each project's API keys (names and types, never values). Read-only.
// See docs/cloud-connectors.md.
package supabase

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const (
	secretName     = "SUPABASE_ACCESS_TOKEN"
	DefaultBaseURL = "https://api.supabase.com"
	setupHint      = "create a personal access token at https://supabase.com/dashboard/account/tokens, store it with " +
		"`security add-generic-password -s segurata-supabase -a \"$USER\" -w` and reference it in " +
		"~/.config/segurata/config.json as connectors.supabase.secrets.SUPABASE_ACCESS_TOKEN = \"keychain:segurata-supabase\""
)

// Connector is the built-in Supabase connector. A zero BaseURL uses the real API.
type Connector struct {
	BaseURL string
}

func init() { connector.Register(&Connector{}) }

// SetupHint says how to create and store the secret the connector needs (connector.SetupHinter).
func (c *Connector) SetupHint(secret string) string {
	return connector.HintFor(secret, secretName, setupHint)
}

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     "supabase",
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "Organizations and plans, projects, API keys by name and type; the spend cap is not exposed by the API",
		Needs:    []string{"secret:" + secretName},
	}
}

type organization struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
	Plan string `json:"plan"`
}

type project struct {
	Ref              string `json:"ref"`
	Name             string `json:"name"`
	OrganizationSlug string `json:"organization_slug"`
	Region           string `json:"region"`
	Status           string `json:"status"`
}

// apiKey decodes only metadata: the api_key field is never read into memory as a value we keep.
type apiKey struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Type       *string `json:"type"`
	InsertedAt *string `json:"inserted_at"`
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	tok := req.Secrets[secretName]
	if tok == "" {
		emit.Status(finding.Status{Account: "supabase", State: finding.StateMissingCredentials, Detail: secretName + " is not configured: " + setupHint})
		return nil
	}
	api := httpx.New(httpx.Base(c.BaseURL, DefaultBaseURL), http.Header{"Authorization": {"Bearer " + tok}})
	var orgs []organization
	if err := api.Get(ctx, "/v1/organizations", nil, &orgs); err != nil {
		emit.Status(finding.Status{Account: "supabase", State: httpx.State(err), Detail: err.Error()})
		return nil
	}
	failed := map[string][]string{}
	for _, o := range orgs {
		var full organization
		if err := api.Get(ctx, "/v1/organizations/"+url.PathEscape(o.Slug), nil, &full); err != nil {
			failed[o.Slug] = append(failed[o.Slug], "organization: "+err.Error())
			continue
		}
		full.Slug = o.Slug
		for _, f := range orgFindings(full) {
			f.Account = o.Slug
			emit.Finding(f)
		}
	}

	var projects []project
	if err := api.Get(ctx, "/v1/projects", nil, &projects); err != nil {
		failed["supabase"] = append(failed["supabase"], "projects: "+err.Error())
		emit.Scope(projectScope("*"), false, "projects not listed: "+err.Error())
	}
	for _, p := range projects {
		if p.Status == "REMOVED" {
			continue
		}
		var keys []apiKey
		if err := api.Get(ctx, "/v1/projects/"+url.PathEscape(p.Ref)+"/api-keys", url.Values{"reveal": {"false"}}, &keys); err != nil {
			failed[p.OrganizationSlug] = append(failed[p.OrganizationSlug], fmt.Sprintf("api keys of %s: %v", p.Name, err))
			continue
		}
		for _, k := range keys {
			f := keyFinding(p, k)
			f.Account, f.Scope = p.OrganizationSlug, projectScope(p.Ref)
			emit.Finding(f)
		}
	}

	emitStatuses(orgs, failed, emit)
	return nil
}

// projectScope scopes a project's findings, which come from the project list: when it fails, the
// organizations still read, but none of the projects.
func projectScope(ref string) string { return "project:" + ref }

// emitStatuses reports one status per organization and per account with failures, in name order.
func emitStatuses(orgs []organization, failed map[string][]string, emit connector.Emitter) {
	accounts := map[string]bool{}
	for _, o := range orgs {
		accounts[o.Slug] = true
	}
	for a := range failed {
		accounts[a] = true
	}
	names := make([]string, 0, len(accounts))
	for a := range accounts {
		names = append(names, a)
	}
	sort.Strings(names)
	for _, a := range names {
		st := finding.Status{Account: a, State: finding.StateOK}
		if msgs := failed[a]; len(msgs) > 0 {
			st.State, st.Detail = finding.StateError, strings.Join(msgs, "; ")
		}
		emit.Status(st)
	}
}
