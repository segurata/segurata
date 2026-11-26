package openai

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpw"
	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// ActionDeleteUnusedKey deletes a project or admin key never used or idle past finding.IdleAfter.
const ActionDeleteUnusedKey = "openai.key.delete-unused"

// writeSecret lives under remediation_secrets, apart from the possibly read-only inventory key,
// and is resolved only at apply time.
const writeSecret = "OPENAI_ADMIN_WRITE_KEY"

const writeSetup = writeSecret + " is not configured. Deleting a key needs an admin key with write access, apart from the inventory's (which may be read-only): " +
	"create one at " + adminURL + `, store it with: security add-generic-password -s segurata-openai-admin-write -a "$USER" -w` +
	` and reference it as "keychain:segurata-openai-admin-write" under connectors.openai.remediation_secrets.` + writeSecret +
	` in ~/.config/segurata/config.json. Only remediate --apply reads it; delete that key when you are done if you prefer.`

// writeRoutes are the only requests a deletion may send (developers.openai.com/api/reference,
// checked 2026-11-24).
var writeRoutes = []httpw.Route{
	httpw.Delete(`/organization/projects/` + httpw.Seg + `/api_keys/` + httpw.Seg),
	httpw.Delete(`/organization/admin_api_keys/` + httpw.Seg),
}

func unusedAction(lastUsed, expires *time.Time, now time.Time) string {
	if expires != nil && expires.Before(now) {
		return ""
	}
	if lastUsed == nil || now.Sub(*lastUsed) > finding.IdleAfter {
		return ActionDeleteUnusedKey
	}
	return ""
}

func (c *Connector) WithCredentials(cs connector.Credentials) connector.Remediator {
	return &remediator{c: c, cs: cs}
}

type remediator struct {
	c  *Connector
	cs connector.Credentials
}

type liveKey struct {
	path     string // DELETE path under the base URL
	label    string
	redacted string
	lastUsed *time.Time
	expires  *time.Time
}

// read finds the key now with the read-only inventory key.
func (r *remediator) read(ctx context.Context, f finding.Finding) (liveKey, error) {
	read := r.cs.Request.Secrets[secretName]
	if read == "" {
		return liveKey{}, fmt.Errorf("%s is not configured: the plan reads the key's current state with it; %s", secretName, setupHint)
	}
	s := &scan{ctx: ctx, api: httpx.New(r.c.base(), http.Header{"Authorization": {"Bearer " + read}})}
	listed, err := list[adminKey](s, "/organization/admin_api_keys", nil)
	if err != nil {
		return liveKey{}, err
	}
	admins, lastUsed := splitAdminListing(listed)
	id := f.Resource.ID
	switch f.Resource.Type {
	case "admin_api_key":
		for _, k := range admins {
			if k.ID == id {
				label := k.ID
				if k.Name != nil && *k.Name != "" {
					label = *k.Name
				}
				return liveKey{path: "/organization/admin_api_keys/" + url.PathEscape(k.ID), label: fmt.Sprintf("admin API key %q", label),
					redacted: k.RedactedValue, lastUsed: httpx.Unix(k.LastUsedAt), expires: httpx.Unix(k.ExpiresAt)}, nil
			}
		}
	case "api_key":
		project, err := projectID(s, f)
		if err != nil {
			return liveKey{}, err
		}
		keys, err := list[projectKey](s, "/organization/projects/"+url.PathEscape(project)+"/api_keys", url.Values{"owner_project_access": {"any"}})
		if err != nil {
			return liveKey{}, err
		}
		for _, k := range keys {
			if k.ID == id {
				used := k.LastUsedAt
				if used == nil {
					used = lastUsed[k.ID]
				}
				name, _ := f.Evidence["project"].(string)
				return liveKey{path: "/organization/projects/" + url.PathEscape(project) + "/api_keys/" + url.PathEscape(k.ID),
					label: fmt.Sprintf("project API key %q in project %q", k.Name, name), redacted: k.RedactedValue,
					lastUsed: httpx.Unix(used), expires: httpx.Unix(k.ExpiresAt)}, nil
			}
		}
	default:
		return liveKey{}, fmt.Errorf("openai cannot delete a %s", f.Resource.Type)
	}
	return liveKey{}, fmt.Errorf("key %s no longer exists: nothing to do; run the inventory again", id)
}

// projectID falls back, for a finding recorded before it carried one, to the only project with
// its name.
func projectID(s *scan, f finding.Finding) (string, error) {
	if id, _ := f.Evidence["project_id"].(string); id != "" {
		return id, nil
	}
	name, _ := f.Evidence["project"].(string)
	projects, err := list[project](s, "/organization/projects", nil)
	if err != nil {
		return "", err
	}
	var ids []string
	for _, p := range projects {
		if p.label() == name {
			ids = append(ids, p.ID)
		}
	}
	if len(ids) != 1 {
		return "", fmt.Errorf("%d projects are named %q now: run the openai inventory again, so the finding names its project id", len(ids), name)
	}
	return ids[0], nil
}

func (r *remediator) Plan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	if f.Remediation.Action != ActionDeleteUnusedKey {
		return connector.Plan{}, fmt.Errorf("openai has no remediation %q", f.Remediation.Action)
	}
	k, err := r.read(ctx, f)
	if err != nil {
		return connector.Plan{}, err
	}
	now := connector.Now(r.c.Now)
	if unusedAction(k.lastUsed, k.expires, now) == "" {
		return connector.Plan{}, fmt.Errorf("the %s is no longer unused (last used %s): not deleting it; run the inventory again", k.label, k.lastUsed.Format(time.DateOnly))
	}
	if httpx.MatchesRedacted(k.redacted, r.cs.Request.Secrets[secretName]) {
		return connector.Plan{}, fmt.Errorf("the %s is the key segurata reads OpenAI with (%s): not deleting it", k.label, secretName)
	}
	used := "never used"
	if k.lastUsed != nil {
		used = fmt.Sprintf("last used %s, %d days ago", k.lastUsed.Format(time.DateOnly), httpx.Days(now, *k.lastUsed))
	}
	p := connector.Plan{
		Action:  ActionDeleteUnusedKey,
		Summary: fmt.Sprintf("Delete the OpenAI %s (%s), %s.", k.label, keyHint(k.redacted), used),
		Calls:   []connector.Call{{Method: http.MethodDelete, URL: r.c.base() + k.path, Secret: writeSecret}},
		SideEffects: []string{
			"No undo: a deleted key cannot be restored. Anything still holding it gets HTTP 401 and needs a new key.",
			"Nothing else changes: the project, its other keys and its service accounts stay.",
		},
	}
	if !r.cs.HasWrite(writeSecret) {
		p.Blocked = writeSetup
	}
	return p, nil
}

func (r *remediator) Apply(ctx context.Context, f finding.Finding, p connector.Plan, _ connector.IO) error {
	write, err := r.cs.Write(ctx, writeSecret)
	if err != nil {
		return err
	}
	return httpw.Send(ctx, r.c.base(), http.Header{"Authorization": {"Bearer " + write}}, p.Calls, writeRoutes...)
}
