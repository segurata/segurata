package openrouter

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
	"github.com/segurata/segurata/internal/remediate"
)

// ActionDeleteUnusedKey deletes an API key that was never used or not for longer than
// httpx.IdleAfter.
const ActionDeleteUnusedKey = "openrouter.key.delete-unused"

// writeSecret is a read/write management key. The inventory's OPENROUTER_MANAGEMENT_KEY is
// read-only by its setup hint, and a read-only management key gets 403 on any write; this one
// lives under remediation_secrets and is resolved only at apply time.
const writeSecret = "OPENROUTER_MANAGEMENT_WRITE_KEY"

const writeSetup = writeSecret + " is not configured. Deleting a key needs a read/write Management API key, apart from the inventory's read-only one: " +
	"create one at " + managementURL + " (access level read/write, scoped like the inventory's)" +
	`, store it with: security add-generic-password -s segurata-openrouter-admin-write -a "$USER" -w` +
	` and reference it as "keychain:segurata-openrouter-admin-write" under remediation_secrets.` + writeSecret +
	` of this instance in ~/.config/segurata/config.json. Only remediate --apply reads it.`

// writeRoutes are the only requests a deletion may send: DELETE /api/v1/keys/{hash}
// (openrouter.ai/docs, "Management API keys", checked 2026-11-24).
var writeRoutes = []httpw.Route{httpw.Delete(`/keys/` + httpw.Seg)}

// unusedAction offers the deletion for a key that has not expired and has no recorded use for
// longer than httpx.IdleAfter: never used, idle, or with past spend but no use recorded since
// OpenRouter began recording it at the end of 2025.
func unusedAction(k apiKey, now time.Time) string {
	if k.Disabled {
		return ""
	}
	if e := httpx.ParseTime(k.ExpiresAt); e != nil && e.Before(now) {
		return ""
	}
	if last := httpx.ParseTime(k.LastUsedAt); last == nil || now.Sub(*last) > httpx.IdleAfter {
		return ActionDeleteUnusedKey
	}
	return ""
}

// WithCredentials binds the instance's credentials (connector.CredentialedRemediator).
func (c *Connector) WithCredentials(cs connector.Credentials) connector.Remediator {
	return &remediator{c: c, cs: cs}
}

type remediator struct {
	c  *Connector
	cs connector.Credentials
}

// read finds the key now in its workspace's listing, with the read-only inventory key.
func (r *remediator) read(ctx context.Context, f finding.Finding) (apiKey, error) {
	read := r.cs.Request.Secrets[secretName]
	if read == "" {
		return apiKey{}, fmt.Errorf("%s is not configured: the plan reads the key's current state with it; %s", secretName, setupHint)
	}
	s := &scan{ctx: ctx, api: httpx.New(httpx.Base(r.c.BaseURL, DefaultBaseURL), http.Header{"Authorization": {"Bearer " + read}})}
	q := url.Values{}
	if ws, _ := f.Evidence["workspace_id"].(string); ws != "" {
		q.Set("workspace_id", ws)
	}
	keys, err := list[apiKey](s, "/keys", q)
	if err != nil {
		return apiKey{}, err
	}
	for _, k := range keys {
		if k.Hash == f.Resource.ID {
			return k, nil
		}
	}
	return apiKey{}, fmt.Errorf("key %s no longer exists: nothing to do; run the inventory again", f.Resource.ID)
}

func (r *remediator) Plan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	if f.Remediation.Action != ActionDeleteUnusedKey {
		return connector.Plan{}, fmt.Errorf("openrouter has no remediation %q", f.Remediation.Action)
	}
	k, err := r.read(ctx, f)
	if err != nil {
		return connector.Plan{}, err
	}
	now := connector.Now(r.c.Now)
	n := k.Name
	if n == "" {
		n = k.Hash
	}
	if unusedAction(k, now) == "" {
		return connector.Plan{}, fmt.Errorf("API key %q is no longer an unused, enabled key: not deleting it; run the inventory again", n)
	}
	if httpx.MatchesRedacted(k.Label, r.cs.Request.Secrets[secretName]) {
		return connector.Plan{}, fmt.Errorf("API key %q is the key segurata reads OpenRouter with (%s): not deleting it", n, secretName)
	}
	used := "never used"
	switch last := httpx.ParseTime(k.LastUsedAt); {
	case last != nil:
		used = fmt.Sprintf("last used %s, %d days ago", last.Format(time.DateOnly), httpx.Days(now, *last))
	case k.Usage > 0 || k.BYOKUsage > 0:
		used = fmt.Sprintf("no recorded use since the end of 2025 (%s spent before)", httpx.USD(k.Usage))
	}
	p := connector.Plan{
		Action:  ActionDeleteUnusedKey,
		Summary: fmt.Sprintf("Delete the OpenRouter API key %q (%s) in %s, %s.", n, k.Label, f.Account, used),
		Calls:   []connector.Call{{Method: http.MethodDelete, URL: httpx.Base(r.c.BaseURL, DefaultBaseURL) + "/keys/" + url.PathEscape(k.Hash), Secret: writeSecret}},
		SideEffects: []string{
			"No undo: a deleted key cannot be restored. Anything still holding it gets HTTP 401 and needs a new key.",
			"Its usage history stays in the account's activity; the credit balance and other keys do not change.",
		},
	}
	if !r.cs.HasWrite(writeSecret) {
		p.Blocked = writeSetup
	}
	return p, nil
}

// Apply reads the key again, refuses a plan that differs from the one shown, resolves the write
// key and sends the plan's one DELETE through the write client's routes.
func (r *remediator) Apply(ctx context.Context, f finding.Finding, p connector.Plan, _ connector.IO) error {
	want, err := r.Plan(ctx, f)
	if err != nil {
		return err
	}
	if err := remediate.SamePlan(want, p); err != nil {
		return err
	}
	write, err := r.cs.Write(writeSecret)
	if err != nil {
		return err
	}
	return httpw.Send(ctx, httpx.Base(r.c.BaseURL, DefaultBaseURL), http.Header{"Authorization": {"Bearer " + write}}, p.Calls, writeRoutes...)
}
