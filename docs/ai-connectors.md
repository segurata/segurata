# AI provider connectors

Three built-in connectors look for keys and accounts that can spend money without a ceiling:
`openai`, `anthropic` and `openrouter`. They send read-only `GET` requests and never print or store
a key value; a key appears only as the redacted hint the provider itself returns. The remediations
`openai.key.delete-unused` and `openrouter.key.delete-unused` delete a key only after a confirmed
plan, with a separate write key under `remediation_secrets` (README, "Write credentials").

Severity rules shared by the three:

| Situation | Severity |
|---|---|
| Key with no spend limit of its own, where the provider has per-key limits (OpenRouter) | high |
| Key whose owner is gone (left the project or the organization) | high |
| Key unused for more than 90 days, or never used | medium |
| Active key under a spend limit | info |
| Organization, project or workspace with no hard limit and no alert | high |
| Alerts but no hard limit | medium |
| Limit unreadable or not exposed by the API | low |

`created_at` and `last_used_at` are filled only from fields the API returns. When it does not
return them they stay `null`.

## OpenAI (`openai`)

Secret `OPENAI_ADMIN_KEY`, an Admin API key (`sk-admin-…`), sent as `Authorization: Bearer`. Base URL
`https://api.openai.com/v1`.

| Endpoint | Used for | Docs |
|---|---|---|
| `GET /organization/projects` | Projects (active only) | [list projects](https://developers.openai.com/api/reference/resources/organization/subresources/projects/methods/list) |
| `GET /organization/projects/{id}/api_keys?owner_project_access=any` | Project keys: `redacted_value`, `created_at`, `last_used_at`, `expires_at`, `owner`, `owner_project_access` | [list project API keys](https://developers.openai.com/api/reference/resources/organization/subresources/projects/subresources/api_keys/methods/list) |
| `GET /organization/admin_api_keys` | Admin keys and their last use | [list admin API keys](https://developers.openai.com/api/reference/resources/organization/subresources/admin_api_keys/methods/list) |
| `GET /organization/spend_limit` | Organization hard spend limit | [get organization spend limit](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/spend_limit/methods/retrieve) |
| `GET /organization/projects/{id}/spend_limit` | Project hard spend limit | [project spend limit](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/spend_limit) |
| `GET /organization/spend_alerts` | Organization spend alerts | [list organization spend alerts](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/spend_alerts/methods/list) |
| `GET /organization/projects/{id}/spend_alerts` | Project spend alerts | [list project spend alerts](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/spend_alerts/methods/list) |
| `GET /organization/costs?group_by[]=project_id` | Cost of the last 30 days per project | [costs](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/usage/methods/costs) |

Lists page with `after` = `last_id` while `has_more`; costs page with `page` = `next_page`.

What it reports: one `spend` finding for the organization and one per project (30-day cost, hard
limit, number of alerts, and for a project how many API keys it holds), one `credential` finding
per project key and per admin key. Keys have no spend limit of their own at OpenAI: a missing hard
limit is stated once, on the project finding ("N API keys can spend without a cap") and the
organization finding, and does not raise each key. A key's severity comes from the key alone
(owner gone, unused, never used); its evidence says `spend_capped` when the limits could be read.
A key whose `owner_project_access` is `inactive` belongs to someone who no longer has access to the
project.

What the API does not give, or what this connector assumes:

- The docs do not say what `GET …/spend_limit` returns when no limit is set. The connector reads a
  `404` as "no hard limit" and any other error as "unknown", which the spend finding reports as
  `low`.
- `enforcement.status` (`inactive` or `enforcing`) is copied to the evidence and does not change
  the severity.
- OpenAI's own usage-tier limit, assigned by OpenAI, is not a limit you set and is not read.
- Service accounts are covered through the owner of their keys; accounts without keys are not listed.

## Anthropic (`anthropic`)

Secret `ANTHROPIC_ADMIN_KEY`, an Admin API key (`sk-ant-admin01-…`), sent as `x-api-key` with
`anthropic-version: 2026-10-21`. Base URL `https://api.anthropic.com`. Only Claude Console
organizations can create this key; individual accounts must set up an organization first.

| Endpoint | Used for | Docs |
|---|---|---|
| `GET /v1/organizations/me` | Organization name for the `account` field | [Admin API](https://platform.claude.com/docs/en/manage-claude/admin-api) |
| `GET /v1/organizations/workspaces` | Workspace names | [list workspaces](https://platform.claude.com/docs/en/api/admin-api/workspaces/list-workspaces) |
| `GET /v1/organizations/users` | Current members, to spot keys whose creator left | [list users](https://platform.claude.com/docs/en/api/organization/users/list) |
| `GET /v1/organizations/api_keys` | Keys: `status`, `created_at`, `created_by`, `principal`, `scope`, `partial_key_hint`, `expires_at` | [list API keys](https://platform.claude.com/docs/en/api/admin-api/apikeys/list-api-keys) |
| `GET /v1/organizations/usage_report/messages?group_by[]=api_key_id&bucket_width=1d` | Last day each key had token use, over the last 91 days | [usage report](https://platform.claude.com/docs/en/api/beta/organization/usage_report/retrieve_messages) |
| `GET /v1/organizations/cost_report?group_by[]=workspace_id` | Cost of the last 30 days per workspace (amounts are cents as decimal strings) | [cost report](https://platform.claude.com/docs/en/api/beta/organization/cost_report/retrieve), [Usage and Cost API](https://platform.claude.com/docs/en/manage-claude/usage-cost-api) |

Lists page with `after_id` = `last_id` while `has_more`; reports page with `page` = `next_page`.

What it reports: one `credential` finding per active or inactive key (archived and expired keys
can no longer authenticate and are skipped), one `spend` finding for the organization and one per
workspace, the default workspace included.

What the API does not give:

- No last-used timestamp per key. The connector reads the daily usage report instead, puts the
  last day with tokens in `evidence.last_usage_day` and leaves `last_used_at` null. Console
  playground use has no key and does not count.
- No per-key spend limit, so the "no limit" rule never applies to Anthropic keys.
- Workspace and organization spend limits are not readable for Console organizations. The Spend
  Limits API exists only for Claude Enterprise and covers members, not workspaces
  ([Spend Limits API](https://platform.claude.com/docs/en/manage-claude/spend-limits-api)). Spend
  findings are therefore `low` with "spend limits are not readable through the Admin API"; check
  the [Limits page](https://platform.claude.com/settings/limits) by hand.
- Orphan detection covers workspace keys only (`principal` null): a key bound to a user acts as
  that user and is not treated as orphaned.
- The usage and cost endpoints used are the legacy ones, still supported. The newer Usage and Cost
  Analytics API is beta.

### Ephemeral Anthropic admin keys

Anthropic admin keys have full access (create and revoke keys, manage members) and cannot be made
read-only or set to expire. Rather than keeping one around, create it for the audit and delete it
right after:

```json
"anthropic:personal": {"secrets": {"ANTHROPIC_ADMIN_KEY": "env:ANTHROPIC_ADMIN_KEY"}}
```

```bash
# copy the new admin key, then:
ANTHROPIC_ADMIN_KEY="$(pbpaste)" segurata inventory anthropic; pbcopy </dev/null
# delete the key at https://platform.claude.com/settings/admin-keys
```

A Keychain item with no trusted apps (`-T ""`) asks on every read, but answering "Always Allow"
once trusts `/usr/bin/security`, which any process can call, so it does not protect the key in
practice.

## OpenRouter (`openrouter`)

Secret `OPENROUTER_MANAGEMENT_KEY`, a Management API key, sent as
`Authorization: Bearer`. Base URL `https://openrouter.ai/api/v1`. A read-only management key is
enough.

| Endpoint | Used for | Docs |
|---|---|---|
| `GET /workspaces` | Every workspace (offset pages of 100) | [list workspaces](https://openrouter.ai/docs/api/api-reference/workspaces/list-workspaces) |
| `GET /keys?workspace_id=…` | Keys: `label` (masked), `limit`, `limit_remaining`, `limit_reset`, `usage*`, `created_at`, `last_used_at`, `expires_at`, `creator_user_id` | [list API keys](https://openrouter.ai/docs/api/api-reference/api-keys/list-api-keys), [API key audit](https://openrouter.ai/docs/cookbook/administration/api-key-audit) |
| `GET /credits` | Credits purchased and used | [get remaining credits](https://openrouter.ai/docs/api/api-reference/credits/get-remaining-credits) |

`/keys` returns up to 100 keys a page; the connector passes `offset` and stops on a short page.
Disabled and expired keys are left out by the API by default.

What it reports: one `credential` finding per key, one `spend` finding per workspace (month-to-date
usage, keys without a limit) and one for the credit balance.

What the API does not give:

- Last-use times exist only from the end of 2025. A null `last_used_at` with past usage means
  "idle since then", not "never used", and the finding says so.
- Spend for the last 30 days: the API gives day, week, calendar-month and lifetime totals. The
  workspace finding uses the calendar month to date.
- Guardrail budgets that cap a key from outside are not read, so a key with `limit` null but under
  a guardrail budget still shows as high. Check guardrails before acting.
- Management keys and OAuth-created keys are not in `/keys`; review them on the security settings page.
- Whether auto top-up is on is not exposed. With it off, the prepaid balance bounds the loss.
- A workspace-scoped management key cannot list workspaces or read credits; the connector then
  inventories that key's own workspace and logs that the rest was skipped.

## One-time setup

1. Create the key in each console:
   - OpenAI: [Admin keys](https://platform.openai.com/settings/organization/admin-keys)
     ([guide](https://developers.openai.com/api/docs/guides/admin-apis)).
   - Anthropic: [Admin keys](https://platform.claude.com/settings/admin-keys), as an organization
     admin. Console admin keys have no scopes, so every key has full admin access
     ([guide](https://platform.claude.com/docs/en/manage-claude/admin-api-keys)).
   - OpenRouter: [Management keys](https://openrouter.ai/settings/management-keys), choose the
     read-only access level and an expiration
     ([guide](https://openrouter.ai/docs/guides/overview/auth/management-api-keys)).
2. Store each one in the macOS Keychain (the command prompts for the value, so it stays out of
   shell history):

   ```sh
   security add-generic-password -s segurata-openai-admin -a "$USER" -w
   security add-generic-password -s segurata-anthropic-admin -a "$USER" -w
   security add-generic-password -s segurata-openrouter-admin -a "$USER" -w
   ```

3. Reference them in `~/.config/segurata/config.json`:

   ```json
   {
     "connectors": {
       "openai": {"secrets": {"OPENAI_ADMIN_KEY": "keychain:segurata-openai-admin"}},
       "anthropic": {"secrets": {"ANTHROPIC_ADMIN_KEY": "keychain:segurata-anthropic-admin"}},
       "openrouter": {"secrets": {"OPENROUTER_MANAGEMENT_KEY": "keychain:segurata-openrouter-admin"}}
     }
   }
   ```

4. Run `segurata inventory openai anthropic openrouter`. Without a key each connector reports
   `missing_credentials` with these steps and does nothing else.

The OpenAI and Anthropic keys can do far more than read. Keep them in the Keychain only, give them
an expiration where the console allows it, and revoke them when you stop running segurata.
