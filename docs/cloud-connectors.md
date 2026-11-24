# Cloud connectors

Five built-in connectors look for credentials that grant too much or live too long, accounts whose
spend has no budget, alert or cap, and weak account and edge settings: `aws`, `azure`, `vercel`,
`supabase` and `cloudflare`. All five are read-only: they only list, get and describe. They never print or store a secret value; a key
appears at most as the identifier or hint the provider itself returns, redacted with
`finding.Redact` when it is a key id.

`aws` and `azure` call the CLIs that are already signed in on the machine (`aws`, `az`) with JSON
output, through the runner they share with `gcp` (`connectors/internal/cli`). Each keeps an
allowlist of exactly the commands in its table below; anything else is refused before it reaches
the CLI, so a bug cannot run `aws iam delete-access-key` or `az ad app credential reset`. Tests
check both that every command the connector runs is on the list and that mutating ones are
refused. Each `aws` command has a 2 minute timeout, each `az` one 3 minutes. `vercel`, `supabase` and `cloudflare` call the providers' REST APIs, GET only, with a token the
core resolves from the config (`env:`, `keychain:` or `op://`, see [secrets.md](secrets.md)). None
reads a token from another tool's config files: the `vercel` CLI's stored login and `wrangler`'s
are never touched.

Whatever fails turns into a `status` record, never a crash: a missing CLI is `unsupported`, an
expired session `reauth`, `az` without a login `signedout`, a missing token `missing_credentials`
with setup steps, and a check the identity has no permission for is `error` on that account while
the other checks still run.

`created_at` and `last_used_at` are filled only from fields the provider returns.

## AWS (`aws`)

Profiles come from `aws configure list-profiles`, or from `connectors.aws.config.profiles` when set.
Each profile is resolved with `sts get-caller-identity`; profiles that reach an account already
inspected are skipped. Every command gets `--profile <p> --region us-east-1 --output json
--no-cli-pager`: IAM, STS, Budgets and Cost Explorer are served from us-east-1 in the `aws`
partition (China and GovCloud partitions are not handled).

| Command | Used for | Docs |
|---|---|---|
| `aws configure list-profiles` | Profiles to inspect | [list-profiles](https://docs.aws.amazon.com/cli/latest/reference/configure/list-profiles.html) |
| `aws sts get-caller-identity` | Account id and caller ARN (a `:root` ARN means the profile uses root keys) | [get-caller-identity](https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html) |
| `aws iam list-account-aliases` | Account label | [list-account-aliases](https://docs.aws.amazon.com/cli/latest/reference/iam/list-account-aliases.html) |
| `aws iam get-account-summary` | Root MFA (`AccountMFAEnabled`) and root keys (`AccountAccessKeysPresent`) | [get-account-summary](https://docs.aws.amazon.com/cli/latest/reference/iam/get-account-summary.html) |
| `aws iam list-users` | IAM users | [list-users](https://docs.aws.amazon.com/cli/latest/reference/iam/list-users.html) |
| `aws iam list-access-keys --user-name` | Key id, status, creation date | [list-access-keys](https://docs.aws.amazon.com/cli/latest/reference/iam/list-access-keys.html) |
| `aws iam get-access-key-last-used --access-key-id` | Last use (`null` when never used) | [get-access-key-last-used](https://docs.aws.amazon.com/cli/latest/reference/iam/get-access-key-last-used.html) |
| `aws iam get-login-profile --user-name` | Whether the user has a console password (`NoSuchEntity` when not) | [get-login-profile](https://docs.aws.amazon.com/cli/latest/reference/iam/get-login-profile.html) |
| `aws iam list-mfa-devices --user-name` | MFA devices of the user | [list-mfa-devices](https://docs.aws.amazon.com/cli/latest/reference/iam/list-mfa-devices.html) |
| `aws budgets describe-budgets --account-id` | Budgets | [describe-budgets](https://docs.aws.amazon.com/cli/latest/reference/budgets/describe-budgets.html) |
| `aws budgets describe-notifications-for-budget` | Alerts of each budget | [describe-notifications-for-budget](https://docs.aws.amazon.com/cli/latest/reference/budgets/describe-notifications-for-budget.html) |

The connector reads users one call at a time instead of using the IAM credential report, so it never
runs `aws iam generate-credential-report`. That command changes no resource, but it does start a
report job; it [exists](https://docs.aws.amazon.com/cli/latest/reference/iam/generate-credential-report.html)
and would cut calls on accounts with many users if that ever matters.

### Cost Explorer is opt-in because it is billed

Every Cost Explorer API request costs USD 0.01
([pricing](https://aws.amazon.com/aws-cost-management/aws-cost-explorer/pricing/)), so the
connector makes none unless the config says so:

```json
{"connectors": {"aws": {"config": {"cost_explorer": true}}}}
```

With it on, each account adds two billed requests per run:

| Command | Used for | Docs |
|---|---|---|
| `aws ce get-cost-and-usage --time-period Start=<1st>,End=<tomorrow> --granularity MONTHLY --metrics UnblendedCost` | Month-to-date spend (end date is exclusive) | [get-cost-and-usage](https://docs.aws.amazon.com/cli/latest/reference/ce/get-cost-and-usage.html) |
| `aws ce get-anomaly-monitors` | Whether Cost Anomaly Detection watches the account | [get-anomaly-monitors](https://docs.aws.amazon.com/cli/latest/reference/ce/get-anomaly-monitors.html) |

The [Budgets pricing page](https://aws.amazon.com/aws-cost-management/aws-budgets/pricing/) charges
for action-enabled budgets and budget reports, and does not list a charge for reading budgets.

### Local credentials file

The connector also reads `~/.aws/credentials` (or `AWS_SHARED_CREDENTIALS_FILE`), keeping only each
profile's name, its access key id (emitted redacted) and whether it has a session token. Secret
values are skipped as the file is read. Profiles with a session token expire on their own and are
not reported. [Config and credential files](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).

### Severity

| Situation | Kind | Severity |
|---|---|---|
| Root user without MFA | `setting` | critical |
| Root user with access keys | `credential` | critical |
| A CLI profile signs in as root | `credential` | critical |
| Active key older than 90 days, unused for 90 days, or never used and older than 90 days | `credential` | high |
| Console user without MFA | `setting` | high |
| No budget in the account | `spend` | high |
| Long-lived key in the credentials file readable by group or others | `exposure` | high |
| Long-lived key in the credentials file at mode 0600 | `exposure` | medium |
| Budget without alerts | `spend` | medium |
| No Cost Anomaly Detection monitor (opt-in) | `spend` | medium |
| Inactive key still present | `credential` | low |
| Any other key, budget with alerts, month-to-date spend (opt-in) | `credential` / `spend` | info |

IAM actions the identity needs: `sts:GetCallerIdentity` (always allowed), `iam:ListAccountAliases`,
`iam:GetAccountSummary`, `iam:ListUsers`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`,
`iam:GetLoginProfile`, `iam:ListMFADevices` and `budgets:ViewBudget`; with the opt-in,
`ce:GetCostAndUsage` and `ce:GetAnomalyMonitors`. A missing one leaves that check as an `error`
status and the others still run.

## Azure (`azure`)

Runs only when `az account show` works; otherwise the status is `signedout` (no login),
`reauth` (token expired) or `unsupported` (no `az`). Every command gets `--output json
--only-show-errors`.

| Command | Used for | Docs |
|---|---|---|
| `az account show` | Signed-in tenant | [az account](https://learn.microsoft.com/en-us/cli/azure/account?view=azure-cli-latest) |
| `az account list` | Subscriptions; only `Enabled` ones are inspected | [az account](https://learn.microsoft.com/en-us/cli/azure/account?view=azure-cli-latest) |
| `az consumption budget list --subscription <id>` | Budgets and their notifications (command group in preview) | [az consumption budget](https://learn.microsoft.com/en-us/cli/azure/consumption/budget?view=azure-cli-latest) |
| `az ad app list --all --query "[].{appId,displayName,passwordCredentials}"` | App registrations and client secret metadata | [az ad app](https://learn.microsoft.com/en-us/cli/azure/ad/app?view=azure-cli-latest) |

`az ad app list` returns only the first 100 apps without `--all`, so the connector passes it. From
each [passwordCredential](https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0)
it keeps `keyId`, `hint` (the first three characters, as the portal shows), `displayName`,
`startDateTime` and `endDateTime`. Graph returns the secret value only when it is created.

| Situation | Kind | Severity |
|---|---|---|
| Client secret without end date or ending more than two years out (the portal caps new secrets at 24 months) | `credential` | high |
| Subscription without budget | `spend` | high |
| Client secret expiring within 30 days | `credential` | medium |
| Budget without enabled notifications | `spend` | medium |
| Expired client secret still registered | `credential` | low |
| Other client secrets, budgets with alerts | `credential` / `spend` | info |

Not covered: certificate credentials (`keyCredentials`), service principal secrets outside app
registrations, and the spending limit of free or credit-based offers, which `az` does not expose.
Some offer types return an error from the budgets API; that subscription gets an `error` status.

## Vercel (`vercel`)

Secret `VERCEL_TOKEN`, sent as `Authorization: Bearer`. Base URL `https://api.vercel.com`
([REST API](https://vercel.com/docs/rest-api)).

| Endpoint | Used for | Docs |
|---|---|---|
| `GET /v2/user` | Account label (username) | [get the user](https://vercel.com/docs/rest-api/reference/endpoints/user/get-the-user) |
| `GET /v6/user/tokens?status=active` | Tokens: `kind`, `origin`, `scopes`, `createdAt`, `activeAt`, `expiresAt`, `leakedAt`, `leakedUrl` (milliseconds) | [list auth tokens](https://vercel.com/docs/rest-api/reference/endpoints/authentication/list-auth-tokens) |
| `GET /v2/teams?limit=100` | Teams, `billing.plan`, the caller's role | [list all teams](https://vercel.com/docs/rest-api/reference/endpoints/teams/list-all-teams) |

The token response also has `prefix` and `suffix`; the connector does not read them.

| Situation | Kind | Severity |
|---|---|---|
| Token reported leaked by Vercel (`leakedAt`) | `credential` | critical |
| Token unused for more than 90 days | `credential` | high |
| Token without expiry | `credential` | medium |
| Team on Pro or Enterprise: check Spend Management by hand | `spend` | low |
| Other tokens, each team and its plan | `credential` / `setting` | info |

Not available through the API: Spend Management budgets. The public
[OpenAPI description](https://vercel.com/openapi.json) has no budget endpoint (it has AI Gateway
budgets only). Vercel CLI releases newer than the installed 48.9.0 add `vercel billing budgets list
--json` ([docs](https://vercel.com/docs/cli/budgets)); it is not used here because the installed CLI
lacks it and its auth would have to come from `VERCEL_TOKEN` rather than the CLI's own login.
[Spend Management](https://vercel.com/docs/spend-management) exists on Pro and Enterprise
(Flexible Commitment); a budget alone only notifies, "Pause production deployments" is what stops
spend. Hobby has no usage billing, so no check is asked for there.

Setup:

1. Create a token at <https://vercel.com/account/settings/tokens>, with an expiry.
2. `security add-generic-password -s securizame-vercel -a "$USER" -w` (paste the token at the prompt).
3. In `~/.config/securizame/config.json`:

   ```json
   {"connectors": {"vercel": {"secrets": {"VERCEL_TOKEN": "keychain:securizame-vercel"}}}}
   ```

## Supabase (`supabase`)

Secret `SUPABASE_ACCESS_TOKEN`, a personal access token, sent as `Authorization: Bearer`. Base URL
`https://api.supabase.com` ([Management API](https://supabase.com/docs/reference/api/introduction),
120 requests per minute). The Supabase CLI is not needed.

| Endpoint | Used for | Docs |
|---|---|---|
| `GET /v1/organizations` | Organizations | [list all organizations](https://supabase.com/docs/reference/api/v1-list-all-organizations) |
| `GET /v1/organizations/{slug}` | Plan (`free`, `pro`, `team`, `enterprise`, `platform`) | [get an organization](https://supabase.com/docs/reference/api/v1-get-an-organization) |
| `GET /v1/projects` | Projects, their organization, region and status | [list all projects](https://supabase.com/docs/reference/api/v1-list-all-projects) |
| `GET /v1/projects/{ref}/api-keys?reveal=false` | API keys: `name`, `type` (`legacy`, `publishable`, `secret`), `inserted_at` | [get project API keys](https://supabase.com/docs/reference/api/v1-get-project-api-keys) |

The keys endpoint returns an `api_key` field; the connector asks with `reveal=false` and does not
decode that field at all. Projects with status `REMOVED` are skipped.

| Situation | Kind | Severity |
|---|---|---|
| Legacy `service_role` key still enabled (long-lived JWT that bypasses RLS) | `credential` | medium |
| Organization on a paid plan: check the spend cap by hand | `spend` | low |
| Other API keys, each organization and its plan | `credential` / `setting` | info |

Not available through the API: the spend cap. The
[Management API description](https://api.supabase.com/api/v1-json) has no spend cap or billing
limit field; [Cost Control](https://supabase.com/docs/guides/platform/cost-control) is set in the
dashboard (Pro plan). Personal access tokens are not listed by the API either.

Setup:

1. Create a token at <https://supabase.com/dashboard/account/tokens>. Prefer a scoped, read-only
   token; the endpoints above are tagged with the scopes `organizations:read`, `projects:read` and
   `secrets:read` in the API description.
2. `security add-generic-password -s securizame-supabase -a "$USER" -w`
3. In `~/.config/securizame/config.json`:

   ```json
   {"connectors": {"supabase": {"secrets": {"SUPABASE_ACCESS_TOKEN": "keychain:securizame-supabase"}}}}
   ```

## Cloudflare (`cloudflare`)

Secret `CLOUDFLARE_API_TOKEN`, a user API token, sent as `Authorization: Bearer`. Base URL
`https://api.cloudflare.com/client/v4` ([API reference](https://developers.cloudflare.com/api/)).
Each login is one instance: `cloudflare` and, for more, `cloudflare:<label>` with its own token.

| Endpoint | Used for | Permission | Docs |
|---|---|---|---|
| `GET /user/tokens/verify` | The token is active (otherwise `reauth`); its id marks it `used_by_securizame` in the list | none | [verify token](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify/) |
| `GET /user/tokens` | User API tokens: `status`, `issued_on`, `modified_on`, `last_used_on`, `expires_on`, `condition` (client IP `in`/`not_in`), `policies` (effect, permission group names, resources) | User > API Tokens > Read | [list tokens](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/list/) |
| `GET /accounts` | Accounts the token reaches | none (lists what the token's account permissions cover) | [list accounts](https://developers.cloudflare.com/api/resources/accounts/methods/list/) |
| `GET /accounts/{id}` | `settings.enforce_twofactor` | Account > Account Settings > Read | [account details](https://developers.cloudflare.com/api/resources/accounts/methods/get/) |
| `GET /accounts/{id}/members` | Members: `status`, `roles`, `policies`, `user.two_factor_authentication_enabled` | Account > Account Settings > Read | [list members](https://developers.cloudflare.com/api/resources/accounts/subresources/members/methods/list/) |
| `GET /zones` | Zones and their account, up to `max_zones` | Zone > Zone > Read | [list zones](https://developers.cloudflare.com/api/resources/zones/methods/list/) |
| `GET /zones/{id}/settings/{ssl,always_use_https,min_tls_version}` | One setting each | Zone > Zone Settings > Read | [get zone setting](https://developers.cloudflare.com/api/resources/zones/subresources/settings/methods/get/) |
| `GET /zones/{id}/dnssec` | DNSSEC `status` | Zone > DNS > Read | [DNSSEC details](https://developers.cloudflare.com/api/resources/dns/subresources/dnssec/methods/get/) |

Endpoints, fields, permission groups and page sizes were checked against Cloudflare's OpenAPI
description ([cloudflare/api-schemas](https://github.com/cloudflare/api-schemas)) and the
[permissions reference](https://developers.cloudflare.com/fundamentals/api/reference/permissions/).
Listings ask for 50 per page, the maximum. Zone settings are read one by one because the bulk
`GET /zones/{id}/settings` is marked deprecated. `GET /memberships` is not used: `/accounts` gives
the same accounts without the extra Memberships Read permission. Moved zones are skipped. The token
response also has `token_prefix` and `token_suffix`; the connector does not read them.

The IP filter key is `request.ip` in the [token guide](https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/)
and `request_ip` in the API reference; both are read. A permission group counts as edit unless its
name ends in "Read" or "Read-Only", so an unnamed or unknown group is never taken for read-only.
A policy on `com.cloudflare.api.account.*` (all accounts) or `com.cloudflare.api.account.zone.*`
(all zones of every account) is broad; all zones of one named account is not.

| Situation | Kind | Severity |
|---|---|---|
| Active token that can edit all zones or all accounts | `credential` | high |
| Account without "Members 2FA enforcement" (`enforce_twofactor` false) | `setting` | high |
| Zone with SSL off | `setting` | high |
| Active token with edit permissions and no client IP `in` filter | `credential` | medium |
| Active token without expiry | `credential` | medium |
| Active token unused for more than 90 days, or never used 90 days after it was issued | `credential` | medium |
| More than one accepted super administrator ("Super Administrator - All Privileges", by role or policy) | `grant` | medium |
| Accepted member without two-factor authentication (low when the account enforces it) | `grant` | medium |
| Zone with Flexible SSL, or minimum TLS 1.0 or 1.1 | `setting` | medium |
| Zone with Full (not strict) SSL, Always Use HTTPS off, DNSSEC disabled or in error | `setting` | low |
| Global API Key: check by hand, the API cannot list it ([keys](https://developers.cloudflare.com/fundamentals/api/get-started/keys/)) | `credential` | info |
| Disabled or expired tokens, other members, accounts, zone settings | all | info |

Rate limits: Cloudflare allows 1200 requests per five minutes per user, shared with the dashboard
and every other token, and blocks all calls for five minutes after that
([limits](https://developers.cloudflare.com/fundamentals/api/reference/limits/)). The connector
starts at most one request every 300 ms (1000 per five minutes), four zones at a time, and stops
at the first HTTP 429 with an `error` status that says when to retry. A zone costs four requests,
so the default `max_zones` of 200 is about 800 requests and four minutes; a run over the cap logs
how many zones it skipped. A check Cloudflare answers with HTTP 403 is `noscope` on the account it
affects, counted once per check rather than once per zone. Without
Account Settings Read, `/accounts` returns an empty list rather than an error, so that gap shows
as missing account findings; `doctor` lists what the token can read.

Not covered: dangling DNS records (a CNAME or A record pointing at a deprovisioned host) need
resolution and ownership checks outside the Cloudflare API; account-owned API tokens
(`/accounts/{id}/tokens`), audit logs, WAF and Access settings.

Config, optional:

```json
{"connectors": {"cloudflare": {"config": {"max_zones": 200}}}}
```

Setup:

1. At <https://dash.cloudflare.com/profile/api-tokens>, Create Token > Create Custom Token, with
   only these permissions:
   - User > API Tokens > Read
   - Account > Account Settings > Read
   - Zone > Zone > Read
   - Zone > Zone Settings > Read
   - Zone > DNS > Read

   Account Resources: Include > All accounts. Zone Resources: Include > All zones. Set a TTL and,
   if you run securizame from a fixed address, Client IP Address Filtering. A read-only token on
   all zones is not flagged as broad; only edit permissions are.
2. `security add-generic-password -s securizame-cloudflare -a "$USER" -w` (paste the token at the prompt).
3. In `~/.config/securizame/config.json`:

   ```json
   {"connectors": {"cloudflare": {"secrets": {"CLOUDFLARE_API_TOKEN": "keychain:securizame-cloudflare"}}}}
   ```

   A second login: `"cloudflare:work": {"secrets": {"CLOUDFLARE_API_TOKEN": "keychain:securizame-cloudflare-work"}}`.

`securizame doctor --connector cloudflare` verifies the token, shows its expiry and reads one page
of tokens, accounts and zones, plus the settings and DNSSEC of the first zone, so a missing
permission shows with the group to add.
