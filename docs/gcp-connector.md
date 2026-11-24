# gcp connector

Built-in connector (`connectors/gcp`) that inventories Google Cloud through the installed `gcloud`
CLI. It uses no Google SDK and no extra Go module: every call is a read-only `gcloud` command with
`--format=json`, and `--account`/`--project` are passed on each call so gcloud config is never
changed.

```
segurata inventory gcp
```

## Configuration

Optional, in `~/.config/segurata/config.json`:

```json
{"connectors": {"gcp": {"config": {
  "accounts": ["me@example.com"],
  "projects": ["my-project"],
  "skip_projects": ["someone-elses-project"],
  "billing_project": "my-quota-project",
  "gcloud_path": "/path/to/gcloud"
}}}}
```

| Key | Default | Meaning |
|---|---|---|
| `accounts` | every account in `gcloud auth list` except service accounts (`*.iam.gserviceaccount.com`) | Accounts to inspect with; a service account listed here is used |
| `projects` | every active project each account can list | Restrict to these projects |
| `skip_projects` | none | Projects never inspected, for example ones you can see but do not own |
| `billing_project` | gcloud's own quota project | Passed as `--billing-project` to `billing budgets list`, for when the Budget API rejects the configured quota project (`USER_PROJECT_DENIED`) |
| `gcloud_path` | `PATH`, then the standard install folders: `~/google-cloud-sdk/bin/gcloud`, `/usr/lib/google-cloud-sdk/bin/gcloud`, `/opt/homebrew/share/google-cloud-sdk/bin/gcloud`, `/usr/local/share/google-cloud-sdk/bin/gcloud` | CLI path |

When the SDK lives elsewhere and only an interactive shell's rc file puts it on `PATH`, segurata
run from a script, cron or launchd does not find it and reports `unsupported`. Set `gcloud_path` to
the binary, for example for an SDK unpacked in `~/src/utils`:

```json
{"connectors": {"gcp": {"config": {"gcloud_path": "/Users/me/src/utils/google-cloud-sdk/bin/gcloud"}}}}
```

The path must be absolute (`~` is not expanded). Keep the file mode at `0600`.

A service account that `gcloud auth activate-service-account` added shows in `gcloud auth list`
next to people; it is a credential (its key on disk is a finding), not an identity to inventory
with, so it is skipped unless `accounts` names it. Projects in `skip_projects` are declared as
skipped scopes (docs/connectors.md, "Coverage"), so findings an earlier run made there are not
taken as resolved. So are the people's accounts `gcloud auth list` shows that `accounts` leaves
out (`segurata accounts unwatch gcp <account>` writes that list). Skipped service accounts are not
declared: no finding is scoped to one, and declaring them would mark every run partial.

Each account that lists projects also gets one info finding (`gcp_projects`) with the id and number
of every project it sees: attribution reads it to know the owner's projects, since an OAuth client
id names only the number (architecture.md, "Attribution").

Each project is inspected once, with the first account that lists it. A check that account is
denied is retried with the next account that lists the project, so a project another account can
read is not reported as denied; the status names every account it tried and is scoped to the
project. Findings keep the project's first account whichever account read them, so their ids do
not change with who answered. Up to 4 projects run in
parallel, each command has a 90 s timeout, and rate-limit answers (HTTP 429, `RESOURCE_EXHAUSTED`)
are retried twice with backoff. Cloud Billing returns 429 with much more parallelism than that.

## What it checks

| Check | Command | Finding |
|---|---|---|
| API keys | `gcloud services api-keys list --project=P` | No API restriction (`restrictions.apiTargets`) or no application restriction (browser, server, Android, iOS): **high**. Restricted keys: info. Shows `displayName`, redacted `uid` and `createTime`. The key string is never fetched. |
| Service account keys | `gcloud iam service-accounts list --project=P`, then `gcloud iam service-accounts keys list --iam-account=SA --managed-by=user` | Each user-managed key: **medium**; `validAfterTime` older than 90 days: **high**; disabled key: low. |
| Broad roles | `gcloud projects get-iam-policy P` | Service account with `roles/owner` or `roles/editor`: **high**. Google service agents (`service-NUMBER@…`, `@gcp-sa-*`, `@cloudservices.gserviceaccount.com`) are skipped; the default Compute Engine and App Engine accounts are not, because Google advises removing Editor from them. |
| Billing budgets | `gcloud billing accounts list`, `gcloud billing projects describe P`, `gcloud billing budgets list --billing-account=ID` | Billing account (open, or paying for a project seen) with no budget that alerts: **high** (`spend`). If it has some, each linked project no alerting budget covers: **high**. A budget alerts when it has `thresholdRules` and someone receives them (default IAM recipients not disabled, or a Pub/Sub topic or monitoring channel). A budget without `budgetFilter.projects` covers the whole account. Budgets that cannot be read become a status naming the projects whose alerts are unknown. |
| Local credentials (`exposure`) | Reads files only | See below. |

### Local credentials

- `application_default_credentials.json` in the gcloud config folder (`CLOUDSDK_CONFIG`, else
  `~/.config/gcloud`, `%APPDATA%\gcloud` on Windows): type, `account`, `quota_project_id`, client id,
  file mode and modification time.
  - `authorized_user`: **medium**, a refresh token any local program can use. The scopes are not in
    the file, and learning them would mean exchanging the refresh token, which the connector does
    not do. When the client id is gcloud's default ADC client
    (`764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur…`, defined in
    `googlecloudsdk/api_lib/auth/util.py`), the grant shows up in the Google account's linked apps as
    "Google Auth Library", where its scopes can be read.
  - `service_account`: **high**, a private key on disk.
- The file named by `GOOGLE_APPLICATION_CREDENTIALS`, judged the same way.
- Any service-account key JSON under the gcloud config folder (skipping `virtenv`, `logs`, `cache`):
  **high**. `gcloud auth activate-service-account --key-file` leaves a copy in
  `legacy_credentials/<sa>/adc.json`.
- Any of these readable by group or others: raised to **high** with a `chmod 600` hint.

Only non-secret fields are decoded: `private_key`, `refresh_token` and `client_secret` are not even
parsed.

### ADC with broad scopes

A typical case: an `authorized_user` ADC created with full Drive, Sheets and Cloud scopes for one
script. Remediation:

1. See the scopes at <https://myaccount.google.com/connections> ("Google Auth Library").
2. Revoke there, or with `gcloud auth application-default revoke`.
3. Log in again with only what the script needs, for example:

   ```
   gcloud auth application-default login --client-id-file=client.json \
     --scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/spreadsheets,https://www.googleapis.com/auth/drive.file
   ```

   gcloud requires `cloud-platform` in `--scopes`, and scopes outside Google Cloud (Drive, Sheets)
   need your own OAuth client passed with `--client-id-file`. `drive.file` only reaches files the
   app created or the user opened with it; `spreadsheets` reaches every spreadsheet.

## Safety

- An allowlist in `gcloud.go` (a `cli.Allowlist` from `connectors/internal/cli`, shared with `aws`
  and `azure`) refuses any command outside the nine read-only paths above before it reaches the
  CLI. `get-key-string`, `keys create`, `config set`, `auth revoke`, any `delete` or
  `disable` cannot run. A test checks it.
- `CLOUDSDK_CORE_DISABLE_PROMPTS=1` on every call, so an expired login becomes a `reauth` status
  instead of a hung prompt.
- Failures are statuses, never crashes: `reauth` for expired logins, `error` with a short reason
  (permission denied, API not enabled, rate limited). Per-project permission failures are folded
  into one line per project.

## Not done

Spend-risk APIs without quota caps (item 5 of the plan). It needs `gcloud services list` per
project plus each API's consumer quota overrides through the Service Usage API, many calls per
project for a weak signal, so it was left out.

Last use of service account keys is not reported (`last_used_at` stays null): it lives in Policy
Intelligence activity analysis, a separate API.

## References

- gcloud reference and wide flags (`--account`, `--project`, `--billing-project`, `--format`): <https://cloud.google.com/sdk/gcloud/reference>
- `gcloud projects list`: <https://cloud.google.com/sdk/gcloud/reference/projects/list>
- `gcloud services api-keys list`: <https://cloud.google.com/sdk/gcloud/reference/services/api-keys/list>
- API Keys resource (`restrictions`, `apiTargets`, `uid`, `keyString`): <https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys>
- API key best practices: <https://cloud.google.com/docs/authentication/api-keys>
- `gcloud iam service-accounts list`: <https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/list>
- `gcloud iam service-accounts keys list`: <https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/keys/list>
- Service account key best practices: <https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys>
- Service accounts and service agents: <https://cloud.google.com/iam/docs/service-account-overview>
- Basic roles: <https://cloud.google.com/iam/docs/understanding-roles>
- `gcloud projects get-iam-policy`: <https://cloud.google.com/sdk/gcloud/reference/projects/get-iam-policy>
- `gcloud billing accounts list`: <https://cloud.google.com/sdk/gcloud/reference/billing/accounts/list>
- `gcloud billing projects describe`: <https://cloud.google.com/sdk/gcloud/reference/billing/projects/describe>
- `gcloud billing budgets list`: <https://cloud.google.com/sdk/gcloud/reference/billing/budgets/list>
- Budget resource (`thresholdRules`, `notificationsRule`, `budgetFilter.projects`): <https://cloud.google.com/billing/docs/reference/budget/rest/v1/billingAccounts.budgets>
- Budgets and alerts: <https://cloud.google.com/billing/docs/how-to/budgets>
- Application Default Credentials: <https://cloud.google.com/docs/authentication/application-default-credentials>
- `gcloud auth application-default login`: <https://cloud.google.com/sdk/gcloud/reference/auth/application-default/login>
- `gcloud auth application-default revoke`: <https://cloud.google.com/sdk/gcloud/reference/auth/application-default/revoke>
- OAuth scopes: <https://developers.google.com/identity/protocols/oauth2/scopes>, Drive: <https://developers.google.com/workspace/drive/api/guides/api-specific-auth>, Sheets: <https://developers.google.com/workspace/sheets/api/scopes>
- Linked apps in a Google account: <https://support.google.com/accounts/answer/13533235>
