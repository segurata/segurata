# gcp connector

Built-in connector (`connectors/gcp`) that inventories Google Cloud through the installed `gcloud`
CLI. It uses no Google SDK and no extra Go module: every call is a read-only `gcloud` command with
`--format=json`, or a GET to a Google REST API with the token `gcloud auth print-access-token`
prints, and `--account`/`--project` are passed on each call so gcloud config is never changed.
It writes only through `segurata remediate --apply`, after you confirmed the plan (see
[Remediation](#remediation)).

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
  "gcloud_path": "/path/to/gcloud",
  "quota_caps": {"geocoding-backend.googleapis.com": 4000},
  "budget_amount": {"default": 50, "000000-AAAAAA-111111": 200}
}}}}
```

Every key is optional. A malformed value stops the run with an error naming the key, as the
[configuration guide](user-guide.md#configuration-and-output) says; `accounts` and `projects` cannot be empty lists, while an
empty `skip_projects` skips nothing.

| Key | Default | Meaning |
|---|---|---|
| `accounts` | every account in `gcloud auth list` except service accounts (`*.iam.gserviceaccount.com`) | Accounts to inspect with; a service account listed here is used |
| `projects` | every active project each account can list | Restrict to these projects |
| `skip_projects` | none | Projects never inspected, for example ones you can see but do not own |
| `billing_project` | gcloud's own quota project | Passed as `--billing-project` to every `billing budgets` command, for when the Budget API rejects the configured quota project (`USER_PROJECT_DENIED`), and as `X-Goog-User-Project` on the REST reads (else the project read) |
| `quota_caps` | none | Requests per day `gcp.quota.cap` sets for each API (service name to a whole number); an API not named here is never capped |
| `budget_amount` | none | Monthly amount, in the billing account's currency, of the budget `gcp.budget.create` creates: a map of billing account id to amount with an optional `default`, or one number for every account; without it the plan is refused |
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
| API key usage | Cloud Monitoring `projects.timeSeries.list`, see below | Each key finding says "Used APIs (30 days): a, b", or that no API was called with the key in 30 days (a candidate for deletion). A key without API restriction that called some API offers `gcp.apikey.restrict`. |
| Service account keys | `gcloud iam service-accounts list --project=P`, then `gcloud iam service-accounts keys list --iam-account=SA --managed-by=user` | Each user-managed key: **medium**; `validAfterTime` older than 90 days: **high**; disabled key: low. |
| Broad roles | `gcloud projects get-iam-policy P` | Service account with `roles/owner` or `roles/editor`: **high**. Google service agents (`service-NUMBER@…`, `@gcp-sa-*`, `@cloudservices.gserviceaccount.com`) are skipped; the default Compute Engine and App Engine accounts are not, because Google advises removing Editor from them. |
| Request caps | `gcloud services list --enabled --project=P`, then Cloud Quotas, see below | A pay-per-use API whose per-day request quota has no cap of the project's own: **medium**, with `gcp.quota.cap`. Only a per-minute quota: **medium**, advice only. Capped: info. |
| Billing budgets | `gcloud billing accounts list`, `gcloud billing projects describe P`, `gcloud billing budgets list --billing-account=ID` | Judged per billing account (open, or paying for a project seen) with the shared budget rules: docs/connectors.md, "Spend and budgets". See below for how a Budget API budget is read. Budgets that cannot be read become a status naming the projects whose alerts are unknown. |
| Local credentials (`exposure`) | Reads files only | See below. |

### API key usage

For each key the connector reads 30 days of
[`serviceruntime.googleapis.com/api/request_count`](https://docs.cloud.google.com/apis/docs/monitoring)
from Cloud Monitoring (`GET https://monitoring.googleapis.com/v3/projects/P/timeSeries`, `view=HEADERS`,
so only the series and no data points), filtered on the `consumed_api` resource label
`credential_id` set to `apikey:` and the key's `uid`, the filter Google's
[API key management codelab](https://codelabs.developers.google.com/api-key-management) uses, and
collects the series' `resource.labels.service`. No request count is kept: the finding names the
services only.

- The token comes from `gcloud auth print-access-token --account=A`, once per account and run. It
  stays in memory: it is never logged, written or put in an error, and tests check that it appears
  in no finding, status, plan or check.
- Requests carry `X-Goog-User-Project` with `billing_project` when set, else the project read:
  gcloud's own OAuth client has no quota for these APIs, as `gcloud auth print-access-token` warns.
  The Cloud Monitoring API must be enabled there.
- A failure (API not enabled, permission denied) is a status scoped `usage:<project>`. The key
  findings stay checked and say the usage is unknown; without usage no key offers the action.

### Request caps of pay-per-use APIs

A quota is the most an API can bill: Google's Maps Platform
[cost guide](https://developers.google.com/maps/billing-and-pricing/manage-costs) calls lowering the
per-day quota the hard cap on usage, and a budget only alerts. The connector reads the caps of the
enabled APIs in a short list of pay-per-use ones (`costServices` in `quotas.go`):

| API | Service |
|---|---|
| Places API (New) | `places.googleapis.com` |
| Geocoding API | `geocoding-backend.googleapis.com` |
| Directions API | `directions-backend.googleapis.com` |
| Maps Static API | `static-maps-backend.googleapis.com` |
| Maps JavaScript API | `maps-backend.googleapis.com` |
| Routes API | `routes.googleapis.com` |
| Gemini API | `generativelanguage.googleapis.com` |
| Vertex AI | `aiplatform.googleapis.com` |
| Cloud Translation | `translate.googleapis.com` |
| Cloud Vision | `vision.googleapis.com` |
| Speech-to-Text | `speech.googleapis.com` |
| Text-to-Speech | `texttospeech.googleapis.com` |
| Document AI | `documentai.googleapis.com` |

The Maps service names are those each API's "Set up in the Cloud console" page enables.

It uses the [Cloud Quotas API](https://docs.cloud.google.com/docs/quotas/api-overview) v1, not
Service Usage's `consumerQuotaMetrics`: Cloud Quotas is a v1 API with GA `gcloud quotas` commands,
while Service Usage serves quota limits and overrides only in `v1beta1`.

- `GET https://cloudquotas.googleapis.com/v1/projects/N/locations/global/quotaPreferences`, once per
  project, and `…/services/S/quotaInfos` per API, every page.
- A request quota is a `QuotaInfo` that is not `isConcurrent` or `isFixed` and whose `quotaId` or
  `metric` says `request`; its limit is `dimensionsInfos[].details.value` of the entry without
  dimensions (`-1` is unlimited). Per-day quotas (`refreshInterval` `day`) are judged; per-minute
  ones only when the API has none per day.
- Capped means a dimensionless `QuotaPreference` of the project for that quota with a
  `preferredValue` other than `-1` and no `traceId`: Google sets a trace id only on increase
  requests, so a preference that raised the limit is not a cap.
- A failure is a status scoped `quotas:<project>`, where the quota findings live, so the project's
  other findings stay checked.

### Billing budgets

Each budget from the [Budget API v1](https://cloud.google.com/billing/docs/reference/budget/rest/v1/billingAccounts.budgets)
is mapped to the shared model:

- Amount: `amount.specifiedAmount` (`units` plus `nanos`), its `currencyCode` or else the billing
  account's `currencyCode`; `amount.lastPeriodAmount` means last period's spend.
- Period: `budgetFilter.calendarPeriod` (`MONTH` when unset, as the API defaults), or custom when
  `budgetFilter.customPeriod` is set.
- Thresholds: `thresholdRules[].thresholdPercent` (1.0 is 100%), forecasted when `spendBasis` is
  `FORECASTED_SPEND` (the API defaults to `CURRENT_SPEND`).
- Scope: `budgetFilter.projects` (project numbers, named by id for every project the run saw); no
  project filter covers every project on the account. `services`, `subaccounts`, `labels` and
  `resourceAncestors` narrow what is counted but are not matched to projects.
- Channels: the billing account's admins unless `notificationsRule.disableDefaultIamRecipients`,
  project owners with `enableProjectLevelRecipients` on a one-project budget,
  `monitoringNotificationChannels`, and `pubsubTopic`.
- Actions: `notificationsRule.pubsubTopic`, the hook Google's
  [Disable billing usage with notifications](https://cloud.google.com/billing/docs/how-to/disable-billing-with-notifications)
  guide connects to a function that removes billing from the project; and a `spendCap` that is
  configured or enforced.
- Risks per project: API keys with no API or application restriction (the high API key findings)
  and enabled user-managed service account keys found in the same run.

Remediations point to `https://console.cloud.google.com/billing/<id>/budgets`; a billing account
without a budget with alerts offers `gcp.budget.create`, and a budget without a threshold at 100% of
actual or of forecasted spend offers `gcp.budget.alerts`. Google creates a budget on its own when
Maps Platform is set up, which is how identical copies of one budget appear; the duplicate rule
names them.

### Budgets alert, they do not stop spend

A budget sends email (and Pub/Sub or Monitoring notifications when wired) as spend crosses its
thresholds; spending goes on. Google's [budgets page](https://cloud.google.com/billing/docs/how-to/budgets)
puts it as "the budget doesn't automatically set a hard cap on spending", and every plan that
creates or edits one says so. A budget spend cap, for the services Google offers one on, is read as
an action by the enforcement rule. Beyond that, two things stop spend:

- A request cap on each pay-per-use API ([request caps](#request-caps-of-pay-per-use-apis),
  `gcp.quota.cap`): the API refuses requests over the cap for the rest of the day.
- A budget that publishes its notifications to a Pub/Sub topic, wired to code that removes billing
  from the project when the budget is exceeded, as Google's
  [Disable billing usage with notifications](https://cloud.google.com/billing/docs/how-to/disable-billing-with-notifications)
  guide builds with a Cloud Run function. Removing billing shuts down every service of the project
  and some resources may not come back, so try it on a test project first. segurata reports whether a
  budget has a topic (the enforcement rule) but never deploys the function.

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
- Any of these readable by other accounts: raised to **high** with the command that makes the file
  private. On Unix that is group or others and `chmod 600`. On Windows it is any account other than
  you, SYSTEM and Administrators, read from the access list, and the command is a Windows
  PowerShell `Set-Acl` that leaves full control to you and SYSTEM only.

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

## Remediation

```
segurata remediate <finding-id>            the plan, read from the live state; changes nothing
segurata remediate <finding-id> --apply    the same plan, confirmed, then applied and checked
```

Every plan is built from a fresh read with the read-only commands above, never from the finding,
and runs as the finding's account (`--account=A`). After the confirmation the core plans again and
refuses a plan that changed since it was shown. The commands a confirmed plan runs are its whole
allowlist (`connector.Allowlist`, exact argument lists): nothing else can run.

| Action | Finding | What it runs | Undo |
|---|---|---|---|
| `gcp.apikey.restrict` | API key without API restriction that called some API in 30 days | `gcloud services api-keys update <key id> --location=<location> --project=P --api-target=service=<svc>` for each service it called, `--account=A` | In the console (see below) |
| `gcp.budget.create` | Billing account without a budget with alerts | `gcloud billing budgets create --billing-account=ID --display-name="segurata: all projects" --budget-amount=<budget_amount> --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1.0 --threshold-rule=percent=1.0,basis=forecasted-spend --account=A [--billing-project=Q] --format=value(name)` | `gcloud billing budgets delete billingAccounts/ID/budgets/<new id> --account=A`, printed with the id once the budget exists |
| `gcp.budget.alerts` | Budget without a threshold at 100% of actual spend, or of forecasted spend | `gcloud billing budgets update billingAccounts/ID/budgets/B --add-threshold-rule=percent=0.9` (when no actual threshold reaches 90%) `--add-threshold-rule=percent=1.0` (when none reaches 100%) `--add-threshold-rule=percent=1.0,basis=forecasted-spend` (when none is forecasted) `--account=A` | `gcloud billing budgets update billingAccounts/ID/budgets/B --clear-threshold-rules --add-threshold-rule=…` with the budget's thresholds before |
| `gcp.quota.cap` | Pay-per-use API without a per-day request cap | Per uncapped per-day request quota: `gcloud quotas preferences create --service=S --quota-id=Q --preferred-value=<quota_caps[S]> --project=P --preference-id=segurata-<quota id> --allow-high-percentage-quota-decrease --account=A`, or `gcloud quotas preferences update <id> …` with the same flags when the project already has a preference for it | `gcloud quotas preferences update <id> --service=S --quota-id=Q --preferred-value=<the limit before> --project=P --account=A` |

`gcp.apikey.restrict`:

- Refused when Cloud Monitoring cannot be read, or when the key called nothing in 30 days (nothing
  to restrict it to; delete the key instead once you are sure nothing uses it), or when the key
  already has API targets.
- gcloud sends only the API targets in its update mask, so the key's application restriction
  (referrers, IP addresses, Android or iOS apps) stays as it is. Those cannot be read from usage:
  add them by hand. gcloud also checks the key's last 7 days of traffic first
  (`--check-existing-usage`, on by default) and refuses a change that traffic would break.
- An API the key last called more than 30 days ago is left out.
- No gcloud command undoes it: `gcloud services api-keys update` refuses to leave a key without
  API targets ("API keys must have API target restrictions"), and the current reference documents no
  `--clear-restrictions`. The plan says so and names the console page where "Don't restrict key"
  removes the API restriction.

`gcp.quota.cap`:

- The amount comes from `quota_caps` only. Without an entry for the API the plan is refused and
  names the key to set; segurata never guesses an amount.
- A quota whose limit is already at or below the cap is left out and named; when none is left the
  plan is refused.
- `--allow-high-percentage-quota-decrease` is there because any real cap lowers a default by more
  than 10%. `--allow-quota-decrease-below-usage` is not: Google refuses a cap below today's usage.
- Cloud Quotas cannot delete a quota preference, so the undo sets it back to the limit it had,
  which Google treats as an increase: it may ask for `--email` and take time to approve.

`gcp.budget.create` and `gcp.budget.alerts`:

- The amount comes from `budget_amount` only; without it the plan is refused and names the key.
  `--budget-amount` carries no currency, so Google uses the billing account's.
- The budget covers every project on the account (no `--filter-projects`), monthly (the API's
  default period), and alerts the billing account's administrators and users (the default
  recipients).
- `gcp.budget.create` is refused when a budget with alerts exists by the time it is planned. The id
  of a budget is Google's, so the undo shown before applying holds `NEW_BUDGET_ID`, and the apply
  prints the exact `delete` from the name `--format=value(name)` returns.
- `gcp.budget.alerts` adds rules to the existing ones (gcloud reads the budget's rules and appends);
  amount, scope and recipients stay. The undo clears the rules and puts back the ones read before.
- Percentages are 1.0-based (`1.0` is 100%) in both commands. The `update` reference says
  `--add-threshold-rule`'s percent is an "Integer between 0 and 100", but gcloud passes it unchanged
  into `thresholdPercent`, which the Budget API documents as 1.0-based (checked in the SDK's
  `surface/billing/budgets/update.yaml` and `command_lib/billingbudgets/hooks.py`, gcloud 594): a
  value of 100 would mean 10000%.

### Permissions

The usage and quota reads and the remediations need these, and `segurata doctor` asks
`testIamPermissions` (a POST that changes nothing) which of them each account holds on the first
project it lists, and the budget ones on the first open billing account, and warns about the missing
ones with the predefined role that grants each:

| Permission | Role | For |
|---|---|---|
| `monitoring.timeSeries.list` | `roles/monitoring.viewer` | Reading API key usage |
| `serviceusage.services.list` | `roles/serviceusage.serviceUsageViewer` | Listing enabled pay-per-use APIs |
| `cloudquotas.quotas.get` | `roles/cloudquotas.viewer` | Reading request quotas and preferences |
| `apikeys.keys.update` | `roles/serviceusage.apiKeysAdmin` | `gcp.apikey.restrict` |
| `cloudquotas.quotas.update` | `roles/cloudquotas.admin` | `gcp.quota.cap` |
| `billing.budgets.create` | `roles/billing.costsManager` | `gcp.budget.create` |
| `billing.budgets.update` | `roles/billing.costsManager` | `gcp.budget.alerts` |
| `billing.budgets.delete` | `roles/billing.costsManager` | Undoing `gcp.budget.create` |

## Safety

- An allowlist in `gcloud.go` (a `cli.Allowlist` from `connectors/internal/cli`, shared with `aws`
  and `azure`) refuses any command outside the read-only paths above (and `auth list`,
  `auth print-access-token`) before it reaches the CLI. `get-key-string`, `keys create`,
  `config set`, `auth revoke`, any `update`, `create`, `delete` or `disable` cannot run on that
  path. The remediation writes are not on it: they run only as the exact steps of a confirmed
  plan, and a test checks that the inventory path refuses each of them.
- `CLOUDSDK_CORE_DISABLE_PROMPTS=1` on every call, so an expired login becomes a `reauth` status
  instead of a hung prompt.
- Failures are statuses, never crashes: `reauth` for expired logins, `error` with a short reason
  (permission denied, API not enabled, rate limited). Per-project permission failures are folded
  into one line per project.

## Not done

Posture checks beyond the ones above (public buckets, firewall rules, Cloud SQL flags, logging,
KMS) come from Prowler through the external connector in
[plugins/prowler](../plugins/prowler/README.md), which leaves out the checks this connector makes.

Last use of service account keys is not reported (`last_used_at` stays null): it lives in Policy
Intelligence activity analysis, a separate API.

## References

- gcloud reference and wide flags (`--account`, `--project`, `--billing-project`, `--format`): <https://cloud.google.com/sdk/gcloud/reference>
- `gcloud auth print-access-token` (and the `X-Goog-User-Project` note): <https://docs.cloud.google.com/sdk/gcloud/reference/auth/print-access-token>
- `gcloud services api-keys update` (`--api-target`, `--append`, `--check-existing-usage`): <https://docs.cloud.google.com/sdk/gcloud/reference/services/api-keys/update>
- API metrics (`api/request_count`): <https://docs.cloud.google.com/apis/docs/monitoring>
- `consumed_api` resource and its `credential_id` label: <https://docs.cloud.google.com/monitoring/api/resources>
- Filtering usage on `credential_id="apikey:<uid>"`: <https://codelabs.developers.google.com/api-key-management>
- `projects.timeSeries.list` (`filter`, `interval`, `view`, `pageToken`): <https://docs.cloud.google.com/monitoring/api/ref_v3/rest/v3/projects.timeSeries/list>
- `projects.testIamPermissions`: <https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/testIamPermissions>
- `gcloud services list`: <https://docs.cloud.google.com/sdk/gcloud/reference/services/list>
- Cloud Quotas API overview (no delete of a `QuotaPreference`, decreases): <https://docs.cloud.google.com/docs/quotas/api-overview>
- `QuotaInfo` (`refreshInterval`, `dimensionsInfos[].details.value`): <https://docs.cloud.google.com/docs/quotas/reference/rest/v1/projects.locations.services.quotaInfos>
- `QuotaPreference` (`quotaConfig.preferredValue`, `traceId`): <https://docs.cloud.google.com/docs/quotas/reference/rest/v1/projects.locations.quotaPreferences>
- `gcloud quotas preferences create`: <https://docs.cloud.google.com/sdk/gcloud/reference/quotas/preferences/create>
- `gcloud quotas preferences update`: <https://docs.cloud.google.com/sdk/gcloud/reference/quotas/preferences/update>
- Service Usage `consumerQuotaMetrics` (v1beta1): <https://docs.cloud.google.com/service-usage/docs/reference/rest/v1beta1/services.consumerQuotaMetrics>
- Maps Platform cost control with quotas: <https://developers.google.com/maps/billing-and-pricing/manage-costs>
- Maps service names: <https://developers.google.com/maps/documentation/geocoding/cloud-setup>, <https://developers.google.com/maps/documentation/directions/cloud-setup>, <https://developers.google.com/maps/documentation/maps-static/cloud-setup>, <https://developers.google.com/maps/documentation/javascript/cloud-setup>, <https://developers.google.com/maps/documentation/places/web-service/cloud-setup>, <https://developers.google.com/maps/documentation/routes/cloud-setup>
- Predefined roles and their permissions: <https://docs.cloud.google.com/iam/docs/roles-permissions>
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
- `gcloud billing budgets create` (`--threshold-rule`, `--budget-amount` currency): <https://docs.cloud.google.com/sdk/gcloud/reference/billing/budgets/create>
- `gcloud billing budgets update` (`--add-threshold-rule`, `--clear-threshold-rules`): <https://docs.cloud.google.com/sdk/gcloud/reference/billing/budgets/update>
- `gcloud billing budgets delete`: <https://docs.cloud.google.com/sdk/gcloud/reference/billing/budgets/delete>
- `billingAccounts.testIamPermissions`: <https://docs.cloud.google.com/billing/docs/reference/rest/v1/billingAccounts/testIamPermissions>
- Budget resource (`amount`, `thresholdRules[].spendBasis`, `notificationsRule`, `budgetFilter`, `spendCap`): <https://cloud.google.com/billing/docs/reference/budget/rest/v1/billingAccounts.budgets>
- Disable billing usage with notifications: <https://cloud.google.com/billing/docs/how-to/disable-billing-with-notifications>
- Budgets and alerts: <https://cloud.google.com/billing/docs/how-to/budgets>
- Application Default Credentials: <https://cloud.google.com/docs/authentication/application-default-credentials>
- `gcloud auth application-default login`: <https://cloud.google.com/sdk/gcloud/reference/auth/application-default/login>
- `gcloud auth application-default revoke`: <https://cloud.google.com/sdk/gcloud/reference/auth/application-default/revoke>
- OAuth scopes: <https://developers.google.com/identity/protocols/oauth2/scopes>, Drive: <https://developers.google.com/workspace/drive/api/guides/api-specific-auth>, Sheets: <https://developers.google.com/workspace/sheets/api/scopes>
- Linked apps in a Google account: <https://support.google.com/accounts/answer/13533235>
