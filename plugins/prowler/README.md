# segurata-prowler

An external segurata connector in Python 3 (standard library only) that runs
[Prowler](https://github.com/prowler-cloud/prowler) (Apache-2.0) against Google Cloud and reports its
failed checks as segurata findings. Prowler 5.51.0 has 117 GCP checks (Cloud Storage, Cloud SQL,
Compute, IAM, KMS, logging, DNS, BigQuery, GKE, Vertex AI and others); this connector wraps them
instead of rewriting them in segurata. Failures of hygiene checks are weighted by what each project
runs (see [Relevance](#relevance)), so CIS logging alerts missing in forty idle projects sit below
a firewall open to the internet. It speaks protocol 1 of the external protocol
([docs/connectors.md](../../docs/connectors.md)) and only inventories: Prowler reads, nothing is
changed.

Only the `gcp` provider is implemented. `aws`, `azure` and `kubernetes` are accepted in the config
and reported as `unsupported` until they are.

## Install

### Prowler

Pin the exact version this connector was checked against, published more than four days ago, and
install it in its own environment. Prowler 5.51.0 (uploaded to PyPI on 2026-11-19) needs Python
3.10 to 3.13:

```bash
pipx install --python python3.13 \
  --pip-args="--only-binary=:all: --exclude-newer=$(date -u -v-4d +%Y-%m-%dT00:00:00Z)" \
  prowler==5.51.0
```

(`date -d '4 days ago'` on Linux. pipx 1.12 installs through uv, so `--exclude-newer` is uv's flag
and applies the quarantine to every dependency, not only to Prowler.) Never `--upgrade` to the
latest version: move the pin after checking the release's upload date at
<https://pypi.org/pypi/prowler/json> and re-running the tests.

**Known blocker under a wheels-only policy.** Prowler 5.51.0 depends on packages published only
as source distributions: `alibabacloud-gateway-oss-util` 0.0.3, `shodan` 1.31.0, `polling` 0.3.2
and nine other `alibabacloud-*` packages (`alibabacloud-tea`, `-tea-xml`, `-endpoint-util`,
`-oss-util`, `-darabonba-string`, `-darabonba-signature-util`, `-darabonba-map`,
`-darabonba-array`, `-darabonba-time`). With `only-binary = :all:` the install fails at
resolution. Building those packages runs their `setup.py`, which the policy exists to avoid.
Possible ways through, each a decision for the owner:

1. Read the twelve sdists, then install once without `--only-binary`, keeping `--exclude-newer`
   and the exact Prowler pin.
2. Run the official image pinned by digest (`docker pull prowlercloud/prowler:5.51.0`) and point
   `prowler_path` at a wrapper script that runs it with the token in its environment and the
   output folder mounted.

### The connector

segurata finds external connectors on `PATH`:

```bash
ln -s "$PWD/plugins/prowler/segurata-prowler" ~/.local/bin/segurata-prowler   # any directory on PATH
segurata connectors | grep prowler                                             # describe loaded
segurata doctor -connector prowler                                             # prowler and gcloud found
```

## Authentication

Prowler's GCP provider reads `CLOUDSDK_AUTH_ACCESS_TOKEN` before it falls back to Application
Default Credentials (`setup_session` in `prowler/providers/gcp/gcp_provider.py`). For each project
the connector asks gcloud for a short-lived token of the account that lists the project:

```
gcloud auth print-access-token --account=<account>
```

and starts Prowler with that token in its environment, `GOOGLE_APPLICATION_CREDENTIALS` removed,
and `GOOGLE_CLOUD_PROJECT` set to the project. So:

- ADC (`~/.config/gcloud/application_default_credentials.json`) is never read, replaced or
  refreshed; another tool can keep using it.
- No service-account key is created, no login is started, gcloud config is not changed
  (`--account` is passed on every call, with `CLOUDSDK_CORE_DISABLE_PROMPTS=1`).
- The token lives only in the connector's memory and Prowler's environment. Every record the
  connector writes is scrubbed of it, and of anything shaped like a Google access token
  (`ya29.…`).
- A gcloud token lasts an hour and Prowler cannot refresh one. Each project gets a fresh token,
  so only a single project taking longer than that fails; keep `timeout` under 3300 s.

Accounts gcloud has no credentials for are reported as `missing_credentials` with the
`gcloud auth login <account>` to run; expired logins as `reauth`.

## Configuration

In `~/.config/segurata/config.json`; every key is optional:

```json
"prowler": {
  "config": {
    "providers": ["gcp"],
    "accounts": ["me@example.com", "work@example.org"],
    "projects": ["my-project", "other-project"],
    "skip_projects": ["someone-elses-project"],
    "checks": [],
    "excluded_checks": ["compute_instance_preemptible_vm_disabled"],
    "severity_min": "low",
    "include_overlaps": false,
    "prowler_path": "/Users/me/.local/bin/prowler",
    "timeout": 1800,
    "parallel": 1,
    "relevance": true,
    "relevance_overrides": {"iam_cloud_asset_inventory_enabled": "keep", "kms_key_rotation_enabled": "info"},
    "not_applicable": [
      {"check": "iam_account_access_approval_enabled", "where": "no_organization",
       "reason": "Access Approval needs Access Transparency enabled for the project's organization, and this project has none"}
    ]
  }
}
```

| Key | Default | Meaning |
|---|---|---|
| `providers` | `["gcp"]` | Prowler providers to run; only `gcp` is implemented |
| `accounts` | every account in `gcloud auth list` except service accounts | Accounts to scan as. People left out are declared as skipped scopes |
| `projects` | every active project the accounts list | Restrict to these projects |
| `skip_projects` | none | Project ids or shell patterns (`sys-*` skips Apps Script's default projects). Never scanned; declared as skipped scopes so earlier findings there are not taken as resolved |
| `checks` | all | Only these Prowler check ids (`prowler gcp --list-checks`) |
| `excluded_checks` | none | Never run these |
| `severity_min` | none | `info`, `low`, `medium`, `high` or `critical`: Prowler runs only checks at or above it |
| `include_overlaps` | `false` | Also run and report the checks segurata's `gcp` connector makes (table below) |
| `prowler_path`, `gcloud_path` | `PATH` (and the SDK folders for gcloud) | Absolute paths to the CLIs |
| `timeout` | 1800 | Seconds one project may take. The whole run is bounded apart: 12 hours unless the instance sets `timeout` next to `config` (`"prowler": {"timeout": "20h", "config": {…}}`) |
| `parallel` | 1 | Projects scanned at once; Prowler is already multi-threaded inside a run |
| `relevance` | `true` | Weigh hygiene checks by the project's profile ([Relevance](#relevance)). With `false` the profile is still read and recorded |
| `relevance_overrides` | none | Check id to `keep` (never adjusted by the profile) or `info` (info in every project) |
| `not_applicable` | Access Approval outside an organization | Failures reported as `info` with the reason. A configured list replaces the default; `[]` turns it off |

Each project is scanned once, with the first account that lists it. When Prowler is denied, the
next account that lists the project is tried; findings keep the first account either way, so their
ids do not depend on who answered.

## What it runs

Per project, in a fresh 0700 temporary folder deleted afterwards:

```
prowler gcp --project-id P --output-formats json-ocsf --output-directory D --output-filename prowler \
  --log-level ERROR --log-file D/prowler.log --no-banner --no-color --ignore-exit-code-3 \
  [--checks …] [--excluded-checks …] [--severity …]
```

No HTML or CSV report is asked for. The connector reads `D/prowler.ocsf.json` (OCSF Detection
Findings) and `D/prowler.log`.

Then, as the account Prowler ran as, it reads the project's [profile](#activity-profile) with
gcloud. The connector runs only the gcloud commands in its `READ_COMMANDS` allowlist (auth list,
print-access-token, projects list, services list, billing projects describe and the six resource
lists in [Activity profile](#activity-profile)); any other command is refused before gcloud starts.

## What it reports

One finding per **FAIL** result and resource. PASS, MANUAL and muted results, overlaps and
results below `severity_min` are counted in the project's `ok` status, for example
`12 FAIL, 80 PASS, 0 MANUAL; 0 muted, 3 already checked by gcp, 0 below severity_min; profile
production: 31 non-default services, 2 compute instances, 3 buckets, billing on; 0 lowered by
relevance, 0 not applicable; APIs disabled (nothing to check there): dataproc, notebooks`.

| Field | From |
|---|---|
| `account` | The gcloud account that lists the project first |
| `scope` | The project id |
| `resource` | `type` `prowler_check`, `id` `<check id>:<project>:<resource uid>`, `name` the resource name |
| `kind` | `exposure` when the check's categories include `internet-exposed`, `credential` for `secrets`, `setting` otherwise |
| `severity` | Prowler's (critical, high, medium, low as they are, informational as `info`), weighed by [Relevance](#relevance) |
| `title` | Prowler's result text, which names the resource (`Bucket x is publicly accessible.`). The check title states the passing condition, so it goes to the evidence |
| `remediation` | Prowler's recommendation text; `url` its page on hub.prowler.com |
| `track` | One tracker item per check across projects (`group` `check`, `key` the check id), titled `<check title> fails in 40 projects (Prowler <check id>)`, or the project's name when only one fails it |
| `evidence` | `check_id`, `check_title`, `service`, `resource_uid`, `resource_type`, `region`, `project`, `compliance` (CIS benchmark versions and requirement ids), `categories`, `prowler_version`, `prowler_severity` (Prowler's severity before relevance), `profile` (the project's activity profile) and, when the severity was changed, `relevance` (why) |

`describe` declares the `cloud` theme, so the tracker lists its items with the gcp connector's.

Prowler's per-resource raw data (`resources[].data`) is never copied: it holds whole API objects.

## Relevance

Most of a first run over many projects is the same CIS hygiene failing everywhere: nine logging
metric-filter alerts, a log sink, Cloud Asset Inventory, container scanning, Access Approval. In a
project that runs nothing they are not worth the attention a public bucket is. So each project
gets an activity profile that sets how much they count.

### Activity profile

Per project, as the account that answered for Prowler:

| Read | Command |
|---|---|
| Enabled services | `gcloud services list --enabled --project P` |
| Billing | `gcloud billing projects describe P` |
| VMs, GKE clusters, Cloud SQL instances, Cloud Run services, Cloud Functions, buckets | `gcloud compute instances list`, `container clusters list`, `sql instances list`, `run services list`, `functions list`, `storage buckets list` (`--project P`), each only when its API is enabled |
| In an organization | The `parent` that `gcloud projects list` already returned (a folder counts: folders exist only under an organization) |

An idle project costs two calls. Prowler's own results are not used for the counts: they depend on
`checks`, `excluded_checks` and `severity_min`, and Prowler has no Cloud Run checks.

| Class | When |
|---|---|
| `production` | Any VM, GKE cluster, Cloud SQL instance, Cloud Run service or function; or billing on and any bucket |
| `empty` | None of the resources above, and at most 5 enabled services beyond the 23 Google enables on every new project ([Services enabled by default](https://cloud.google.com/service-usage/docs/enabled-service)) |
| `light` | Everything else, e.g. a Firebase project with a bucket and no billing |
| `unknown` | A call failed (other than a disabled API) and what it would have said could change the class |

The profile goes into the evidence of every finding of the project (`class`, `services_enabled`,
`services_non_default`, `billing_enabled`, `in_organization`, `resources`, `unread`) and into the
project's `ok` status, e.g. `profile light: 25 non-default services, 1 buckets, billing off; 14
lowered by relevance, 0 not applicable`.

### Rules

Applied to each failure in this order; the first that matches decides:

1. **Not applicable** (`not_applicable`): `info`, with `relevance` = `not applicable: <reason>`.
   `where: "no_organization"` limits an entry to projects outside an organization; `any` (the
   default) applies everywhere. Info findings never open a tracker item, so these stay in the
   report with their reason instead of as open work.
2. **Overrides** (`relevance_overrides`): `info` sets the check to info everywhere; `keep` leaves it
   as Prowler rated it.
3. **Profile**, only with `relevance` on and only for the hygiene checks below:
   `empty` → `info`; `light` → one level lower (high → medium → low → info); `production` and
   `unknown` → unchanged.

Hygiene checks (Prowler 5.51.0 ids):

| Group | Checks |
|---|---|
| CIS 2.4-2.11 metric filters and alerts | `logging_log_metric_filter_and_alert_for_{audit_configuration,bucket_permission,compute_configuration,custom_role,project_ownership,sql_instance_configuration,vpc_firewall_rule,vpc_network,vpc_network_route}_changes_enabled` |
| Log export and audit logs | `logging_sink_created`, `iam_audit_logs_enabled`, `cloudstorage_audit_logs_enabled`, `cloudstorage_bucket_logging_enabled`, `compute_subnet_flow_logs_enabled`, `compute_network_dns_logging_enabled`, `compute_loadbalancer_logging_enabled` |
| Inventory, scanning, governance | `iam_cloud_asset_inventory_enabled`, `artifacts_container_analysis_enabled`, `gcr_container_scanning_enabled`, `iam_account_access_approval_enabled`, `iam_organization_essential_contacts_configured` |

Never lowered by the profile, whatever the project runs: findings of kind `exposure` or
`credential`, and these checks: firewall SSH/RDP open to the internet, VM public IP, default service
account on a VM (with or without full API access), public image, Shodan-listed address, public
bucket, Cloud SQL public IP or public access, public BigQuery dataset, public function, KMS key or
secret, Vertex AI Workbench public IP, API key checks, and service-account admin roles and unused
keys (`PROTECTED_CHECKS` in the script). `cloudstorage_uses_vpc_service_controls` is not in the
hygiene list because Prowler files it as `internet-exposed`.

`severity_min` filters on Prowler's severity, before relevance.

### Not applicable by default

| Check | Where | Why |
|---|---|---|
| `iam_account_access_approval_enabled` | Projects outside an organization | "Before enabling Access Approval, you must enable Access Transparency for your organization" ([Access Approval overview](https://cloud.google.com/assured-workloads/access-approval/docs/overview)). A project with no organization cannot meet that. Inside an organization Access Transparency is on by default ([Enable Access Transparency](https://cloud.google.com/assured-workloads/access-transparency/docs/enable)), so the check stays a hygiene check there |

Prowler 5.51.0 has no Access Transparency check of its own.

## Overlap with the gcp connector

Checked against Prowler 5.51.0 and [docs/gcp-connector.md](../../docs/gcp-connector.md). Unless
`include_overlaps` is true, full overlaps are passed to Prowler as `--excluded-checks` and partial
ones are run with the overlapping failures dropped.

| Prowler check | segurata `gcp` | Here |
|---|---|---|
| `apikeys_api_restrictions_configured` | API key without an API restriction: high | Not run |
| `apikeys_key_exists` | Every API key is a finding (restricted ones info) | Not run |
| `apikeys_api_restricted_with_gemini_api` | Unrestricted keys: high | Run; "does not have restrictions configured" dropped, "Gemini as well as other APIs" kept |
| `apikeys_key_rotated_in_90_days` | Shows `createTime`, no age rule | Run |
| `iam_sa_no_user_managed_keys` | Each user-managed key: medium | Not run |
| `iam_sa_user_managed_key_rotate_90_days` | User-managed key older than 90 days: high | Not run |
| `iam_sa_user_managed_key_unused` | Not reported (`last_used_at` stays null) | Run |
| `iam_sa_no_administrative_privileges` | Service account with `roles/owner` or `roles/editor`: high | Run; failures naming Owner or Editor dropped, other `*admin*` roles kept. Prowler names only the last matching binding; an account that also has Owner or Editor is already a high finding in `gcp`, and that role implies the narrower one |
| `iam_service_account_unused`, `compute_instance_default_service_account_in_use*` | Not reported | Run |

Not in Prowler, only in `gcp`: billing budgets and local credential files (ADC, key files).

## Coverage and statuses

| Record | When |
|---|---|
| `status ok` (account) | gcloud listed the account's projects |
| `status ok` (account, scope = project) | Prowler finished on the project; the detail is the summary, with the project's profile and how many failures relevance changed |
| `status noscope` (scope = project) | Every account that lists the project was denied, or Google refused one of Prowler's project-level calls (HTTP 403 in its log, including reading whether an API is enabled), so those checks saw nothing; the detail names the services and the roles to grant. Findings from what was read are still reported |
| `status error` (scope = project) | Prowler timed out, crashed, or wrote output that is not JSON |
| `status reauth` | gcloud's login for the account expired, or Prowler was refused its token |
| `status missing_credentials` | An account in `accounts` that gcloud has no credentials for |
| `status unsupported` (scope `*`) | Prowler or gcloud not found; a provider not implemented yet |
| `scope` inspected false | Projects in `skip_projects`, projects in `projects` no account lists, people `accounts` leaves out |

A disabled API leaves nothing of that service to check, so it does not make the run partial; the
project's summary names it.

## Test

```bash
cd plugins/prowler && python3 -m unittest
```

The tests put a fake `prowler` and a fake `gcloud` (shell scripts in `testdata/fakebin`) on `PATH`
and feed synthetic OCSF fixtures (`testdata/ocsf`, invented projects and resources); the fake gcloud
answers the profile calls from files each test writes. Nothing
reaches Google Cloud. The fixture follows the OCSF writer of Prowler 5.51.0
(`prowler/lib/outputs/ocsf/ocsf.py`).
