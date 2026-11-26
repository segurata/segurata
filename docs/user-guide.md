# User guide

Start with the [README quickstart](../README.md#quickstart). Use this guide when you need
configuration, the tracker, reports, or a plan for a change.

- [Configuration and output](#configuration-and-output)
- [Safety model](#safety-model)
- [Tracker and status](#tracker-and-status)
- [Accounts](#accounts) and [signing in](#signing-in)
- [Reports](#report) and [remediation](#remediation)
- [Accepted risks](#accepted-risks) and [scheduled runs](#scheduled-runs)

## Configuration and output

The config is `~/.config/segurata/config.json` (`SEGURATA_CONFIG` overrides it). The
[inventory guide](inventory.md) lists the keys for each connector. A key left out or set to
`null` takes its default. A malformed value
stops that connector with an error naming the key (`aws config: "profiles" must be a list of
non-empty strings`), never a silent default: a value of another type, an empty or blank string or
list entry, a number below 1 where a count or a limit belongs, or an empty list where the list
picks what to inspect (`accounts`, `profiles`, `projects`, `services`), since it would inspect
nothing; leave such a key out to inspect everything. Pass a connector name to `inventory` to limit
what runs.

Before the first inventory, `segurata doctor` checks, read-only, the config and its secret
references (resolved, never printed), the browser's debugging port, each connector's CLIs and
sign-ins (expired gcloud accounts, AWS profiles, `az`, `gh` scopes, Workspace tokens, the
Cloudflare token's permissions, rg and gitleaks) and the modes of segurata's own files, with the exact fix for each problem
(`--connector name` checks one). Details: [docs/architecture.md](architecture.md#doctor).

An external connector is any `segurata-<name>` executable on `PATH`, in any language; how to
write one, built-in or external: [docs/connectors.md](connectors.md). Contributing:
[CONTRIBUTING.md](../CONTRIBUTING.md).

Output goes to `~/.segurata/out/<date>/`. The inventory summary prints each JSONL path.
Unix runs use mode 0600 for those files in a 0700 directory because they contain account and
service details. Set `SEGURATA_OUT` or pass `--out` to choose another directory. Each inventory
ends with `segurata track sync`, which folds the latest runs into the tracker.

## Safety model

Every connector **inventories first, read-only**. Changing anything is a separate step, by hand or
with `segurata remediate`, which shows the exact plan and changes nothing without `--apply` and a
confirmation. The full list of guarantees, each of which counts as a vulnerability when broken:
[SECURITY.md](../SECURITY.md#security-principles).

### What leaves your machine

- No telemetry, no segurata server, no update check.
- Read requests to the providers you configure, with your own credentials: the provider CLIs
  (`gh`, `gcloud`, `aws`, `az`), GET requests to provider APIs with the token your config
  references, and pages of your own signed-in browser through its local debugging port.
- Secrets found on disk are fingerprinted and attributed locally by default. If you enable
  [liveness checks](inventory.md#liveness), supported checks authenticate against the provider with the
  candidate credential. AWS STS uses a request signed locally with the secret access key.
- Results stay on disk. Unix systems use mode 0600 for state files. On Windows, use folders
  with access restricted by Windows ACLs.
- `segurata remediate --apply` sends exactly the commands or requests its plan showed.
- External connectors (`segurata-<name>` on `PATH`) run as you and send what they send: the
  [hibp example](../examples/hibp/README.md) sends your email addresses to Have I Been Pwned. Read one
  before you install it.

## Tracker and status

```bash
./segurata status                         # the briefing: what to do next, decisions, blockers, changes (read-only)
./segurata status --explain               # same, with the score behind each "Do next" entry
./segurata status --mark-seen             # same, and start "Since the last status" from now
./segurata status --priority P0,P1 --theme github-orgs
./segurata status --write                 # also ~/.segurata/status.md and status.html (mode 0600); implies --mark-seen
./segurata track list [--all] [--kind rotate] [--theme t] [--priority P0,P1] [--status s]
./segurata track show T-0042
./segurata track start|done|reopen T-0042 [--note "..."]
./segurata track note T-0042 "ordered a backup disk"
./segurata track snooze T-0042 --until 2027-01-15
./segurata track ignore T-0042 --reason "test fixture"
./segurata track ignore --path ~/src/app/log/test.log --reason "test fixtures"   # every item found only there
./segurata track expect T-3153 --reason "ephemeral key on purpose" [--dry-run]   # a setup item kept on purpose: config rule

./segurata track prioritize T-0042 P0 --reason "client data"   # `auto` goes back to the computed one
./segurata track decide T-0003 --answer "yes" [--ignore-scope path:~/src/old] [--accept-scope repo:acme/site]
./segurata track decide T-0002 --answer "rotate mine, ignore the rest" --ignore-scope path:~/src/legacyco --owner not-mine [--dry-run]
./segurata track add --title "Buy a hardware key" [--kind fix|setup|review] [--priority P1]
./segurata track add --kind decide --question "Keep the old VPS?" --option yes --option no
./segurata track add --kind decide --question "Are the legacy repos dead?" --option "yes=ignore:path:~/src/legacy" --option no
./segurata track sync [--out out]         # also run by inventory; rotations sync is the same, needing a local-secrets run
```

`~/.segurata/tracker.json` (mode 0600 in a 0700 folder; `SEGURATA_HOME` names another folder)
is the single record of what to do, what is done and what is pending, and survives restarts: one
item per thing a person would act on. Five GitHub orgs that do not require 2FA are one item; each
secret to rotate, each data dump and each Mac setting is its own item; a connector that needs a
fresh sign-in is a setup item; info findings make none. Items have a kind (fix, rotate, decide,
setup, review), a theme, a status (open, in_progress, done, accepted, ignored, snoozed, and two
segurata sets itself: reclassified, a secret a corrected rule now rates as noise, and expected), a computed
priority that `prioritize` can override, the findings they link, the next step and a history.

A decision can carry effects: answering it adds rules (`ignore` or `accept` a scope:
`path:<dir>`, `repo:<owner/name>`, `account:<glob>`, `gcp-project:<id>`) that close the items in
scope now and at every sync, with the decision named in the reason. A pending decision shows
how many open items each answer would close. `--owner not-mine` (or an option written
`yes=ignore@not-mine:path:~/src/old`) narrows the rules to secrets attributed to someone else (see
[Attribution](inventory.md#attribution)): the owner's own and the unknown ones stay open, and `--dry-run` says so
before anything changes ("closes 120 open items (P0 100, P1 20) attributed not-mine, keeps 8 open
(mine 5, unknown 3)"). Details:
[docs/architecture.md](architecture.md#decisions-and-rules).

A status other than `ok` that is kept on purpose (an ephemeral key, an IAM user limited by design,
other people's accounts) goes in the config as an expected rule, by hand or with `track expect`:
`{"connectors": {"anthropic:personal": {"expected": [{"state": "missing_credentials", "reason":
"…"}]}}}`, with optional `account` (a glob) and `detail` (substring, or `/regexp/`). It then opens
no setup item and is counted on one line, "N expected (by your config)", but its scope still
counts as not inspected. Details:
[docs/architecture.md](architecture.md#expected-statuses).

Each connector instance's inventory runs under a deadline, one hour unless the connector declares
more (local-secrets 6h, prowler 12h) or the instance sets `timeout`:
`{"connectors": {"gcp": {"timeout": "2h"}}}`. A run that hits it ends failed, so nothing it left
out is closed. Details: [docs/architecture.md](architecture.md#run-completeness).

A done item is verified when a later run no longer reports its findings, and reopened if one does;
an item whose findings vanish on their own is closed as "verified (no longer reported)", and a
setup item whose status a finished run no longer reports as "verified (status no longer
reported)", whatever that run inspected. Expired
snoozes and acceptances open their items again. Every change goes through the CLI; the file is
written atomically and the previous version kept as `tracker.json.bak`. A tracker that does not
parse is never overwritten: fix it or restore the backup. It holds redacted hints and fingerprints,
never a secret value, so the backup holds none either.

## Accounts

```bash
./segurata accounts list [gcp|google-personal] [--out out]   # accounts each connector saw: watched or not, last state, last seen
./segurata accounts unwatch google-personal colleague@example.com  # take it out of connectors."google-personal".config.accounts
./segurata accounts watch google-personal colleague@example.com    # put it back
./segurata accounts owned [--out out]                         # the owner's accounts attribution compares secrets with
```

`unwatch` writes the connector's `accounts` list (from the accounts the runs saw, when there is no
list yet) and closes the account's open setup items as ignored; `watch` adds it back and opens the
items `unwatch` closed. The config is rewritten atomically (mode 0600, keys in their order) and the
previous file kept as `config.json.segurata-bak-<time>`. An unwatched account is declared a skipped
scope at each run, so its earlier findings are never taken as resolved. `gcp` and
`google-personal` take an accounts list.

## Signing in

```bash
./segurata signin --list                 # what it would open and list; opens nothing
./segurata signin                        # open the pages, wait, run those connectors again
./segurata signin google-personal        # only this connector (or connector:label)
./segurata signin --all --timeout 20m    # also the commands of other setup items; wait longer
```

`signin` takes the open setup items where a browser connector reports `reauth` or `signedout`
(Google asks you to verify it's you, GitHub wants sudo mode, Microsoft Security info wants a fresh
MFA sign-in, Dropbox is signed out) and opens a
normal tab at each page where you act, in the browser at `cdp_url`. It prints a numbered list with
what to do on each page, then reads the pages every few seconds, read-only, with the test the
connector itself uses, until each shows what the connector reads (the list instead of the sign-in
or "Confirm access" page). It stops once every page is through, when you press Enter, or after the
timeout (10 minutes by default). Then it runs those connector instances again, syncs the tracker
and says which setup items closed. It never types a password or clicks anything, and the tabs stay
open: they are yours.

- GitHub sudo mode lasts minutes, so `connected-apps` runs as soon as you confirm on GitHub, while
  the other pages wait; it runs again at the end only if one of its pages was through after that.
- Commands for your terminal (`gcloud auth login <account>`, `gh auth refresh -s <scope>`) are
  listed with the rerun that follows them; `signin` never runs them, since they start a browser of
  their own. `--all` also lists the commands of the other setup items, such as storing a
  credential.
- Accounts taken out with `segurata accounts unwatch` are skipped.
- Tabs open only in the browser at `cdp_url`, through CDP. When it is not reachable, `signin`
  prints the URLs and stops; it never opens another browser or calls the system's `open`.
- `segurata status` ends the setup blockers with "`segurata signin` opens the pages that need
  you" whenever one of them is a browser sign-in.

## Report

```bash
./segurata report                                   # terminal text
./segurata report --format html --out report.html   # one self-contained page, mode 0600
./segurata report --format md --out report.md
```

One page from the latest run of every connector instance (`out/<date>/<name>.jsonl`, the same
files `remediate` reads), the accepted risks and the secrets to rotate, both from the tracker. The
report is the per-run view; `segurata status` is the tracker's:

- Headline: the tracker's items counted as `status` counts them (open by priority and theme,
  done, accepted, merged…), then the findings of the latest runs as a note and a table by
  connector instance (run date, severities, accepted, statuses needing attention).
- Setup blockers: the tracker's setup items, as in `status`, each with what to do and the
  `segurata inventory <name>` that checks it afterwards.
- Changes in the last 7 days: items found, closed, verified by a later run and reopened, from the
  tracker's history, the latest listed. Before the first `track sync` the report syncs a copy of
  the tracker in memory (nothing is saved), so every item reads as new.
- Top findings, worst first and grouped by connector, each with its remediation, its page and
  `segurata remediate <id>` when automatable.
- Rotation ledger: open rotate items by priority, the first P0 items (redacted hint, exposure, reason,
  rotate URL; never a location) and snoozes past their date.
- Accepted risks, with the expired ones and the ones the latest run no longer reports.

`--min-severity` (default `low`) and `--top` (default 10 per connector)
trim the lists; `--dir` names another inventory directory. The HTML page has no script and no
external asset, follows the system's light or dark mode and fits a phone. Written to a file, the
report gets mode 0600: it names accounts, services and paths. It never contains a secret value,
because findings and the tracker never hold one.

## Remediation

```bash
./segurata remediate --list                # automatable findings of the latest run, one line per group
./segurata remediate <id>                  # the exact plan; changes nothing
./segurata remediate <id> --apply          # asks "Apply? [y/N]", applies, re-checks
```

One finding at a time, or one group: some actions fix every finding of a group in one plan (all
public repositories of a GitHub owner, every expired secret of an Azure tenant), which `--list`
shows as one line and the plan lists finding by finding. The plan shows the commands or HTTP
requests, whether they need sudo, the side effects and how to undo them, or that they cannot be
undone. With `--apply` it asks for confirmation (and refuses without a terminal unless `--yes`),
then runs that connector again and checks that no finding of the plan still offers the action.
Commands that need root run as `sudo <command>` on your terminal, so sudo asks for your password
itself; segurata never sees it. An interactive command (`gh auth refresh` opens a browser) runs on
your terminal too and is refused without one, `--yes` or not. Design:
[docs/architecture.md](architecture.md#remediation).

| Action | What it runs | Undo |
|---|---|---|
| `macos.firewall.enable` | `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on` | `--setglobalstate off` |
| `macos.firewall.stealth` | `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on` | `--setstealthmode off` |
| `macos.smb.share-remove` | `sudo /usr/sbin/sharing -r <name>` (orphaned records and shared folders without guest access) | `sudo /usr/sbin/sharing -a <path> -n <name> -S <smb name> -s <flag> -g <flag> -R <0/1>` with the record's current flags; not applicable for an orphan, whose folder no longer exists |
| `macos.smb.guest-off` | `sudo /usr/sbin/sharing -e <name> -g 000` (live shares open to guests) | `sudo /usr/sbin/sharing -e <name> -g 001` |
| `macos.home.private` | `/bin/chmod 700 <home>`, no sudo, when group or others can read the home folder (every user is in `staff`, so 750 is as open as 755; 711 passes, as CIS allows) | `/bin/chmod <old mode> <home>` |
| `file.chmod600` | Makes the file in the finding's `evidence.path` private: mode 600, or 700 when its owner could execute it. With a group, every file of the group once | `chmod <old mode> <path>` per file |
| `github.secret-scanning.enable` | Per GitHub owner: `gh api --method PATCH --silent /repos/<owner>/<repo> -f 'security_and_analysis[secret_scanning][status]=enabled' -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'` for each public repository you administer where either is off (only the fields that are off). Private repositories are left out: there it needs GitHub Secret Protection, a paid add-on | the same request with `disabled` |
| `github.workflow-token.read` | Per GitHub owner: `gh api --method PUT --silent /orgs/<org>/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=<as it is>` for the organization first, then `/repos/<owner>/<repo>/actions/permissions/workflow` for each repository whose default is write | the same request with `write` |
| `connected-apps.gh.drop-scopes` | `gh auth refresh -h github.com -r delete_repo,admin:org[,admin:enterprise]`, the removable scopes gh's token holds now, in your terminal (browser approval) | `gh auth refresh -h github.com -s <the same scopes>` |
| `azure.app-secret.delete-expired` | Per tenant: `az ad app credential delete --id <appId> --key-id <keyId> --only-show-errors` for each client secret that is still registered and already expired | none: a deleted secret cannot be restored (it had expired) |
| `openai.key.delete-unused` | `DELETE /v1/organization/projects/<project>/api_keys/<key>` or `DELETE /v1/organization/admin_api_keys/<key>`, for a key never used or idle for over 90 days, with `OPENAI_ADMIN_WRITE_KEY` | none |
| `openrouter.key.delete-unused` | `DELETE /api/v1/keys/<hash>`, for an enabled key never used, idle for over 90 days or without recorded use since the end of 2025, with `OPENROUTER_MANAGEMENT_WRITE_KEY` | none |

Every plan is computed from a fresh read (the repository, the token's scopes, the tenant's app
registrations, the key's last use), not from the finding: what changed since the inventory is left
out and named, and a key back in use, or the key segurata reads with, is refused. The allowlist of
exact command lines and HTTP routes is built from that same read at apply time.

Dropping `admin:org` from gh's token makes the github connector report each organization's
settings as `noscope` ("organization settings need admin:org"), and `github.workflow-token.read`
can then no longer change an organization's default. Give segurata a read-only fine-grained token
in `GH_TOKEN` for its runs if it should hold no write scope at all; `gh auth refresh` cannot change
a token that comes from the environment, and the plan refuses then.

### Write credentials

The inventory keys stay read-only. A remediation that writes through a provider's API uses a
separate write key, referenced under `remediation_secrets` of the same connector instance. Only
`remediate --apply` resolves it, after you confirmed the plan; no inventory ever reads it, and a
`*_WRITE_KEY` under `secrets` is rejected when the config loads. Without it, the dry run shows the
plan marked blocked, with these instructions, and `--apply` refuses before asking.

```sh
security add-generic-password -s segurata-openai-admin-write -a "$USER" -w      # admin key with write access to API keys
security add-generic-password -s segurata-openrouter-admin-write -a "$USER" -w  # management key, access level read/write
```

```json
"openai":              {"secrets": {"OPENAI_ADMIN_KEY": "keychain:segurata-openai-admin"},
                        "remediation_secrets": {"OPENAI_ADMIN_WRITE_KEY": "keychain:segurata-openai-admin-write"}},
"openrouter:personal": {"secrets": {"OPENROUTER_MANAGEMENT_KEY": "keychain:segurata-openrouter-personal"},
                        "remediation_secrets": {"OPENROUTER_MANAGEMENT_WRITE_KEY": "keychain:segurata-openrouter-personal-write"}}
```

You can create the write key for the session and delete it afterwards. A 401 or 403 on apply
means the key cannot write; the error names it.

External connectors speaking protocol 2 add their own actions (`segurata connectors` lists
them after `remediates:`). The plan, the confirmation and the check afterwards are the same; the
connector runs its own plan as you, and segurata refuses any plugin plan that needs sudo
([docs/connectors.md](connectors.md#plan-v2)).

The home folder path comes from the OS (`os.UserHomeDir`), never from the finding, and the octal
`chmod` leaves its ACL entries (macOS's `group:everyone deny delete`) in place; the finding's
evidence lists them.

The share point name comes from a fresh `sharing -l -f json` read at plan and at apply time, never
from the finding alone: a name that matches no record exactly is refused, and the apply-time
allowlist holds only the records that exist then. The name is one argument to `sharing`, never
passed through a shell, so spaces and quotes in it are safe. Turning guest access off changes the
finding's id (`smb-share-guest:<name>` becomes `smb-share:<name>`), which is how the re-check sees
the fix; the share itself stays reported as a medium finding.

Port 445 stays manual. `launchd` owns that socket (netstat shows pid 1) and hands connections to
`smbd` on demand, so it listens while File Sharing is on, with or without share points. After the
last share point is removed, the port finding says "with no shared folders" and points to System
Settings > General > Sharing > File Sharing. Turning off the `smbd` launchd service by hand is not a
supported way.

Manual, with the System Settings path in the finding: File Sharing itself (SMB, port 445), AirPlay Receiver (ports 5000 and 7000), Remote Login, Screen Sharing, FileVault,
Gatekeeper, SIP, update settings, screen lock, login items and browser extensions.

AirPlay Receiver is manual because the Terminal remediation the CIS benchmarks give (`defaults
-currentHost write com.apple.controlcenter AirplayRecieverEnabled -bool false`, then restarting
ControlCenter) left ports 5000 and 7000 open on macOS 15.6 (tried 2026-11-23).

After `--apply`, the check waits 5 seconds and needs the finding fixed in two inventories in a row:
a restarted process can drop its ports for a moment and open them again. Fixed means no fresh
finding with the same id still offers the action: a GitHub repository finding that keeps a deploy
key issue is fixed as far as secret scanning goes, and then offers the next action
(`github.workflow-token.read`) if its workflow token is still writable.

## Accepted risks

```bash
./segurata accept <id> --reason "AI agents drive Brave over CDP" [--until 2027-03-31]
./segurata accept --list
./segurata unaccept <id>
```

A finding you keep on purpose stays in `out/<date>/*.jsonl` with an `accepted` field, but leaves
the summary and `remediate --list`, which print how many were hidden. With `--until`, it shows
again after that day, marked "(acceptance expired)". Acceptances are tracker items with status
`accepted`; accepting one finding of a grouped item (one of five orgs) moves it to an item of its
own first. `unaccept` takes the finding id or the item id. Details:
[docs/architecture.md](architecture.md#accepted-risks).

## Scheduled runs

```bash
./segurata schedule install                         # print the launchd agent; changes nothing
./segurata schedule install --every 12h --apply     # write and load it, after "Apply? [y/N]"
./segurata schedule status
./segurata schedule uninstall --apply
```

A launchd user agent (`~/Library/LaunchAgents/com.segurata.inventory.plist`) runs an inventory
every day (or `--every`), writes `~/.segurata/last-report.md`, and posts a macOS
notification when its tracker sync opens a P0 or P1 item, new or reopened. By default
it runs every connector; `--connectors macos,local-secrets,hibp` picks them. The browser connectors
(`google-personal`, `connected-apps`) run only when Brave answers at `cdp_url`, in hidden pages that
never take focus; when it does not, or another browser holds the port, they are recorded as not
inspected ("browser not reachable over CDP"), nothing they found is closed, and no other browser is
started. After `"browser_stale_days"` (default 7) of that, one notification says so. Logs go to `~/Library/Logs/segurata/`, inventories to
`~/.segurata/out`, pruned to the last 30 days after each run (`"keep_runs_days"` in the config; the
latest run of each connector and the one before it always stay). Install it from the binary you
will keep: the agent runs that
exact path, with the PATH you had when installing. On Linux it prints a systemd user timer to
install by hand. Details: [docs/architecture.md](architecture.md#scheduled-runs).
