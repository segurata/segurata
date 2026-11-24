# Architecture

segurata inventories the digital footprint of a person or a small company (consumer accounts,
clouds, AI providers, secrets on disk), assesses it and, only when asked, cleans it up.

Everything in this repository is written in English: code, comments, finding text, docs and commit
messages.

## Pieces

```
segurata (Go binary)
├── core: config, secret references, connector execution, output, report
├── built-in connectors (compiled in)
└── external connectors: segurata-<name> executables on PATH, in any language
```

Both kinds of connector share one contract. A built-in one implements the Go interface
`connector.Connector`; an external one speaks the protocol below over stdin/stdout and the core
wraps it in that same interface. The rest of the program cannot tell them apart.

### Verbs

| Verb | What it does | Changes anything outside |
|---|---|---|
| `inventory` | Lists what exists: grants, keys, settings, spend | Never |
| `assess` | Assigns severity and remediation to each finding | Never |
| `remediate` | Applies one remediation to one finding | Yes, one item at a time, dry run unless `--apply`, explicit confirmation |
| `status` | The briefing from the tracker: what to do next, decisions, setup blockers, changes since the last status, accepted risks | Only segurata's own `tracker.json` (the "since" mark) and, with `--write`, `status.md` and `status.html` |
| `track` | Lists, shows and changes tracker items; `track sync` folds the latest runs in | Only segurata's own `tracker.json` |
| `accept` / `unaccept` | Marks a finding as a risk kept on purpose, or stops doing so | Only segurata's own `tracker.json` |
| `doctor` | Checks prerequisites: config, secret references, browser port, CLIs and sign-ins, state file modes | Never |
| `rotations` | Keeps the ledger of secrets to rotate (the tracker's rotate items) and guides each rotation | Only segurata's own `tracker.json`, except `replace --apply`: the `used_in` files and the Keychain, after confirmation |
| `report` | Summarises the latest runs, what changed, the secrets to rotate and the accepted risks | Never (writes only the `--out` file) |
| `redact` | Replaces the secrets `local-secrets` finds in trail files (agent transcripts, shell histories, logs) with `[REDACTED:<type>:<fingerprint8>]` | With `--apply` and confirmation: those trail files, never a working file; a history note in `tracker.json` |

In v0 each connector sets severity while inventorying (`assess` lives inside `inventory`).
`remediate` always states the exact scope of what it will remove before acting. On Google,
"Remove all access" on an app's permissions page also removes that app's Sign in with Google
link; that has to be said up front, not discovered afterwards.

## Finding model

A connector emits JSON records (`internal/finding`): one `finding` per thing worth looking at
(connector, account, resource, kind, severity, title, evidence, dates, remediation) and one
`status` per account saying whether it could be inspected (`ok`, `reauth`, `signedout`,
`noscope`, `unverified`, `missing_credentials`, `unsupported`, `error`). The core fills the
derived fields: the stable id (a hash of connector, instance, account, resource type and resource
id), the connector name, `observed_at`, `automatable` and `accepted`. `evidence` never holds a
secret. Fields, kinds, stable-id and severity rules: [connectors.md](connectors.md#finding-model).

## Tracker

Runs and findings are ephemeral: each inventory rewrites them. The tracker (`internal/tracker`) is
the one durable record of what to do, what is done and what is pending.

State: `~/.segurata/tracker.json`, mode 0600 in a 0700 folder (`SEGURATA_HOME` names another
folder), outside any repository. Generated views live beside it (`status.md`, `status.html`) and
are never edited by hand. The file is JSON with a `schema_version`; it is the single source of
truth, and every change goes through the CLI.

### Ontology

- **Run** and **finding**: as above, with stable finding ids.
- **Item**: one thing a person would do.

```json
{"id": "T-0042", "key": "group:github|github_org_setting|check:org-2fa-not-required",
 "kind": "fix", "theme": "github-orgs", "title": "Two-factor authentication not required in 5 GitHub orgs",
 "status": "open", "priority": "P1", "priority_override": null, "severity": "high",
 "findings": [{"id": "b312fe6437ca5c65", "connector": "github", "account": "github:acme-labs",
               "title": "acme-labs does not require two-factor authentication", "severity": "high",
               "last_seen": "…", "gone": false}],
 "next": {"who": "you", "action": "Turn on \"Require two-factor authentication\" …",
          "command": "segurata track show T-0042", "url": "https://github.com/organizations/acme-labs/settings/security"},
 "status_at": "…", "verified_at": null, "created_at": "…", "updated_at": "…",
 "history": [{"at": "…", "event": "found", "action": "found", "detail": "5 findings"}]}
```

  - `id` is `T-` and a number from `next_id`: stable, never reused. `key` says what makes findings
    the same item; sync finds items by key.
  - `kind`: `fix`, `rotate` (one secret, by `fingerprint`, with its locations under `secret`),
    `decide` (with `decision`: question, options, answer, answered_at), `setup` (what keeps
    segurata from seeing an account) or `review` (a list to keep or prune).
  - `status`: `open`, `in_progress`, `done`, `accepted` (with `accepted`: reason, until,
    accepted_at), `ignored` or `snoozed` (with `snoozed_until`).
  - `priority` is computed: a rotate item's comes from the rotation model below; others map the
    worst linked severity (critical P0, high P1, medium P2, low P3). `priority_override`
    (priority, reason, at) wins when set.
  - `history` events are `found`, `seen`, `status`, `note`, `verified`, `reopened`, `decided` or
    `priority`; `action` keeps the precise verb (`done`, `auto-done`, `auto-reopen`,
    `snooze-expired`, `acceptance-expired`, `history-only`, `redacted`, `next`, …).
- **Theme**: `{id, title, description}`, seeded in every tracker: `rotations`, `data-dumps`,
  `transcripts`, `mac`, `browser-extensions`, `github-orgs`, `connected-apps`, `google`, `cloud`,
  `ai-spend`, `setup`, `decisions`, `other`. A connector maps to one (local-secrets by resource
  type).

### Grouping

Info findings never make an item. The rest group by a table of rules (`group.go`), matched on
connector and resource type, first match wins:

| Findings | One item per | Kind |
|---|---|---|
| local-secrets secrets | fingerprint (rotate items, below) | rotate |
| local-secrets secrets in transcripts, shell histories and logs | local-secrets instance: "Redact secrets from N trail files", next step `segurata redact --trails`, severity capped at medium | fix |
| local-secrets `data_dump` | file | fix |
| github org and repository-setting checks | check, across orgs ("Two-factor authentication not required in 5 GitHub orgs") | fix |
| github repositories | organization | fix |
| connected-apps Slack apps | workspace and severity | review |
| other connected-apps | account and title family ("27 X apps can post and delete posts as you") | review |
| google-personal OAuth grants | account and severity | review |
| gcp API keys, service-account keys, service-account roles | project | fix |
| openai, anthropic, openrouter API keys | instance, account and severity | fix |
| macos, aws | finding | fix |
| browser-extensions | extension | review |
| anything else | account, resource type and title family (the title without the resource's name, quoted names and numbers blanked) | fix |
| a connector status other than `ok` | instance, account and state | setup |

A finding that has an item of its own (key `finding:<id>`) always goes there before any rule: one
accepted apart from its group, or one grouped per finding anyway. The title and next step come
from the rule and the worst finding's remediation (`segurata remediate <id>` and `who:
segurata` when the only finding is automatable). Only generic decisions are seeded, once each
(whether to install the daily schedule). Questions about an owner's own projects are added with
`segurata track add --kind decide` and live only in that owner's tracker, never in the code.

### Lifecycle: `segurata track sync`

`track sync` runs at the end of `inventory` and `rotations sync`, or by hand. It reads the latest
run of every connector instance (`remediate.LatestFiles`) and:

1. Skips a run older than the one the tracker last folded for that instance (`sources`), so
   syncing two output folders (interactive and scheduled) never makes items flap.
2. Folds local-secrets findings into rotate items (below) and every other finding at low or above
   into the item its rule names, creating it (`found`) or adding the new finding (`seen`).
3. Marks a linked finding `gone` when its connector instance ran and did not report it, unless
   that run could not inspect the finding's account (a non-ok status for that account, or for all).
4. Moves items on:
   - open, in progress or snoozed, with every finding gone: done, `verified (no longer reported)`;
   - done: verified once every finding is gone in a run after it was marked done; reopened
     (`auto-reopen`) if a run after it was marked done or verified reports one again. A sync
     that only reads the run from before the item was marked done changes nothing;
   - accepted and ignored items only get their findings updated;
   - a snooze past its date, or an acceptance past its last day, opens the item again. An
     expired acceptance stays on the item, so its findings show "(acceptance expired)" until the
     owner acts.
5. Adds any missing theme or seeded decision.

Rotate items keep the rotation rules below instead: they are never closed because a secret
stopped being reported (git history and transcripts do not forget, and a redacted copy still
reached the model provider).

### Restart resistance

- Writes are atomic (`statefile`: temporary file, fsync, rename), mode 0600 in a 0700 folder.
- Before each write the file being replaced is copied to `tracker.json.bak` (one copy, 0600). The
  tracker holds no secret value (rotate items carry redacted hints and HMAC fingerprints, findings
  none), so the backup holds none either.
- Load validates: JSON with no unknown field, a known `schema_version`, unique `T-` ids below
  `next_id`, unique keys, known kinds and statuses, rotate items with a secret and decide items
  with a decision. A file that fails is an error for every command, never an empty tracker, and
  is never overwritten (Save re-reads it and refuses): fix it or restore the backup.
- `schema_version` 1 is the current format. A future format change adds an upgrade step from
  version n to n+1 on the raw JSON, applied in order when loading; a newer file than the binary
  knows is refused.

### Migration from the former state files

The first command that opens the tracker when `tracker.json` does not exist but
`rotations.json` in `~/.segurata` (`SEGURATA_STATE` names another folder) or
`~/.config/segurata/accepted.json` (`SEGURATA_ACCEPTED`) does imports them:

- every ledger item becomes a rotate item, ids in order of first sighting, with its locations,
  `used_in`, reasons, priority, `rotated_locations`, snooze and full history (each event's time,
  action and note kept; `rotated` becomes `done`, `ignored`, `snoozed` and `open` stay);
- every accepted risk becomes an accepted item of its own linking that finding, with its reason,
  end date and acceptance time.

Stored values are imported as they are, not recomputed. The tracker is saved, then the old files
are renamed to `<file>.migrated-<date>` (never deleted, never overwritten). A file that does not
parse, or has an unknown version or status, stops the import and nothing is written or moved.

### Directories of the former name

`internal/legacy`, run by every command before config or state is read (what moves where: README,
"Upgrading"). Each old directory is renamed only when the new one does not exist; when both exist
it warns on stderr and the new one is used. A rename keeps modes and bytes, so the fingerprint key
and every fingerprint survive. After moving the tracker it rewrites the binary's own words in it
(who takes the next step, its action and command, decision questions and options, theme
descriptions), never the owner's notes or a path. After moving the config it renames a Keychain
reference only when the new item exists, checked from its attributes (`security
find-generic-password -s <service>`, no `-w`).

`segurata keychain-migrate [--apply [--yes]]` handles the rest, one item at a time: read the old
value (`-w`, captured in memory), store it under the new name with `security -i` and the add command
on stdin, read it back and compare, rewrite the reference in the config, and only then delete the
old item. A failure before the rewrite leaves the config and the old item as they were; a new item
that already holds a different value is left for the owner to resolve. Values never reach an
argument list or the output. `internal/keychain` holds the Keychain calls it shares with `rotations
replace --to-keychain`.

### `segurata status`

```
segurata status [--theme t] [--kind k] [--priority P0,P1] [--format text|md|html] [--write]
```

The briefing, built with the report's document model and renderers (`internal/doc`), so text,
Markdown and HTML say the same thing: a headline (open items by priority and theme, done and
verified in the last 7 days, accepted, ignored, snoozed), "Do next" (the ten most urgent entries
with their next step, command and page; secrets count as one entry per priority pointing to
`segurata rotations next`), pending decisions, setup blockers, the changes since the last
unfiltered status (events counted, the latest listed) and the accepted risks. `--write` also
writes `status.md` and `status.html` next to the tracker, mode 0600. `report` stays the per-run
view.

## Remediation

```
segurata remediate --list                      automatable findings of the latest run
segurata remediate <finding-id>                print the plan; changes nothing
segurata remediate <finding-id> --apply        print the plan, ask "Apply? [y/N]", apply, check
segurata remediate <finding-id> --apply --yes  same without asking
```

The finding comes from the latest `out/<date>/*.jsonl` (a unique id prefix is enough). The plan
(`connector.Plan`) states the whole scope before anything runs: a summary, the exact commands, the
file changes, whether it needs sudo, the side effects and the exact commands that undo it.

- One finding per run. Without `--apply` it stops after the plan. With `--apply` it asks on the
  terminal and refuses when stdin is not a terminal, unless `--yes`.
- After applying, the core runs that connector instance's inventory again and reports whether the
  finding is gone. A finding still reported, or a check that could not run, is an error.
- A built-in connector remediates by implementing the optional `connector.Remediator` interface
  (`Plan`, `Apply`). `Apply` recomputes the plan and refuses one that differs from what was shown.
- Every command an action may run is on a per-action allowlist of exact argument lists, written by
  hand (`remediate.Allowlist`). There is no pattern matching; anything else is refused before the
  first command runs. An action whose argument names a live object (an SMB share point, the home folder) gets its
  entries at apply time from a fresh read of what exists, never from the finding: the finding only
  says which object, and a name that matches nothing exactly is refused.
- sudo: a command that needs root runs as `/usr/bin/sudo <argv>` with the terminal's stdin, stdout
  and stderr attached, so sudo asks for the password itself. segurata never reads, stores or
  pipes a password.
- Generic actions belong to the core, so any connector can attach them. `file.chmod600` takes the
  file in `evidence.path` (absolute or `~/`), refuses symlinks and non-regular files, and changes the
  mode in-process; the undo is `chmod <old mode> <path>`.
- An external connector remediates through protocol 2: it declares its actions in `describe`
  (`remediates`), returns a plan from `segurata-<name> plan` and runs it in
  `segurata-<name> apply` (`remediate.External`). The core shows the plan and confirms as for a
  built-in, asks for the plan again before applying and refuses one that differs, and refuses any
  plan that needs sudo: a plugin's command line is never on the hand-written allowlist, so the core
  cannot vet it and will not run it as root. The plugin runs its plan as the owner; the allowlist
  binds built-in actions only. Details: [connectors.md](connectors.md#plan-v2).

## Accepted risks

```
segurata accept <finding-id> --reason "..." [--until YYYY-MM-DD]
segurata accept --list
segurata unaccept <finding-id>
```

Some findings describe a risk the owner keeps on purpose (Brave's remote debugging port, which
local AI agents drive). `accept` looks the finding up in the latest run (a unique id prefix is
enough) and records it in the tracker (`internal/accept` on `internal/tracker`): the item that
links the finding gets status `accepted` with `{"reason", "until", "accepted_at"}`. When that item
groups other findings too (one of five orgs), the finding first moves to an item of its own, so
the others stay open. `unaccept` takes the finding id (or a unique prefix) or the item id and
opens the item again. Acceptances recorded in the former `~/.config/segurata/accepted.json` are
imported once (see "Tracker").

- The core stamps every finding of an inventory with `"accepted": {"reason", "accepted_at",
  "until", "expired"}` when an item holding its id carries an acceptance. The finding stays in the JSONL; the summary
  and `remediate --list` leave it out and say "N accepted findings hidden; see segurata accept
  --list". `remediate` re-reads the file, so an acceptance made after the run counts.
- `until` is the last day it applies. After it the finding shows again, its title followed by
  "(acceptance expired)", and the next sync opens the item again.
- This only works with stable ids: a finding id hashes connector, account, resource type and
  resource id, so a resource id must not hold anything that changes between runs (a pid, a port).
  The debugging-port finding's resource id is `brave-remote-debugging`, whatever port Brave uses.
- A broken tracker is an error, never an empty list: a typo must not unhide or hide anything silently.

## Report

`segurata report [--format text|md|html] [--out file]` (`internal/report`) reads, and never
changes:

- the latest run of every connector instance, through `remediate.LatestFiles` and
  `remediate.ReadRun` (findings and statuses);
- for each, its previous run: `remediate.PreviousFile`, the same file name in the newest earlier
  `out/<date>/` folder;
- the tracker's acceptances, which annotate every finding as `inventory` does, so an acceptance
  made after the run counts and an expired one shows again;
- the tracker's rotate items.

The only write is the one-time import of the former state files, when the tracker does not exist
yet.

The diff is by finding id: an id only in the latest file is new, one only in the previous file is
resolved, one in both with another severity changed. That is why ids must stay stable (see
"Accepted risks"). Runs compare per connector instance, because each connector runs on its own
schedule.

The report is built once as a small document (headings, paragraphs, lists, tables) and rendered as
text, Markdown or HTML, so the three formats carry the same content. Markdown escapes markup in
titles; HTML escapes everything, links only absolute http(s) URLs, has no script, loads nothing
(its CSP is `default-src 'none'`) and switches colours with `prefers-color-scheme`. `--out` writes
atomically with mode 0600 (`statefile.Write`).

What it shows of the rotate items is the secret's short id, service, type, redacted hint, worst exposure, first
reason and rotate URL; never a location path. Findings never hold a value, so neither does the
report.

## Scheduled runs

```
segurata schedule install [--every 24h] [--connectors a,b] [--apply [--yes]]
segurata schedule uninstall [--apply [--yes]]
segurata schedule status
segurata schedule run [--connectors a,b]        what the agent executes
```

`internal/schedule`. On macOS, `install` builds a launchd user agent,
`~/Library/LaunchAgents/com.segurata.inventory.plist`, that runs `segurata schedule run` every
`--every` (default 24h, at least 1h; `StartInterval`, not at load) from
`~/.segurata`, with the PATH of the shell that installed it and its output in
`~/Library/Logs/segurata/`. Without `--apply` it prints the plist and the
`launchctl bootstrap gui/<uid> <plist>` command and changes nothing; with `--apply` it asks on the
terminal as `remediate` does (`--yes` skips it), writes the plist (mode 644), boots out an agent
already loaded and bootstraps the new one. `uninstall` boots it out and removes the plist, keeping
reports and logs. `install` refuses a binary under the temp directory (`go run`), which would be
gone by the first run.

One `schedule run`:

1. Reads the high and critical findings of the latest scheduled run (`~/.segurata/out`),
   leaving out accepted ones.
2. Runs `segurata inventory --out ~/.segurata/out <connectors>`. Without
   `--connectors`, every installed connector except those whose `describe` needs `cdp`: the browser
   is rarely running with its debugging port when the agent fires.
3. Posts one macOS notification (`osascript -e 'display notification …'`) naming up to three new
   high or critical findings by title. Titles never carry secrets; evidence is never shown. Each
   is also written to the log.
4. Runs `segurata report --format md --out ~/.segurata/last-report.md --dir
   ~/.segurata/out`.

Scheduled inventories live apart from the interactive `out/`; `segurata remediate --out
~/.segurata/out --list` works from them.

On Linux `install` prints the equivalent systemd user service and timer
(`~/.config/systemd/user/segurata-inventory.{service,timer}`) and the `systemctl --user` commands
to enable them; `--apply` is refused there, and new findings go to the journal instead of a
notification.

## Doctor

```
segurata doctor [--connector name|name:label] [--out out]
```

`internal/doctor`, read-only. Prints one line per check, `OK`, `WARN` or `FAIL`, each `WARN` and
`FAIL` with the exact fix, then the counts; exits 1 when anything failed. `--connector` checks one
connector or instance (the config and state are always checked).

- Config: the file is found and valid; a key that names no connector is a warning.
- Secret references: every reference of every selected instance is resolved through
  `run.NewRequest`, the path an inventory takes, and reported by key and reference; the values are
  only handed to the connector's own check, never printed. Whether a Keychain item's ACL would
  prompt cannot be read without prompting, so it is not checked.
- Browser: when a selected connector needs `cdp`, `cdp_url` must answer `/json/version`
  (`cdp.ReadVersion`, the first half of `cdp.Connect`). The OK line restates the accepted-risk
  tradeoff of an open debugging port.
- Connectors: a built-in connector implementing the optional `connector.Doctor` checks its own
  prerequisites through the same runners, allowlists and classifiers its inventory uses. For any
  other connector (externals included) the core checks the `describe` needs: `cli:x` on `PATH`
  (`(optional)` makes a miss a warning), `secret:X` configured (a warning when not: the connector
  is skipped, not broken). `os:` needs are checked for every connector.

| Connector | Checks |
|---|---|
| `gcp` | gcloud found as the inventory finds it (`gcloud_path`, `PATH`, SDK folders); `auth list`; per account `projects list --limit=1`, so an expired token fails with `gcloud auth login <account>` |
| `workspace` | Per tenant: the token is obtained as the inventory does (secret, or gcloud with the tenant's `CLOUDSDK_CONFIG`) and checked with tokeninfo for scopes and domain; the token is discarded |
| `aws` | `sts get-caller-identity` per profile; SSO, static-key and missing-credential failures get different fixes |
| `azure` | `az account show` |
| `cloudflare` | `GET /user/tokens/verify` (status and expiry), then one page of tokens, accounts and zones and the first zone's SSL setting and DNSSEC, each failure naming the permission group to add |
| `connected-apps` | `gh auth status --json hosts` (JSON, never the token; the one gh command added to its allowlist); scopes the key lists need (`admin:public_key`, `admin:ssh_signing_key`, `admin:gpg_key`, from `ghKeyEndpoints`) |
| `macos` | `dscl` lists the local users; `tmutil destinationinfo -X` and the Time Machine preferences are readable (a warning with the Full Disk Access fix otherwise) |
| `local-secrets` | rg, gitleaks (optional; not needed with `skip_git_history`), git and ssh-keygen on `PATH`; `rg --version` and `gitleaks version` (added to the gitleaks guard) |

- State: the fingerprint key exists (a warning before the first `local-secrets` run), is a valid
  key and has mode 0600; `tracker.json` loads and has mode 0600 when present; a former
  `rotations.json` or `accepted.json` still in place is a warning (not imported yet); the tracker
  folder and the output directory (`--out`) have mode 0700 (a warning otherwise, since their files
  are 0600).

## External connector protocol (v1, v2)

An external connector is a `segurata-<name>` executable on `PATH`, in any language, discovered
at start (`connector.Discover`) and wrapped in the `connector.Connector` interface
(`connector.External`). It answers `describe` with a JSON object and `inventory` with JSON Lines
records, reading one JSON request (protocol, config, resolved secrets, CDP address) on stdin.
Protocol 2 adds `plan` and `apply` for remediation. The core speaks both versions and sends each
connector the version it declared, so a version 1 connector keeps working unchanged. Full protocol
with examples: [connectors.md](connectors.md#external-connector-protocol).

## Secrets used by connectors

Admin keys (OpenAI, Anthropic, OpenRouter, Vercel, Supabase, Cloudflare…) do not live in plain files. The
config says where each one is; the core resolves it on the fly and passes it to the connector in
the request, without writing it to disk. A literal value in the config is rejected.

| Reference | Resolved with |
|---|---|
| `env:NAME` | Environment variable |
| `keychain:service` | `security find-generic-password -s service -w` (macOS Keychain) |
| `op://vault/item/field` | `op read` (1Password CLI) |

Config at `~/.config/segurata/config.json` (override with `SEGURATA_CONFIG`):

```json
{
  "cdp_url": "http://127.0.0.1:9222",
  "connectors": {
    "openai": {"secrets": {"OPENAI_ADMIN_KEY": "keychain:segurata-openai-admin"}},
    "gcp": {"config": {"projects": ["my-project"]}}
  }
}
```

### Several accounts of one provider

A config key `name` is the connector's unnamed instance; `name:label` adds a labelled one, with
its own config and secrets. Each instance runs separately, writes `out/<date>/<name>-<label>.jsonl`,
and stamps `"instance": "<label>"` on its records (part of the finding id). On the command line,
`name` selects every instance and `name:label` just one.

```json
"openrouter:work":     {"secrets": {"OPENROUTER_MANAGEMENT_KEY": "keychain:segurata-openrouter-work"}},
"openrouter:personal": {"secrets": {"OPENROUTER_MANAGEMENT_KEY": "keychain:segurata-openrouter-personal"}}
```

## v0 connectors

| Connector | How it looks | What it looks for |
|---|---|---|
| `google-personal` | CDP over the signed-in browser | Linked apps, scopes, dates, accounts that need a fresh sign-in |
| `connected-apps` | CDP over the signed-in browser, `gh api` | Apps connected to GitHub (OAuth apps with scopes and organization access, GitHub Apps, sessions, SSH/signing/GPG keys), X, Slack (every signed-in workspace), Notion (developer connections), Facebook (first page of Apps and websites), Instagram and LinkedIn (empty list verified only), Microsoft and Dropbox (session check only). `services` in the config selects some; one instance per service is allowed |
| `local-secrets` | `rg`, `gitleaks`, `git`, `ssh-keygen`, `gh` (optional) | Plaintext secrets in config and `.env` files, shell histories, logs, agent transcripts and git history; database dumps committed to git, one finding per file; SSH keys without a passphrase; HMAC fingerprints so one secret is recognised in every place it appears |
| `github` | `gh api`, GET on allowlisted paths | Account 2FA; organizations you own: 2FA requirement and members or outside collaborators without it, base permission, public repository creation, Actions (allowed actions, default workflow token, PR approval), code security defaults for new repositories; repositories you administer: insecure webhooks, write deploy keys, secret scanning and push protection, write workflow token on public repositories, Dependabot security updates, optional default-branch protection. Missing scopes are `noscope` with the `gh auth refresh` command |
| `gcp` | `gcloud` CLI | Unrestricted API keys, service-account keys and their age, service accounts with broad roles, billing budgets and alerts, local ADC credentials and their scopes |
| `aws` | `aws` CLI | Root keys or no root MFA, old or unused access keys, budgets |
| `azure` | `az` CLI | Budgets, app registration secrets that never expire or expire soon |
| `openai` | Admin API | Keys, last use, projects, limits and spend |
| `anthropic` | Admin API | Keys, last use, workspaces, limits and spend |
| `openrouter` | API | Keys, per-key credit limit, spend |
| `vercel` | API | Tokens, spend management |
| `supabase` | Management API | Projects, service keys, spend cap |
| `cloudflare` | API, read-only user token | User API tokens (no expiry, idle, edit without an IP filter, edit on all zones or accounts), Global API Key reminder, account 2FA enforcement, members without 2FA, super administrators, per zone SSL mode, Always Use HTTPS, minimum TLS and DNSSEC. One instance per login |
| `macos` | macOS tools, read-only and without sudo | FileVault, SIP, Gatekeeper, firewall and stealth mode, update settings and pending updates, screen lock, automatic login, guest account, home folder readable by other accounts, local accounts other than yours (admin, home folder, last login), items owned by deleted accounts' UIDs in shared folders and launchd folders, Time Machine (no destination, unencrypted destination, latest backup age), endpoint agents and their leftovers, TCP ports reachable from the network, SMB share points (guest access, orphaned records), login and background items, Brave's remote debugging port. Remediates the firewall, stealth mode, share points (remove a record, turn guest access off) and the home folder mode |
| `workspace` | Admin SDK, token from a per-tenant gcloud config | One instance per tenant: accounts without 2SV enrolled or enforced, admins (super admins used day to day), suspended or inactive accounts, third-party apps with OAuth grants ranked by scope and users, token authorizations and revocations over 30 days |
| `browser-extensions` | Brave and Chrome profile files, read-only, no network | Every extension in every profile: capabilities, source, install and update dates, category hint, and a `remove`/`review`/`keep` verdict with reasons (README, "Browser extensions"). Not automatable; each finding links the extension's page in the browser. Web Store lookups (pulled extensions, new owners) are a future enhancement |

`browser-extensions` is its own connector rather than part of `macos`: it reads browser data, not
OS settings, the same files exist on Linux, and the triage compares extensions across all profiles
of a browser at once (duplicates, one finding per extension).

Every connector is written in Go. The Node prototypes (`google/`, `connected-apps/`, `workspace/`,
`secrets/`, `macos/`) were deleted once their connectors matched them on a live run.

## Incremental git history scan

gitleaks over every repository under `repos_root` is most of a `local-secrets` run (about 30
minutes for ~330 repositories). History only grows, so each repository is scanned in full once and
then only for the commits added since (`connectors/localsecrets/historycache.go`).

Cache: `~/.cache/segurata/gitleaks/<sha256(repo path)[:16]>.json`, mode 0600, one per
repository. It holds the repository path, the cache format version, a hash of the gitleaks
version and configuration (`GITLEAKS_CONFIG`, `GITLEAKS_CONFIG_TOML`, the repository's
`.gitleaks.toml` and `.gitleaksignore`), a probe fingerprint of the machine key, the tips (every
commit a ref or HEAD pointed to, from `git rev-list --no-walk --all`) and the leaks found, as
prepared evidence: fingerprint, redacted hint, path, line, commit. The evidence is cached after
the check that it does not contain the value, so the cache never holds one.

Each run:

1. Lists the current tips.
2. Loads the cache. A different format, repository, gitleaks version or configuration, or
   fingerprint key (the probe differs) discards it.
3. Checks that every old tip is still reachable from a current one: `git rev-list -n 1 <old tips>
   --not <current tips>` must print nothing. A rewritten or deleted ref fails the check (its
   commits, and their leaks, may be gone), and so does an old tip whose object no longer exists:
   gitleaks itself would scan nothing and exit 0 on a bad object.
4. Passing the check, it scans `gitleaks git --log-opts "--full-history <new tips> --not <old
   tips>"`, exactly the commits no earlier run saw, or nothing when no tip is new. Failing it, it
   scans `--full-history <current tips>` in full. Tips are passed explicitly rather than with
   gitleaks' default `--all`, so the cache records exactly what was scanned. A tip list longer
   than 256 KiB falls back to gitleaks' default.
5. Replays the cached leaks plus the new ones, recomputing what can change without a new commit:
   whether the repository has a remote, and whether a cached JWT has expired since.

`git_cache: false` in the connector config turns it off: every repository is scanned in full and
the cache is neither read nor written. A cache that cannot be written is logged and costs the next
run a full scan, nothing more. The connector runs only `git rev-list`, `git ls-files`, `git log`
with a fixed set of listing flags, `git cat-file -s` and `git cat-file blob` (the data-dump check
below), `gitleaks git` and `gitleaks version`, and `gh repo view <owner/name> --json visibility`,
each on an allowlist (`guards.go`).

## Data dumps in git

A database dump committed to a repository is reported once per file, as an `exposure` finding of
resource type `data_dump`, rather than as the thousands of gitleaks matches its hash columns
produce (`connectors/localsecrets/datadump.go`, `dumpscan.go`). It runs inside `local-secrets`, not
as a separate connector: it needs the same repository discovery, git runner, guards and tips, and
its results change how the gitleaks matches of the same run are judged.

For each repository under `repos_root`:

1. Candidates by name: every path in the index (`git ls-files -s -z`) and every path ever added
   (`git log --all --no-renames --diff-filter=A --name-only --format= -z`) whose name looks like a
   dump: `*.sql`, `*.sql.gz|zip|bz2|xz`, `*.dump`, `*.pgdump`, `*.sqlite`, `*.sqlite3`, `*.db`,
   `*.bak` with a database word, and `.csv`/`.json`/`.xlsx` with `prod`, `production`, `backup` or
   `dump` in the name (those only above 1 MiB). Never: names containing `schema`, `structure` or
   `seed`, migration folders (`migrations`, `migrate`, `drizzle`, `flyway`, `alembic`,
   `liquibase`), vendored code (`vendor`, `third_party`, `node_modules`), `Thumbs.db`. Under test
   folders (`test`, `spec`, `fixtures`, `testdata`…) a file must exceed 1 MiB. The test and vendor
   folders are those of `secretrisk.RoleOf`, the classifier secrets use too.
2. History of the candidates: `git log --all --full-history --no-renames --diff-filter=AM --raw
   --no-abbrev -- :(literal)<path>…` gives every blob id and the commit that first added each
   path. `--full-history` matters: a dump added and deleted on a merged branch is otherwise
   simplified away. `git log --remotes …` says whether a remote-tracking ref holds the addition.
3. Size: the largest blob of the path (`git cat-file -s`, at most the 32 newest versions); files of
   4 KiB or less are dropped.
4. Content: the first 4 KiB of one blob (the current one if tracked, else the largest), read by
   `git cat-file blob` through a reader that stops git after 4 KiB, never more. gzip is inflated
   as far as those bytes go and UTF-16 is read as ASCII. Headers: `PGDMP`, `SQLite format 3`,
   mysqldump and pg_dump banners (`data`), `INSERT INTO` / `COPY … FROM stdin` (`rows`), `CREATE
   TABLE` (`schema`).
5. Visibility: for a repository with a GitHub remote and at least one hit, `gh repo view
   <owner/name> --json visibility`, cached for 7 days. No gh, no GitHub remote or no access: unknown.

Severity. A file is a real dump when it has a production or backup name (or folder), a `data`
header, `rows` in a file of 64 KiB or more, or `schema` in a file of 1 MiB or more. A real dump in
a repository with a remote is `critical` when the remote is public and `high` otherwise; a local
one is `medium`. Other candidates are `medium` (remote) or `low` above 1 MiB, and `info` below.
The title says whether the addition is on a remote branch ("pushed") or only in a repository that
has a remote.

gitleaks matches inside a detected dump get `in_data_dump: true` and `secretrisk.ImpactOf` makes
them noise, so the rotation ledger skips them; the dump finding counts them in
`gitleaks_matches`. AWS access keys, Stripe live keys, GitHub and GitLab tokens and private keys
keep their impact: those are more often the owner's own credentials than a column of user data.

Cache: `~/.cache/segurata/datadumps/<sha256(repo path)[:16]>.json`, mode 0600, beside the
gitleaks cache and named the same way. It holds the tips the history was read at (the same
`git rev-list --no-walk --all` as the gitleaks cache), the candidates' history facts, sizes and
header classes by blob id, and the visibility. With unchanged tips a repository costs one
`rev-list` and one `ls-files`; with new tips the history is read again but known blobs are neither
sized nor read again. Never any content beyond the header class.

`data_dumps` in the connector config: `true` (default), `false`, or `"only"` to run just this
check (with `skip_git_history: true`, no rg, gitleaks or ssh-keygen pass runs).

## Rotation ledger

`segurata rotations` turns `local-secrets` findings into a list of secrets to rotate, one item per
fingerprint. The items are the tracker's rotate items (`internal/tracker/secret.go`: folding,
priority, reopen rules); `internal/rotation` is the command family on top (list, next, show,
replace, done, snooze, ignore, reopen). The risk model it shares with the connector lives in
`internal/secretrisk`, so a finding's severity and an item's priority never disagree.

State: in the tracker (see "Tracker"); the former `~/.segurata/rotations.json` is
imported once. A rotate item holds redacted hints and fingerprints, never values. Its status is the
tracker's (`done` reads "rotated" in these commands):

```json
{"id": "T-0007", "key": "rotate:3f9a12c4…", "kind": "rotate", "theme": "rotations",
 "title": "Stripe live secret key sk_live_…a1b2(107) in ~/src/shop/.env", "status": "open", "priority": "P0", "severity": "critical",
 "fingerprint": "3f9a12c4…(16 hex)",
 "secret": {"id": "3f9a12c4", "service": "stripe", "type": "stripe-live", "redacted": "sk_live_…a1b2(107)",
   "impact": "high", "reasons": ["Stripe live secret key; pasted into an agent transcript, so it reached the model provider"],
   "first_seen": "…", "last_seen": "…",
   "locations": [{"path": "~/src/shop/.env", "line": 3, "bucket": "3-local", "tracked": false, "mode": "600",
                  "source": "scan", "kind": "repo", "last_seen": "…"}],
   "used_in": ["~/src/shop/.env"], "rotate_url": "https://dashboard.stripe.com/apikeys"},
 "next": {"who": "you", "action": "Rotate it at https://dashboard.stripe.com/apikeys and copy the new value; segurata puts it in 1 file.",
          "command": "segurata rotations replace 3f9a12c4", "url": "https://dashboard.stripe.com/apikeys"},
 "history": [{"at": "…", "event": "found", "action": "found", "detail": "found in 2 places"}]}
```

Priority is impact × exposure, both table-driven:

| Impact | Local (0600 file, history, log) | Shared (readable by others, local repo history) | Remote (pushed git history, agent transcript) |
|---|---|---|---|
| High: Stripe live keys, AWS keys, GCP service-account keys, private and SSH keys, GitHub/GitLab tokens, Google refresh tokens and OAuth client secrets, Cloudflare tokens | P2 | P1 | P0 |
| Medium: AI provider keys (Anthropic, OpenAI, xAI, OpenRouter…), Notion, Slack, SendGrid, npm, Telegram, Stripe webhook secrets, passwords in URLs | P3 | P2 | P1 |
| Low: Sentry DSNs, Google API keys, Stripe test keys, JWTs of unknown origin | P3 | P3 | P2 |

- Exposure is the worst location of the secret. An agent transcript counts as remote: whatever
  was pasted there was sent to the model provider.
- Noise is left out by default: generic `NAME=value` matches, gitleaks `generic-api-key`, anon or
  expired JWTs, encrypted private keys and the cases below. `sync --include-noise` tracks them
  without a priority, but the connector emits noise only with `emit_noise: true`.
- `sync` merges locations (never drops one: git history and transcripts do not forget) and
  refreshes `last_seen` only for secrets it saw. Expired snoozes go back to `open`.
- After a real rotation the old value is revoked, so only a working file that still holds it
  matters. `done` and `replace` record the locations known at that moment (`rotated_locations`).
  A `rotated` item seen again is reopened, with the reason "still present after rotation (old
  value still in a working file)", only when a sighting is in a working file (config, `.env`, rc
  or repo working tree; the kinds that feed `used_in`), whether known at rotation time (the new
  value never reached it) or new since; the history note says which. Copies only in git history,
  transcripts, logs or shell history leave it `rotated` and add one `history-only` note per
  rotation ([docs/secrets.md](secrets.md#after-a-rotation)).
- `used_in` lists the working files (config, `.env`, rc files) that hold the secret: where the new
  value has to go once it is rotated.
- `rotate_url` is the provider console page for that kind of secret, checked against each
  provider's documentation. Types without a stable, account-independent page (npm tokens, Shopify,
  private keys) have none.
- `secret.id` is the first 8 characters of the fingerprint, longer on collision. Commands accept
  any unique prefix of it or of the fingerprint, or the tracker's `T-` id.
- `done`, `snooze`, `ignore` and `reopen` also take `--path <prefix>` instead of an id: every item
  whose locations all lie under that path. A test log or a data file full of fixtures goes away in
  one command, while a secret that also appears elsewhere stays.

### What counts against the owner

`secretrisk.ImpactOf` adjusts a copy's impact by where it is, and the connector adds the facts it
needs to the evidence. Every rule is a pure function of the evidence, so the finding's severity,
the rotate item's priority and `segurata redact` agree, and cached git history is re-judged on
every run without a new scan.

- Repository origin (`origin`). From each repository's GitHub remotes, origin first, and the
  owner's names: `owned_owners` in the config plus the login and organizations from `gh api user`
  and `gh api user/orgs?per_page=100`, asked once a week and cached in
  `~/.cache/segurata/github-owners.json` (both calls are on the gh guard's allowlist). `owned`
  when origin's owner is one of them, `third-party` otherwise (a clone of instructure/canvas-lms).
  A copy committed to a third-party repository is noise and its spot is local: the upstream's
  secret. An owned repository with another remote whose owner is not the user is a fork: commits
  reachable from that remote's branches (`git rev-list <leak commits> --not --remotes=<upstream>`)
  are `fork-upstream`, judged like third-party, and so is the working copy of the same value at
  the same path. Limits: a repository without a GitHub remote, or every repository when neither gh
  nor `owned_owners` names anyone, has no origin and counts as the owner's; a fork's inherited
  history is recognised only when its upstream remote has fetched branches.
- Reused (`reused`). A third-party or inherited copy of a value that also sits in one of the
  owner's own files (config, `.env`, a working file or commit of an owned repository) is the
  owner's secret leaked into someone else's repository, and counts in full. Transcripts, logs and
  histories do not make a value the owner's: an agent that read a third-party file leaves its
  value there.
- Paths (`secretrisk.RoleOf`, repository files only). Checksum lists (`*.md5`, `*.sha1`,
  `*.sha256`, `*.sha512`, `*.sum`) and lockfiles are noise. Test folders and files (`test`, `spec`,
  `fixtures`, `__tests__`, `cassettes`, `*_test.*`, `*.test.*`, `*.spec.*`, `test_*`), examples
  (`examples`, `samples`, `demo`, `*.example`, `*.sample`, `*.template`, `*.dist`), documentation
  (`docs`, `README*`, `*.md`) and vendored code lower the impact one level, to noise when the value
  reads like test data (`sample`: "test", "fake", "demo", "1234", "abcd", a run of four equal
  characters). The sample flag needs the value, so git history cached before it existed is judged
  by path alone until its repository is scanned in full again.
- segurata's own repositories (a `go.mod` declaring `github.com/segurata/segurata`, worktrees
  included) are not scanned for secrets: their test corpus is synthetic. The status line counts
  what was skipped.
- AWS temporary credentials (`ASIA…`) live 36 hours at most: one whose commit date (end of that
  day) or file modification time is older is expired (`public`, note "expired"). Pre-signed URLs
  (`X-Amz-Credential=` or `AWSAccessKeyId=` before the key id) are their own type, low impact, and
  the temporary keys and pre-signed URLs of one file collapse into one finding counting them all.
- URL credentials (`url-credentials`, `url-token-param`) are judged by host, written into the
  note (`postgresql://…@host`, `https://host/…?access_token=…`): localhost, loopback, `example.*`,
  `.local`, `.test`, `.invalid` are noise; private, CGNAT and link-local addresses, single-label
  names, `.internal` and `.lan` are low; public hosts keep medium, high for managed databases
  (Neon, Supabase, RDS, MongoDB Atlas, Upstash, PlanetScale, Railway) or a `prod`, `production`,
  `prd` or `live` label. ripgrep prints only the match, so the line of a query-string token is read
  back from its file to find the URL it belongs to.
- Jupyter notebooks: only cell source counts. A match on a line of the notebook's JSON that holds
  no source text (outputs, metadata, attachments) is dropped; history reads the notebook as
  committed (`git cat-file blob <commit>:<path>`).
- Public OAuth clients: the client secrets of gcloud (`CLOUDSDK_CLIENT_NOTSOSECRET`) and of
  `gcloud auth application-default login` are published in its source; they are recognised by
  their first seven and last four characters and length, and are noise. The refresh token beside
  them is not. `~/.config/gcloud/logs` is not scanned.
- Bare 40-hex values matched by gitleaks' `sourcegraph-access-token` without the `sgp_` prefix
  are noise. gitleaks 8.30 has no other rule that takes a bare hex value: `facebook-secret` and
  `codecov-access-token` require the provider's name next to the value.
- Noise is counted, not emitted, unless `emit_noise: true`: the run's status line ends with
  `noise not emitted …: N; by type: …; by place: …` (the 25 largest places, the rest summed).

Hints. Every value hint the connector writes is `secretrisk.Redact`'s: the known prefix, `…`, the
last four characters when the value is long and random, and the length, `sk_live_…a1b2(107)`;
`secretrisk.ParseHint` reads it back. Keys and whole files have no value hint (`PEM`, empty).

Titles. A rotate item is named `<label> <hint> in <repo>:<file> (+N places), committed YYYY-MM`:
the location that exposed it most (among equals the owner's repository, then the latest commit),
the number of other locations, and the earliest commit date. Within a priority and exposure, items
with a copy in an owned repository and with more recent commits come first.

### Guided rotation: `next` and `replace`

- `next [--priority P0] [--service x]` prints the first active item in list order with its
  reasons, locations (worst first, eight at most), `rotate_url`, the service's rotation guide,
  `used_in` with the recorded line, and the commands to run next. Guides live in
  `internal/secretrisk/guides.go`: two to four steps per type, each citing the provider page it
  was checked against.
- `replace <id>` never stores, prints or passes the new value as an argument. It reads it from
  `pbpaste` or a pipe (`--stdin` refuses a terminal, which would echo it). A value must be one
  line of `[A-Za-z0-9._~+/=:@%-]`, so it can go unquoted into a shell, `.env` or JSON line;
  anything else is edited by hand.
- Locating the old value without having it: the redacted hint gives its length, prefix and last
  four characters (`secretrisk.ParseHint`), so every window of the line that fits is HMAC'd with
  the fingerprint key (`internal/fingerprint`) and compared with the item's fingerprint. The
  recorded line must still hold it, or the file changed since the scan and `replace` refuses.
  Other lines of the same file that hold it are replaced too. Types that are not one value on
  one line (PEM keys, service-account files, keystores) are refused.
- The new value's fingerprint must differ from the item's: a clipboard still holding the old key
  is refused.
- `--apply` confirms like `remediate` (a terminal on stdin, or `--yes`), re-reads each file and
  refuses one that changed since the plan, writes it with `statefile.Replace` (temporary file,
  fsync, rename; mode kept; a symlink's target is written, the link stays), then re-reads every
  file: the old fingerprint must be gone from all of it and each edited line must hold the new
  value. Only then is the item marked `rotated` and the clipboard cleared (`pbcopy` with empty
  stdin).
- `--to-keychain <service>`: for shell rc files whose line is a plain `[export ]NAME=value`, the
  value is stored with `security -i` reading `add-generic-password -U -a $USER -s <service> -w
  <value>` from stdin (no argument list carries it), read back with `find-generic-password -w`
  and compared by fingerprint before any file changes; the line becomes
  `export NAME="$(security find-generic-password -a "$USER" -s <service> -w)"`.
- `--backup` keeps a 0600 copy of each file as it was. It is off by default because the copy
  holds the old value in plaintext.
- History: `next` (once per run of consecutive calls), `replace-plan` (dry run),
  `replace-failed` (with what was already written), `done` (with the files and Keychain service).

## Redaction

```
segurata redact --trails                       dry run: files, matches per file and per type, bytes
segurata redact --path ~/.claude/projects/-src-shop
segurata redact --item 3f9a12c4                one rotation item's secret, in every trail
segurata redact --trails --min-priority P1 --apply [--yes] [--backup]
```

A remediation that rewrites local trail files (`internal/redact`). Transcripts, shell histories
and logs keep secrets in plaintext long after they were pasted. Those copies already went
wherever they went (a transcript reached the model provider), so rotation is still required;
redaction removes the copy that stays on disk, in backups and in sync tools.

- Scope: `--trails` is every trail `local-secrets` scans (its history, log and transcript ripgrep
  passes); `--path` narrows to trail files under a prefix; `--item` takes only that ledger item's
  secret. `--min-priority` uses the item's priority when the ledger knows the secret, otherwise
  that copy's. A working file (config, `.env`, rc, repo working tree) is never touched, whatever
  the scope: a program still reads its value.
- Matching is `local-secrets`' own (`localsecrets.Trails`): ripgrep with the same passes finds
  the candidate lines, and the same patterns, classification and judgement, joined into one
  leftmost-first alternation as ripgrep joins several `-e`, place each secret on its line. Go's
  regexp has no DFA and runs that alternation at about 2 MB/s, so `matcher.go` produces the same
  matches another way: each pattern's syntax tree gives literals every match contains at a
  bounded offset from its start; one pass finds them and each pattern is tried alone, anchored,
  where they allow, in the order the alternation would pick. Texts it cannot handle that way go
  through the alternation of the patterns whose literals occur. Tests and a fuzz target check
  both give identical spans. Files are planned in parallel. A value is replaced only if an
  inventory would report it as non-noise (`--include-noise` adds generic `assignment` matches,
  public, expired and encrypted values). Each becomes `[REDACTED:<type>:<fingerprint8>]`, so the
  copy still points at its rotation item.
- Plain lines (shell history, logs) change only in the secret's bytes, which keeps zsh's
  `: <ts>:<d>;cmd` format. A line that is valid JSON is edited inside its strings: where the
  secret stands byte for byte inside one string, and only when the bytes before, the secret and
  the bytes after are each whole string content (no escape cut in two, no quote crossed); then,
  for strings that hold escapes, in the decoded value, re-encoding that one string. Field order
  and every other byte are kept, each rewritten line must parse, and a whole file that was valid
  JSON must stay so. A match that cannot be replaced this way stays and is counted.
- Safety: files modified within `--min-age` (default 2h) and any file a running `claude` or
  `codex` process has open (`lsof -Fn -c claude -c codex`, read-only; if lsof fails the command
  refuses) are left alone, as are symlinks and files of another account. `--apply` confirms like
  `remediate`, then, per file, checks the guards again, refuses a file whose size or modification
  time changed since the plan, writes with `statefile.Replace` (mode kept) and puts the
  modification time back, so tools that sort sessions by date are not confused.
- After applying, ripgrep scans the rewritten files again: no secret in scope may remain beyond
  what the plan said would stay, and mode and modification time must be unchanged. Each rotation
  item whose secret was replaced gets a history note, "redacted from N trail files". Its
  locations stay: the copies were exposed before they were cleaned.
- No backup by default: a backup is one more plaintext copy. `--backup` keeps a 0600 copy next to
  each file and says so loudly.

## Why Go, and why so few dependencies

- One static binary for macOS, Linux and Windows, no runtime to install.
- A security tool with a hundred dependencies is a supply-chain risk in itself. The core uses only
  the standard library (including a minimal WebSocket client for CDP). Cloud connectors call the
  official CLIs (`gcloud`, `aws`, `az`), already authenticated on the machine, instead of
  vendoring their SDKs.
- Any new dependency goes through a 4-day quarantine and is pinned to an exact version.

## Prior art

Prowler and ScoutSuite already audit AWS, Azure and GCP security posture in depth. When that depth
is needed they get wrapped as external connectors rather than rewritten. segurata covers what they
don't: consumer accounts, personal OAuth grants, AI-provider keys and spend, and local secrets.
