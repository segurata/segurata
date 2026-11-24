# Architecture

securizame inventories the digital footprint of a person or a small company (consumer accounts,
clouds, AI providers, secrets on disk), assesses it and, only when asked, cleans it up.

Everything in this repository is written in English: code, comments, finding text, docs and commit
messages.

## Pieces

```
securizame (Go binary)
├── core: config, secret references, connector execution, output, report
├── built-in connectors (compiled in)
└── external connectors: securizame-<name> executables on PATH, in any language
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
| `accept` / `unaccept` | Marks a finding as a risk kept on purpose, or stops doing so | Only securizame's own `accepted.json` |
| `doctor` | Checks prerequisites: config, secret references, browser port, CLIs and sign-ins, state file modes | Never |
| `rotations` | Keeps the ledger of secrets to rotate and guides each rotation | Only securizame's own `rotations.json`, except `replace --apply`: the `used_in` files and the Keychain, after confirmation |
| `report` | Summarises the latest runs, what changed, the ledger and the accepted risks | Never (writes only the `--out` file) |

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

## Remediation

```
securizame remediate --list                      automatable findings of the latest run
securizame remediate <finding-id>                print the plan; changes nothing
securizame remediate <finding-id> --apply        print the plan, ask "Apply? [y/N]", apply, check
securizame remediate <finding-id> --apply --yes  same without asking
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
  and stderr attached, so sudo asks for the password itself. securizame never reads, stores or
  pipes a password.
- Generic actions belong to the core, so any connector can attach them. `file.chmod600` takes the
  file in `evidence.path` (absolute or `~/`), refuses symlinks and non-regular files, and changes the
  mode in-process; the undo is `chmod <old mode> <path>`.
- An external connector remediates through protocol 2: it declares its actions in `describe`
  (`remediates`), returns a plan from `securizame-<name> plan` and runs it in
  `securizame-<name> apply` (`remediate.External`). The core shows the plan and confirms as for a
  built-in, asks for the plan again before applying and refuses one that differs, and refuses any
  plan that needs sudo: a plugin's command line is never on the hand-written allowlist, so the core
  cannot vet it and will not run it as root. The plugin runs its plan as the owner; the allowlist
  binds built-in actions only. Details: [connectors.md](connectors.md#plan-v2).

## Accepted risks

```
securizame accept <finding-id> --reason "..." [--until YYYY-MM-DD]
securizame accept --list
securizame unaccept <finding-id>
```

Some findings describe a risk the owner keeps on purpose (Brave's remote debugging port, which
local AI agents drive). `accept` looks the finding up in the latest run (a unique id prefix is
enough) and stores it in `~/.config/securizame/accepted.json`, mode 0600 (`SECURIZAME_ACCEPTED`
names another file, `internal/accept`):

```json
{"version": 1, "entries": [{"id": "5c7ae3818002130e", "connector": "macos",
  "title": "Brave runs with a remote debugging port: …", "reason": "AI agents drive Brave",
  "accepted_at": "2026-11-24T00:39:00Z", "until": "2027-03-31"}]}
```

- The core stamps every finding of an inventory with `"accepted": {"reason", "accepted_at",
  "until", "expired"}` when the file holds its id. The finding stays in the JSONL; the summary
  and `remediate --list` leave it out and say "N accepted findings hidden; see securizame accept
  --list". `remediate` re-reads the file, so an acceptance made after the run counts.
- `until` is the last day it applies. After it the finding shows again, its title followed by
  "(acceptance expired)".
- This only works with stable ids: a finding id hashes connector, account, resource type and
  resource id, so a resource id must not hold anything that changes between runs (a pid, a port).
  The debugging-port finding's resource id is `brave-remote-debugging`, whatever port Brave uses.
- A broken file is an error, never an empty list: a typo must not unhide or hide anything silently.

## Report

`securizame report [--format text|md|html] [--out file]` (`internal/report`) reads, and never
changes:

- the latest run of every connector instance, through `remediate.LatestFiles` and
  `remediate.ReadRun` (findings and statuses);
- for each, its previous run: `remediate.PreviousFile`, the same file name in the newest earlier
  `out/<date>/` folder;
- the accepted-risks file, which annotates every finding as `inventory` does, so an acceptance
  made after the run counts and an expired one shows again;
- the rotation ledger.

The diff is by finding id: an id only in the latest file is new, one only in the previous file is
resolved, one in both with another severity changed. That is why ids must stay stable (see
"Accepted risks"). Runs compare per connector instance, because each connector runs on its own
schedule.

The report is built once as a small document (headings, paragraphs, lists, tables) and rendered as
text, Markdown or HTML, so the three formats carry the same content. Markdown escapes markup in
titles; HTML escapes everything, links only absolute http(s) URLs, has no script, loads nothing
(its CSP is `default-src 'none'`) and switches colours with `prefers-color-scheme`. `--out` writes
atomically with mode 0600 (`statefile.Write`).

What it shows of the ledger is the item id, service, type, redacted hint, worst exposure, first
reason and rotate URL; never a location path. Findings never hold a value, so neither does the
report.

## Scheduled runs

```
securizame schedule install [--every 24h] [--connectors a,b] [--apply [--yes]]
securizame schedule uninstall [--apply [--yes]]
securizame schedule status
securizame schedule run [--connectors a,b]        what the agent executes
```

`internal/schedule`. On macOS, `install` builds a launchd user agent,
`~/Library/LaunchAgents/com.securizame.inventory.plist`, that runs `securizame schedule run` every
`--every` (default 24h, at least 1h; `StartInterval`, not at load) from
`~/.local/state/securizame`, with the PATH of the shell that installed it and its output in
`~/Library/Logs/securizame/`. Without `--apply` it prints the plist and the
`launchctl bootstrap gui/<uid> <plist>` command and changes nothing; with `--apply` it asks on the
terminal as `remediate` does (`--yes` skips it), writes the plist (mode 644), boots out an agent
already loaded and bootstraps the new one. `uninstall` boots it out and removes the plist, keeping
reports and logs. `install` refuses a binary under the temp directory (`go run`), which would be
gone by the first run.

One `schedule run`:

1. Reads the high and critical findings of the latest scheduled run (`~/.local/state/securizame/out`),
   leaving out accepted ones.
2. Runs `securizame inventory --out ~/.local/state/securizame/out <connectors>`. Without
   `--connectors`, every installed connector except those whose `describe` needs `cdp`: the browser
   is rarely running with its debugging port when the agent fires.
3. Posts one macOS notification (`osascript -e 'display notification …'`) naming up to three new
   high or critical findings by title. Titles never carry secrets; evidence is never shown. Each
   is also written to the log.
4. Runs `securizame report --format md --out ~/.local/state/securizame/last-report.md --dir
   ~/.local/state/securizame/out`.

Scheduled inventories live apart from the interactive `out/`; `securizame remediate --out
~/.local/state/securizame/out --list` works from them.

On Linux `install` prints the equivalent systemd user service and timer
(`~/.config/systemd/user/securizame-inventory.{service,timer}`) and the `systemctl --user` commands
to enable them; `--apply` is refused there, and new findings go to the journal instead of a
notification.

## Doctor

```
securizame doctor [--connector name|name:label] [--out out]
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
| `connected-apps` | `gh auth status --json hosts` (JSON, never the token; the one gh command added to its allowlist); scopes the key lists need (`admin:public_key`, `admin:ssh_signing_key`, `admin:gpg_key`, from `ghKeyEndpoints`) |
| `macos` | `dscl` lists the local users; `tmutil destinationinfo -X` and the Time Machine preferences are readable (a warning with the Full Disk Access fix otherwise) |
| `local-secrets` | rg, gitleaks (optional; not needed with `skip_git_history`), git and ssh-keygen on `PATH`; `rg --version` and `gitleaks version` (added to the gitleaks guard) |

- State: the fingerprint key exists (a warning before the first `local-secrets` run), is a valid
  key and has mode 0600; `rotations.json` and `accepted.json` load and have mode 0600 when present;
  the output directory (`--out`) has mode 0700 (a warning otherwise, since its files are 0600).

## External connector protocol (v1, v2)

An external connector is a `securizame-<name>` executable on `PATH`, in any language, discovered
at start (`connector.Discover`) and wrapped in the `connector.Connector` interface
(`connector.External`). It answers `describe` with a JSON object and `inventory` with JSON Lines
records, reading one JSON request (protocol, config, resolved secrets, CDP address) on stdin.
Protocol 2 adds `plan` and `apply` for remediation. The core speaks both versions and sends each
connector the version it declared, so a version 1 connector keeps working unchanged. Full protocol
with examples: [connectors.md](connectors.md#external-connector-protocol).

## Secrets used by connectors

Admin keys (OpenAI, Anthropic, OpenRouter, Vercel, Supabase…) do not live in plain files. The
config says where each one is; the core resolves it on the fly and passes it to the connector in
the request, without writing it to disk. A literal value in the config is rejected.

| Reference | Resolved with |
|---|---|
| `env:NAME` | Environment variable |
| `keychain:service` | `security find-generic-password -s service -w` (macOS Keychain) |
| `op://vault/item/field` | `op read` (1Password CLI) |

Config at `~/.config/securizame/config.json` (override with `SECURIZAME_CONFIG`):

```json
{
  "cdp_url": "http://127.0.0.1:9222",
  "connectors": {
    "openai": {"secrets": {"OPENAI_ADMIN_KEY": "keychain:securizame-openai-admin"}},
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
"openrouter:work":     {"secrets": {"OPENROUTER_MANAGEMENT_KEY": "keychain:securizame-openrouter-work"}},
"openrouter:personal": {"secrets": {"OPENROUTER_MANAGEMENT_KEY": "keychain:securizame-openrouter-personal"}}
```

## v0 connectors

| Connector | How it looks | What it looks for |
|---|---|---|
| `google-personal` | CDP over the signed-in browser | Linked apps, scopes, dates, accounts that need a fresh sign-in |
| `connected-apps` | CDP over the signed-in browser, `gh api` | Apps connected to GitHub (OAuth apps with scopes and organization access, GitHub Apps, sessions, SSH/signing/GPG keys), X, Slack (every signed-in workspace), Notion (developer connections), Facebook (first page of Apps and websites), Instagram and LinkedIn (empty list verified only), Microsoft and Dropbox (session check only). `services` in the config selects some; one instance per service is allowed |
| `local-secrets` | `rg`, `gitleaks`, `git`, `ssh-keygen` | Plaintext secrets in config and `.env` files, shell histories, logs, agent transcripts and git history; SSH keys without a passphrase; HMAC fingerprints so one secret is recognised in every place it appears |
| `github` | `gh api`, GET on allowlisted paths | Account 2FA; organizations you own: 2FA requirement and members or outside collaborators without it, base permission, public repository creation, Actions (allowed actions, default workflow token, PR approval), code security defaults for new repositories; repositories you administer: insecure webhooks, write deploy keys, secret scanning and push protection, write workflow token on public repositories, Dependabot security updates, optional default-branch protection. Missing scopes are `noscope` with the `gh auth refresh` command |
| `gcp` | `gcloud` CLI | Unrestricted API keys, service-account keys and their age, service accounts with broad roles, billing budgets and alerts, local ADC credentials and their scopes |
| `aws` | `aws` CLI | Root keys or no root MFA, old or unused access keys, budgets |
| `azure` | `az` CLI | Budgets, app registration secrets that never expire or expire soon |
| `openai` | Admin API | Keys, last use, projects, limits and spend |
| `anthropic` | Admin API | Keys, last use, workspaces, limits and spend |
| `openrouter` | API | Keys, per-key credit limit, spend |
| `vercel` | API | Tokens, spend management |
| `supabase` | Management API | Projects, service keys, spend cap |
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

Cache: `~/.cache/securizame/gitleaks/<sha256(repo path)[:16]>.json`, mode 0600, one per
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
run a full scan, nothing more. The connector runs only `git rev-list` and `git ls-files`, and
`gitleaks git` and `gitleaks version`, each on an allowlist (`guards.go`).

## Rotation ledger

`securizame rotations` turns `local-secrets` findings into a list of secrets to rotate, one item per
fingerprint (`internal/rotation`). The risk model it shares with the connector lives in
`internal/secretrisk`, so a finding's severity and an item's priority never disagree.

State: `~/.local/state/securizame/rotations.json`, mode 0600, outside the repository
(`SECURIZAME_STATE` names another directory). It holds redacted hints and fingerprints, never
values.

```json
{"id": "3f9a12c4", "fingerprint": "3f9a12c4…(16 hex)", "service": "stripe", "type": "stripe-live",
 "redacted": "sk_live_…a1b2(107)", "impact": "high", "priority": "P0",
 "reasons": ["Stripe live secret key; pasted into an agent transcript, so it reached the model provider"],
 "status": "open", "first_seen": "…", "last_seen": "…",
 "locations": [{"path": "~/src/shop/.env", "line": 3, "bucket": "3-local", "tracked": false, "mode": "600",
                "source": "scan", "kind": "repo", "last_seen": "…"}],
 "used_in": ["~/src/shop/.env"], "rotate_url": "https://dashboard.stripe.com/apikeys",
 "history": [{"at": "…", "action": "found", "note": "found in 2 places"}]}
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
  expired JWTs, encrypted private keys. `sync --include-noise` tracks them without a priority.
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
- `id` is the first 8 characters of the fingerprint, longer on collision. Commands accept any
  unique prefix of an id or a fingerprint.
- `done`, `snooze`, `ignore` and `reopen` also take `--path <prefix>` instead of an id: every item
  whose locations all lie under that path. A test log or a data file full of fixtures goes away in
  one command, while a secret that also appears elsewhere stays.

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

## Why Go, and why so few dependencies

- One static binary for macOS, Linux and Windows, no runtime to install.
- A security tool with a hundred dependencies is a supply-chain risk in itself. The core uses only
  the standard library (including a minimal WebSocket client for CDP). Cloud connectors call the
  official CLIs (`gcloud`, `aws`, `az`), already authenticated on the machine, instead of
  vendoring their SDKs.
- Any new dependency goes through a 4-day quarantine and is pinned to an exact version.

## Prior art

Prowler and ScoutSuite already audit AWS, Azure and GCP security posture in depth. When that depth
is needed they get wrapped as external connectors rather than rewritten. securizame covers what they
don't: consumer accounts, personal OAuth grants, AI-provider keys and spend, and local secrets.
