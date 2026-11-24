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
| `gcp` | `gcloud` CLI | Unrestricted API keys, service-account keys and their age, service accounts with broad roles, billing budgets and alerts, local ADC credentials and their scopes |
| `aws` | `aws` CLI | Root keys or no root MFA, old or unused access keys, budgets |
| `azure` | `az` CLI | Budgets, app registration secrets that never expire or expire soon |
| `openai` | Admin API | Keys, last use, projects, limits and spend |
| `anthropic` | Admin API | Keys, last use, workspaces, limits and spend |
| `openrouter` | API | Keys, per-key credit limit, spend |
| `vercel` | API | Tokens, spend management |
| `supabase` | Management API | Projects, service keys, spend cap |
| `macos` | macOS tools, read-only and without sudo | FileVault, SIP, Gatekeeper, firewall and stealth mode, update settings and pending updates, screen lock, automatic login, guest account, home folder readable by other accounts, TCP ports reachable from the network, SMB share points (guest access, orphaned records), login and background items, Brave's remote debugging port. Remediates the firewall, stealth mode, share points (remove a record, turn guest access off) and the home folder mode |
| `workspace` | Admin SDK, token from a per-tenant gcloud config | One instance per tenant: accounts without 2SV enrolled or enforced, admins (super admins used day to day), suspended or inactive accounts, third-party apps with OAuth grants ranked by scope and users, token authorizations and revocations over 30 days |
| `browser-extensions` | Brave and Chrome profile files, read-only, no network | Every extension in every profile: capabilities, source, install and update dates, category hint, and a `remove`/`review`/`keep` verdict with reasons (README, "Browser extensions"). Not automatable; each finding links the extension's page in the browser. Web Store lookups (pulled extensions, new owners) are a future enhancement |

`browser-extensions` is its own connector rather than part of `macos`: it reads browser data, not
OS settings, the same files exist on Linux, and the triage compares extensions across all profiles
of a browser at once (duplicates, one finding per extension).

Every connector is written in Go. The Node prototypes (`google/`, `connected-apps/`, `workspace/`,
`secrets/`, `macos/`) were deleted once their connectors matched them on a live run.

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
- `sync` merges locations (never drops one: git history and transcripts do not forget), refreshes
  `last_seen` only for secrets it saw, and reopens a `rotated` item found again with the same
  fingerprint, with the reason "still present after rotation (old value not removed)". Expired
  snoozes go back to `open`.
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
