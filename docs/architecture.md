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

In v0 each connector sets severity while inventorying (`assess` lives inside `inventory`).
`remediate` always states the exact scope of what it will remove before acting. On Google,
"Remove all access" on an app's permissions page also removes that app's Sign in with Google
link; that has to be said up front, not discovered afterwards.

## Finding model

One JSON line per finding (`internal/finding`):

```json
{
  "type": "finding",
  "id": "sha256(connector|account|resource.type|resource.id)[:16]",
  "connector": "google-personal",
  "account": "person@example.com",
  "resource": {"type": "oauth_grant", "id": "…", "name": "Dropbox"},
  "kind": "grant",
  "severity": "high",
  "title": "Dropbox can see and download your contacts",
  "evidence": {"scopes": ["…"]},
  "created_at": "2020-03-24T00:00:00Z",
  "last_used_at": null,
  "remediation": {"summary": "…", "url": "https://…", "action": "", "automatable": false},
  "observed_at": "2026-11-23T21:00:00Z"
}
```

- `kind`: `grant` (third-party access), `credential` (key, token, service account), `setting`
  (security configuration), `spend` (spend, budget or limit), `exposure` (secret in plain sight).
- `severity`: `info`, `low`, `medium`, `high`, `critical`.
- `last_used_at`: whatever the provider reports. If it reports nothing, `null`, never a made-up date.
- `evidence` never holds a secret. At most a redacted prefix and the length (`finding.Redact`).
- `remediation.action`: id of a built-in remediation (`macos.firewall.enable`, `file.chmod600`),
  empty when the fix is manual. `automatable` is true exactly when `action` is set.

Besides findings, a connector emits per-account status records saying why something could not be
inspected:

```json
{"type": "status", "connector": "openai", "account": "org-…", "state": "missing_credentials", "detail": "…"}
```

`state`: `ok`, `reauth`, `signedout`, `missing_credentials`, `unsupported`, `error`.

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
  first command runs.
- sudo: a command that needs root runs as `/usr/bin/sudo <argv>` with the terminal's stdin, stdout
  and stderr attached, so sudo asks for the password itself. securizame never reads, stores or
  pipes a password.
- Generic actions belong to the core, so any connector can attach them. `file.chmod600` takes the
  file in `evidence.path` (absolute or `~/`), refuses symlinks and non-regular files, and changes the
  mode in-process; the undo is `chmod <old mode> <path>`.
- External connectors cannot remediate yet. A later protocol version will add a
  `securizame-<name> remediate` subcommand with the same plan and apply steps.

## External connector protocol (v1)

An external connector is a `securizame-<name>` executable with two subcommands.

`securizame-<name> describe` prints a JSON object:

```json
{"name": "example", "version": "0.1.0", "protocol": 1,
 "summary": "What it inventories", "needs": ["cdp", "cli:gcloud", "secret:EXAMPLE_API_KEY"]}
```

`securizame-<name> inventory` reads one JSON request from stdin and writes JSON Lines records
(`finding`, `status` or `log`) to stdout:

```json
{"protocol": 1, "cdp_url": "http://127.0.0.1:9222", "config": {"…": "…"},
 "secrets": {"EXAMPLE_API_KEY": "value already resolved by the core"}}
```

Rules:
- Exit 0 when it finished, even if some accounts reported error statuses. Non-zero only when the
  connector could not start at all.
- stderr is for human diagnostics; the core shows it with `--verbose`.
- The connector never writes secrets to stdout or stderr.
- The core takes the connector name from `describe`, never from the records.

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
| `local-secrets` | `rg`, `gitleaks`, `git`, `ssh-keygen` | Plaintext secrets in config and `.env` files, shell histories, logs, agent transcripts and git history; SSH keys without a passphrase; HMAC fingerprints so one secret is recognised in every place it appears |
| `gcp` | `gcloud` CLI | Unrestricted API keys, service-account keys and their age, service accounts with broad roles, billing budgets and alerts, local ADC credentials and their scopes |
| `aws` | `aws` CLI | Root keys or no root MFA, old or unused access keys, budgets |
| `azure` | `az` CLI | Budgets, app registration secrets that never expire or expire soon |
| `openai` | Admin API | Keys, last use, projects, limits and spend |
| `anthropic` | Admin API | Keys, last use, workspaces, limits and spend |
| `openrouter` | API | Keys, per-key credit limit, spend |
| `vercel` | API | Tokens, spend management |
| `supabase` | Management API | Projects, service keys, spend cap |
| `macos` | macOS tools, read-only and without sudo; Brave profile files | FileVault, SIP, Gatekeeper, firewall and stealth mode, update settings and pending updates, screen lock, automatic login, guest account, TCP ports reachable from the network (with File Sharing guest access), login and background items, Brave extensions and their permissions, Brave's remote debugging port. Remediates the firewall and stealth mode |

The Node scripts in `connected-apps/` and `workspace/` are the
prototypes. They keep working until their Go connector replaces them, and then they are deleted.

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
