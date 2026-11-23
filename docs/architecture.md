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
| `remediate` | Applies one remediation to one finding | Yes, one item at a time, `--dry-run` by default, explicit confirmation |

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
  "remediation": {"summary": "…", "url": "https://…", "automatable": false},
  "observed_at": "2026-11-23T21:00:00Z"
}
```

- `kind`: `grant` (third-party access), `credential` (key, token, service account), `setting`
  (security configuration), `spend` (spend, budget or limit), `exposure` (secret in plain sight).
- `severity`: `info`, `low`, `medium`, `high`, `critical`.
- `last_used_at`: whatever the provider reports. If it reports nothing, `null`, never a made-up date.
- `evidence` never holds a secret. At most a redacted prefix and the length (`finding.Redact`).

Besides findings, a connector emits per-account status records saying why something could not be
inspected:

```json
{"type": "status", "connector": "openai", "account": "org-…", "state": "missing_credentials", "detail": "…"}
```

`state`: `ok`, `reauth`, `signedout`, `missing_credentials`, `unsupported`, `error`.

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

## v0 connectors

| Connector | How it looks | What it looks for |
|---|---|---|
| `google-personal` | CDP over the signed-in browser | Linked apps, scopes, dates, accounts that need a fresh sign-in |
| `gcp` | `gcloud` CLI | Unrestricted API keys, service-account keys and their age, service accounts with broad roles, billing budgets and alerts, local ADC credentials and their scopes |
| `aws` | `aws` CLI | Root keys or no root MFA, old or unused access keys, budgets |
| `azure` | `az` CLI | Budgets, app registration secrets that never expire or expire soon |
| `openai` | Admin API | Keys, last use, projects, limits and spend |
| `anthropic` | Admin API | Keys, last use, workspaces, limits and spend |
| `openrouter` | API | Keys, per-key credit limit, spend |
| `vercel` | API | Tokens, spend management |
| `supabase` | Management API | Projects, service keys, spend cap |

The Node scripts in `google/`, `connected-apps/`, `workspace/`, `secrets/` and `macos/` are the
prototypes. They keep working until their Go connector replaces them, and then they are deleted.

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
