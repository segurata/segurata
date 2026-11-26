# Changelog

Each release's section here is its release notes on GitHub. Versions follow
[semver](https://semver.org/); until 1.0 a minor version may change the CLI, the config or the
connector protocol.

## [0.1.0]

The first public release.

### Inventories

Sixteen built-in connectors, each read-only on the systems it inspects:

- Accounts and apps: `connected-apps` (apps connected to GitHub, X, Slack, Notion, Microsoft,
  Dropbox, Facebook, Instagram and LinkedIn, read from the signed-in browser), `google-personal`
  (OAuth grants of every Google account in the browser), `github`, `workspace`.
- Cloud and AI: `aws`, `gcp`, `azure`, `cloudflare`, `vercel`, `supabase`, `anthropic`, `openai`,
  `openrouter`, including budgets and spend limits where the provider exposes them.
- This computer: `browser-extensions`, `local-secrets` (plaintext secrets in config and `.env`
  files, shell histories, logs, agent transcripts and git history; database dumps; SSH keys
  without a passphrase) and `macos`.
- External connectors on `PATH` speak the same JSON protocol: Prowler (`plugins/prowler`) and a
  Have I Been Pwned example (`examples/hibp`).

### Tracking and fixing

- A local tracker groups findings into items, keeps decisions, snoozes and accepted risks across
  runs, and closes an item only when a run that inspected its scope no longer sees it.
- `status` and `report` (text, Markdown, HTML) say what each run covered, so a scope that was not
  inspected is never reported as clean.
- `remediate` shows a plan for supported fixes and applies it only with `--apply` and
  confirmation, with an undo where one exists.
- `rotations` keeps a ledger of secrets to rotate; `rotations replace` swaps a rotated value in
  the files that use it and can move it to the macOS Keychain or Windows Credential Manager.
- `redact` replaces secrets in trail files such as shell histories and agent transcripts.
- `schedule` runs inventories on an interval: a launchd agent on macOS, a Task Scheduler task on
  Windows, a printed systemd timer on Linux.

### Platforms and distribution

- macOS, Linux and Windows on amd64 and arm64. CI runs the tests on macOS (arm64), Linux (amd64)
  and Windows (amd64); each release builds all six targets.
- Release archives signed with Sigstore (keyless, by this repository's release workflow) with an
  SPDX SBOM per archive; a Homebrew cask in `segurata/tap`; `go install` with Go 1.26 or later.

[0.1.0]: https://github.com/segurata/segurata/releases/tag/v0.1.0
