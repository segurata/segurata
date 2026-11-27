# Changelog

Each release's section here is its release notes on GitHub, which keeps line breaks as written: one line per paragraph or bullet. Versions follow [semver](https://semver.org/); until 1.0 a minor version may change the CLI, the config or the connector protocol.

## [Unreleased]

### Attribution

- A secret committed in one of your repositories (its GitHub remote's owner is among your GitHub accounts and organizations) is attributed mine; one committed only in other people's repositories is attributed not-mine. History a fork inherited from its upstream does not count.
- A commit authored by one of your emails makes a secret mine (medium confidence); a commit by someone else stays a hint, never evidence of not-mine.
- A secret kept in your own config, a dot file or dot folder of your home outside any git repository and package store (`~/.zshrc`, `~/.npmrc`, `~/.config/<tool>/…`), is attributed mine.
- A secret kept in a `.env` file (`.env`, `.env.local`, `.env.production`…) that git does not track, inside a git checkout or worktree under your home, is attributed mine: a clone never creates an untracked file. Templates (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`), package folders and test, example and vendored folders do not count; a tracked `.env` follows its repository.
- A private key whose public half is one of your `~/.ssh/*.pub` files or a key of one of your GitHub users (`gh api users/<login>/keys`, cached a week) is attributed mine.
- An account a secret names outranks the repository, author or file of a copy: someone else's AWS key you committed stays not-mine and is never sent to its provider.
- `segurata rotations owner <id> mine|not-mine --reason text` sets a secret's owner by hand, recorded in its history and shown by `rotations show`; it wins everywhere attribution is used, including the liveness check. `owner <id> unknown` clears it.
- `owned_owners` in the local-secrets config now counts as your GitHub accounts for attribution too.
- `segurata rotations sync` recomputes every owner from what the tracker already holds, without a new scan. The tracker file moves to `schema_version` 8, which older binaries refuse.

### Rotation ranking

- Test material is noise, never a rotation: files a test run generated under a project's `tmp/` (a test-named folder after `tmp/`, or an untracked file git ignores there), test logs (`test.log`, `*.test.log`, `log/test*.log`) and the test data of vendored third-party libraries (a `test`, `tests`, `testdata` or `spec` folder below `vendor/`, `third_party/` or `node_modules/`). The finding and the item's history say which. `segurata rotations sync` re-ranks what is already tracked; the git-ignored `tmp/` case needs a new `segurata inventory local-secrets`.

## [0.1.0]

The first public release.

### Inventories

Sixteen built-in connectors, each read-only on the systems it inspects:

- Accounts and apps: `connected-apps` (apps connected to GitHub, X, Slack, Notion, Microsoft, Dropbox, Facebook, Instagram and LinkedIn, read from the signed-in browser), `google-personal` (OAuth grants of every Google account in the browser), `github`, `workspace`.
- Cloud and AI: `aws`, `gcp`, `azure`, `cloudflare`, `vercel`, `supabase`, `anthropic`, `openai`, `openrouter`, including budgets and spend limits where the provider exposes them.
- This computer: `browser-extensions`, `local-secrets` (plaintext secrets in config and `.env` files, shell histories, logs, agent transcripts and git history; database dumps; SSH keys without a passphrase) and `macos`.
- External connectors on `PATH` speak the same JSON protocol: Prowler (`plugins/prowler`) and a Have I Been Pwned example (`examples/hibp`).

### Tracking and fixing

- A local tracker groups findings into items, keeps decisions, snoozes and accepted risks across runs, and closes an item only when a run that inspected its scope no longer sees it.
- `status` and `report` (text, Markdown, HTML) say what each run covered, so a scope that was not inspected is never reported as clean.
- `remediate` shows a plan for supported fixes and applies it only with `--apply` and confirmation, with an undo where one exists.
- `rotations` keeps a ledger of secrets to rotate; `rotations replace` swaps a rotated value in the files that use it and can move it to the macOS Keychain or Windows Credential Manager.
- `redact` replaces secrets in trail files such as shell histories and agent transcripts.
- `schedule` runs inventories on an interval: a launchd agent on macOS, a Task Scheduler task on Windows, a printed systemd timer on Linux.

### Platforms and distribution

- macOS, Linux and Windows on amd64 and arm64. CI runs the tests on macOS (arm64), Linux (amd64) and Windows (amd64), on Windows both as an administrator and as a standard user; each release builds all six targets.
- Release archives signed with Sigstore (keyless, by this repository's release workflow) with an SPDX SBOM per archive; a Homebrew cask in `segurata/tap`; `go install` with Go 1.26 or later.

[0.1.0]: https://github.com/segurata/segurata/releases/tag/v0.1.0
