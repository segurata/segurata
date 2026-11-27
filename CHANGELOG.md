# Changelog

Each release's section here is its release notes on GitHub, which keeps line breaks as written: one line per paragraph or bullet. Versions follow [semver](https://semver.org/); until 1.0 a minor version may change the CLI, the config or the connector protocol.

## [0.3.1]

### Distribution

- Windows installs and updates with Scoop: `scoop bucket add segurata https://github.com/segurata/scoop-bucket`, `scoop install segurata`, then `scoop update segurata`. Each release writes the manifest to `segurata/scoop-bucket`.

## [0.3.0]

Windows gets device posture of its own: the new `windows` connector checks disk encryption, firewall, antivirus, updates, screen lock, accounts and remote access as the signed-in user, without elevating.

### Windows

- New built-in connector `windows`, the Windows counterpart of `macos`, which brings the built-in connectors to seventeen. It runs as the signed-in user and never elevates: one Windows PowerShell process from System32 that loads no module, plus read-only registry reads.
- Checks: BitLocker on each fixed drive, Microsoft Defender Firewall per profile, Microsoft Defender or another antivirus registered in Windows Security Center, Windows Update (service, policy, last installation, pending restart), screen lock, other local administrators, Guest, accounts allowed an empty password, automatic sign-in, User Account Control, Remote Desktop and Network Level Authentication, SMBv1, shared folders, TCP ports reachable from the network, Secure Boot and browser debugging ports (Brave, Chrome, Edge).
- What a standard user cannot read (BitLocker through WMI, the shell's BitLocker answer on Windows Server, share permissions) is reported as not inspected, with the command to run from an elevated PowerShell, never as clean.
- Every finding names the Settings page or the elevated command that fixes it. `windows.screen-lock.set` fixes the screen lock in the user's own registry hive, with an undo; machine-wide changes stay with the owner.
- `segurata doctor --connector windows` runs the probe and says which sources a standard user is refused.

### Fixes

- With no connector named, `inventory`, `schedule`, `signin`, `doctor` and the coverage line in `status` leave out the connectors for another system: `macos` on Windows and Linux, `windows` on macOS and Linux. Named, such a connector still runs and says it is not supported here.
- A credential no provider is known for, such as an internal service's bearer token, is no longer to be rotated "in the provider's console": the next step says to rotate it in the service that accepts it, which segurata cannot name.
- The tracker lists a theme added by a new version in briefing order in a tracker saved by an older one, instead of last.

## [0.2.0]

Secrets are attributed to their owner from where they live and who committed them, and Google Cloud gets its first remediations: API keys restricted to the APIs they use, daily caps on pay-per-use APIs, and budgets with alerts.

Upgrading: the first command that saves the tracker moves it to `schema_version` 8, which 0.1.0 refuses to read.

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

### Google Cloud

- Each API key finding says which APIs the key called in the last 30 days, read from Cloud Monitoring (`serviceruntime.googleapis.com/api/request_count` on `consumed_api`, by `credential_id` `apikey:<uid>`), or that it called none and is a candidate for deletion. Reading it needs `monitoring.timeSeries.list` (`roles/monitoring.viewer`); a failure is a status of its own and leaves the key findings checked.
- `gcp.apikey.restrict` restricts a key without API restriction to the APIs it called: `gcloud services api-keys update <key> --api-target=service=<svc>…`, keeping its application restriction. Refused when the key called nothing or usage cannot be read. gcloud cannot undo it; the plan names the console page that can.
- Pay-per-use APIs (Maps Platform, Gemini API, Vertex AI, Translation, Vision, Speech-to-Text, Text-to-Speech, Document AI) enabled without a per-day request cap of the project's own are a medium finding, read from the Cloud Quotas API (`quotaInfos`, `quotaPreferences`).
- `gcp.quota.cap` caps them: `gcloud quotas preferences create` (or `update`) with the requests per day set in the new `quota_caps` config key; the plan is refused without it. The undo sets the old limit back, since a quota preference cannot be deleted.
- `gcp.budget.create` creates a monthly budget for all projects of a billing account that has none with alerts, at 50%, 90% and 100% of actual and 100% of forecasted spend, for the amount in the new `budget_amount` config key (refused without it); the apply prints the exact `gcloud billing budgets delete` that undoes it. `gcp.budget.alerts` adds the missing 100% actual and forecasted thresholds to a budget, and its undo restores the old ones. A budget alerts and does not stop spend: docs/gcp-connector.md says what does.
- `segurata doctor` tests, with `testIamPermissions`, the permissions the newer gcp checks and remediations need on each account's first project and first open billing account, and names the roles that grant the missing ones.

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

[0.3.1]: https://github.com/segurata/segurata/releases/tag/v0.3.1
[0.3.0]: https://github.com/segurata/segurata/releases/tag/v0.3.0
[0.2.0]: https://github.com/segurata/segurata/releases/tag/v0.2.0
[0.1.0]: https://github.com/segurata/segurata/releases/tag/v0.1.0
