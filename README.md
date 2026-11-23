# securizame

Inventory, assess and clean up a personal digital footprint: Google and other consumer accounts,
clouds, AI providers and secrets on disk. Design: [docs/architecture.md](docs/architecture.md).

House rule: every connector **inventories first, read-only**. Removing access is a separate step,
by hand or with an explicit remediation, after reviewing the list.

## Build

```bash
go build -o securizame ./cmd/securizame
./securizame connectors            # built-in and external connectors
./securizame inventory [name ...]  # all connectors when none is given
```

Output goes to `out/<date>/<connector>.jsonl` (mode 0600; `out/` is gitignored because it holds
email addresses and each account's services), with a summary sorted by severity.

## Google: linked apps (`google-personal`)

```bash
./securizame inventory google-personal
```

Walks every Google account signed in to the browser and reports each linked app with its scopes,
the date access was given and a severity: `high` for full Gmail, Drive, Sheets, Cloud data or Google
Ads; `info` for Sign in with Google only. Accounts where Google asks for a fresh sign-in show up as
`reauth` statuses.

- Requires Brave or Chrome started with `--remote-debugging-port=9222` (another address via
  `cdp_url` in the config or `SECURIZAME_CDP`). Pages open in the background and always close,
  without touching your tabs.
- To remove access: the finding's remediation URL. On Google, "Remove all access" there also
  removes that app's Sign in with Google link.

## Connected apps outside Google

```bash
node connected-apps/inventory.mjs              # every service
node connected-apps/inventory.mjs github x     # only those
```

Using the sessions the browser already has open, lists the apps with access to each account,
their permissions, and the authorization or last-used date when the service shows it. `href`
points to the page where access is revoked.

| Service | What it lists |
|---|---|
| GitHub | OAuth apps (scopes and organizations with access), authorized and installed GitHub Apps, web sessions; SSH, signing and GPG keys via `gh api` (title, type, dates, never the key) |
| X | Connected apps with scopes and authorization date |
| Slack | Installed apps and their scope count, in every workspace the browser is signed in to |
| Notion | Developer connections of the active workspace, with capabilities, owner and date |
| Microsoft, Dropbox | Detects whether there is a session; when signed in it saves the page text under `out/` for review, because the reader has not been checked against the real page |

`status` of each row: `ok`; `signedout`; `reauth` when the service wants identity confirmed
(GitHub requires sudo mode for authorized GitHub Apps: open the page, confirm, run again);
`noscope` when `gh` lacks a scope (the message carries the exact `gh auth refresh`);
`ratelimited`; `unverified`; `error`.

- Requires the same browser setup as the Google script, plus a signed-in `gh` for GitHub keys.
- Output: `out/connected-apps-<date>.jsonl` and a summary with counts, apps with broad
  permissions (write, full control, delete, or more than 15 Slack scopes) and services without data.
- X rate-limits its connected-apps API hard. The script loads the list page once and reads the
  app list from that page's own API response (the grant tokens in it are dropped, never stored);
  opening each app's page exhausts the limit. If X answers "Rate limit exceeded", wait 15 minutes.
- Notion has no URL for Settings > Connections (it is a modal): review those by hand.

## Google Workspace: admin audit

```bash
node workspace/audit.mjs example.com example.org [--inactive-days 90] [--quota-project ID]
node --test workspace/        # tests with a mocked fetch, no network
```

Per tenant, read-only through the Admin SDK: accounts without 2SV enrolled or enforced (admins
first), admins, accounts suspended or without a login in over 90 days, and third-party apps with
OAuth grants ranked by number of users, with their scopes (`tokens.list` per user). If the token
allows it, adds OAuth authorizations and revocations over the last 30 days (Reports API,
`applicationName=token`).

Credentials, once per tenant. The script never signs in and never creates service accounts:

1. In a Google Cloud project of the tenant, enable "Admin SDK API" and create an OAuth client ID
   of type "Desktop app". gcloud's default client does not allow scopes outside Google Cloud.
2. Sign in with an admin account of the tenant in a separate gcloud config, so the usual ADC is
   left alone:

   ```bash
   CLOUDSDK_CONFIG="$HOME/.config/securizame/gcloud-example.com" \
     gcloud auth application-default login \
     --client-id-file=$HOME/Downloads/client_secret.json \
     --scopes=openid,https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.reports.audit.readonly
   ```

   gcloud requires `cloud-platform` on that login. The token the script then requests carries only
   the three read-only Admin SDK scopes, and the script checks the account belongs to the audited
   domain.

- Without credentials the script stops and prints that same command with the tenant's path.
- `WORKSPACE_ACCESS_TOKEN` replaces gcloud when the token comes from elsewhere.
- If the Admin SDK API is not enabled in the quota project, pass `--quota-project <ID>`.
- Output: `out/workspace-<domain>-<date>.jsonl`, with `user`, `grant`, `app` and
  `token-activity` lines, plus the summary on screen.

## Plaintext secrets on disk

```bash
node secrets/local-secrets-scan.mjs
```

Looks for tokens, API keys and private keys in plain files and reports, for each finding, the path,
line, type, file permissions and whether git tracks the file. **Never the value**: at most the
known prefix and length (`sk-ant-…(108)`) and a fingerprint `fp` (12 hex of SHA-256) to see where
the same secret repeats.

- Where it looks: `.env*`, `*.pem`, `*.key`, `credentials*`, `secrets*`, `*.secret.exs` and
  `config/master.key` under `~/src` (skipping `node_modules`, `deps`, `_build`, `vendor`); known
  credential files (`~/.aws`, `~/.config/**`, `~/.npmrc`, `~/.netrc`, `~/.docker`, `~/.mcp`,
  `~/.claude.json`, `~/.claude/**/*.json`, `~/.codex`, `~/.cursor`, `~/.gemini`, `~/.zshrc` and
  friends); shell histories; logs (`*.log` under `~/src`, `~/Library/Logs`, `~/.local/log`); agent
  transcripts (`~/.claude/projects`, `~/.codex/sessions`, `~/.cursor/projects`).
- Git history: with `gitleaks` installed, `gitleaks git --redact` on every repo under `~/src` and on
  `~/.claude`. Without it, the script scans the whole `~/src` working tree with its own patterns,
  but not history; to enable history scanning, install gitleaks respecting the 4-day quarantine
  (`~/.claude/scripts/safe-update.sh`, or check the release date before `brew install gitleaks`).
- SSH keys in `~/.ssh`: type, permissions and whether they have a passphrase (`ssh-keygen -y -P ""`).
- Requirements: `rg` (ripgrep) and Node. It takes several minutes: transcripts weigh tens of GB
  and gitleaks walks hundreds of repos.
- Output: `out/local-secrets-<date>.jsonl` (mode 600) and a summary by severity: P0 in git, P1 in
  files readable by group or others, P2 in transcripts, logs and histories, P3 in closed local
  files. Rows with `public: true` are not secrets on their own (AWS key IDs, Sentry DSNs, test
  keys, anon or expired JWTs).
- What to do with each finding: [docs/secrets.md](docs/secrets.md); each row's `fix` field links
  the section.

## macOS and Brave posture (`macos`)

```bash
./securizame inventory macos
./securizame inventory --verbose macos   # also logs the checks that pass
```

Read-only checks without `sudo`: FileVault, SIP, Gatekeeper, firewall and stealth mode, automatic
update settings and pending updates (`softwareupdate -l`, capped at 120 s), screen lock, automatic
login and guest account, TCP ports listening outside loopback (instead of
`systemsetup -getremotelogin`, which needs admin; for SMB it names the shared folders and flags guest
access), login and background items (`sfltool dumpbtm`, flagging those without a developer
signature), Brave extensions per profile with their permissions (flags access to all sites and APIs
such as `cookies`, `debugger` or `nativeMessaging`), and whether Brave runs with
`--remote-debugging-port`.

- A passing check emits no finding (only a log line with `--verbose`); a check that cannot run here
  is an `unsupported` status. Findings are kind `setting`.
- The remote debugging port is a `high` finding even though the google-personal and connected-apps
  connectors need it: while the port is open, any local process can drive the browser with every
  signed-in session. Start Brave with the flag only for those connectors.
- Every command it runs is on an exact allowlist in `connectors/macos`. Takes about half a minute
  because of `softwareupdate` and `sfltool`.

## Remediation

```bash
./securizame remediate --list                # automatable findings of the latest run
./securizame remediate <id>                  # the exact plan; changes nothing
./securizame remediate <id> --apply          # asks "Apply? [y/N]", applies, re-checks
```

One finding at a time. The plan shows the commands, whether they need sudo, the side effects and
how to undo them. With `--apply` it asks for confirmation (and refuses without a terminal unless
`--yes`), then runs that connector again and says whether the finding is gone. Commands that need
root run as `sudo <command>` on your terminal, so sudo asks for your password itself; securizame
never sees it. Design: [docs/architecture.md](docs/architecture.md#remediation).

| Action | What it runs | Undo |
|---|---|---|
| `macos.firewall.enable` | `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on` | `--setglobalstate off` |
| `macos.firewall.stealth` | `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on` | `--setstealthmode off` |
| `macos.airplay-receiver.disable` | `defaults -currentHost write com.apple.controlcenter AirplayRecieverEnabled -bool false`, then `killall ControlCenter` (no sudo) | the same with `true` |
| `file.chmod600` | Makes the file in the finding's `evidence.path` private (mode 600) | `chmod <old mode> <path>` |

Manual, with the System Settings path in the finding: File Sharing (SMB, port 445; turning off the
`smbd` launchd service by hand is not a supported way), Remote Login, Screen Sharing, FileVault,
Gatekeeper, SIP, update settings, screen lock, login items and Brave extensions.

AirPlay Receiver: the `defaults` key is the Terminal remediation in the CIS macOS benchmarks, and
Control Center restarts so it reads it again. If the check after `--apply` still sees ports 5000 or
7000 open, turn it off in System Settings > General > AirDrop & Handoff > AirPlay Receiver.

## Plan

Actions by area and priority, with verified sources and what a script can audit: [docs/plan.md](docs/plan.md).

## Manual review

Services without a connector, with the page where you revoke access: [docs/manual-review.md](docs/manual-review.md).
