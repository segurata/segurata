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

## Plaintext secrets on disk (`local-secrets`)

```bash
./securizame inventory local-secrets
```

Looks for tokens, API keys and private keys in plain files and reports, for each one, the path,
line, type, file permissions, whether git tracks the file (and whether that repository has a
remote) and an exposure bucket. **Never the value**: at most the known prefix, the last four
characters of a long random key and the length (`sk_live_…a1b2(107)`), plus a fingerprint.

- Where it looks: `.env*`, `*.pem`, `*.key`, `*.p8`, `credentials*`, `secrets*`, `*.secret.exs`,
  `config/master.key` and keystores under `repos_root` (default `~/src`, skipping `node_modules`,
  `deps`, `_build`, `vendor`); known credential files (`~/.aws`, `~/.config/**`, `~/.npmrc`,
  `~/.netrc`, `~/.docker`, `~/.mcp`, `~/.claude.json`, `~/.claude/**/*.json`, `~/.codex`,
  `~/.cursor`, `~/.gemini`, `~/.zshrc` and friends); shell histories; logs (`*.log` under
  `repos_root`, `~/Library/Logs`, `~/.local/log`); agent transcripts (`~/.claude/projects`,
  `~/.codex/sessions`, `~/.cursor/projects`, `~/.gemini/tmp`).
- Git history: `gitleaks git` over every repository under `repos_root` and over `~/.claude`, six
  at a time, each with a 10-minute timeout. Without gitleaks it scans the whole working tree under
  `repos_root` with its own patterns instead, but not history; install gitleaks respecting the
  4-day quarantine (`~/.claude/scripts/safe-update.sh`).
- SSH keys in `~/.ssh`: type, permissions and whether they have a passphrase
  (`ssh-keygen -y -P ""`). A key without one is an `exposure` finding; a key with one, an `info`
  `setting`.
- Severity is the rotation priority of that one copy (P0 `critical` … P3 `low`, see
  [Rotation ledger](docs/architecture.md#rotation-ledger)). Generic matches (`assignment`,
  gitleaks `generic-api-key`), anon or expired JWTs and encrypted private keys are `info`.
- A finding in a working file that group or others can read carries the `file.chmod600` action:
  `securizame remediate <finding-id>` closes the file. The secret still has to be rotated.
- Requirements: `rg` (ripgrep), `git`, `ssh-keygen`; `gitleaks` for history. The disk scan takes
  about a minute; the history scan of ~330 repositories takes most of the run.
- Config (`connectors.local-secrets.config`): `repos_root`, `skip_git_history` (true skips
  gitleaks and keeps the fast scan), `gitleaks_workers` (default 6), `gitleaks_timeout` (per
  repository, default `"10m"`).
- What to do with each finding: [docs/secrets.md](docs/secrets.md); each finding's `evidence.fix`
  links the section.

### Fingerprints

Every secret gets `evidence.fingerprint`: HMAC-SHA256 of the raw value under a random per-machine
key, truncated to 16 hex characters, so the same secret is recognised wherever it appears (a
`.env`, a transcript, git history) while the output stays useless to anyone without the key. A
private key is fingerprinted by its base64 body, so a `.pem` file, the same key escaped inside a
service-account JSON or a transcript, and its copy in git history all match. gitleaks runs with
its JSON report on stdout, read through a pipe: the raw values exist only in the process memory,
long enough to compute the HMAC.

The key lives at `~/.config/securizame/fingerprint.key` (32 random bytes in hex, created with mode
0600 on first use). Keep it: with a new key every fingerprint changes and the rotation ledger sees
every secret as new.

### Rotation ledger

```bash
./securizame rotations sync                    # from the latest out/<date>/local-secrets.jsonl
./securizame rotations list --priority P0,P1   # what to rotate first
./securizame rotations show <id>               # locations, where the new value goes, rotate URL
./securizame rotations done <id> --note "rolled in the dashboard"
./securizame rotations snooze <id> --until 2027-01-15
./securizame rotations ignore <id> --reason "test fixture"
./securizame rotations reopen <id>
```

One item per secret fingerprint, with its priority (P0 to P3), the reasons in plain words, every
location, `used_in` (the config, `.env` and rc files that hold it, where the new value must go)
and the provider page where it is rotated. State lives outside the repository, at
`~/.local/state/securizame/rotations.json` (mode 0600; `SECURIZAME_STATE` names another
directory), and holds no secret values. A secret marked done that the next sync still finds with
the same fingerprint is reopened: the old value is still somewhere. Generic matches are left out
unless `sync --include-noise`. Details: [docs/architecture.md](docs/architecture.md#rotation-ledger).

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
| `file.chmod600` | Makes the file in the finding's `evidence.path` private (mode 600) | `chmod <old mode> <path>` |

Manual, with the System Settings path in the finding: File Sharing (SMB, port 445; turning off the
`smbd` launchd service by hand is not a supported way), AirPlay Receiver (ports 5000 and 7000), Remote Login, Screen Sharing, FileVault,
Gatekeeper, SIP, update settings, screen lock, login items and Brave extensions.

AirPlay Receiver is manual because the Terminal remediation the CIS benchmarks give (`defaults
-currentHost write com.apple.controlcenter AirplayRecieverEnabled -bool false`, then restarting
ControlCenter) left ports 5000 and 7000 open on macOS 15.6 (tried 2026-11-23).

After `--apply`, the check waits 5 seconds and needs the finding gone in two inventories in a row:
a restarted process can drop its ports for a moment and open them again.

## Plan

Actions by area and priority, with verified sources and what a script can audit: [docs/plan.md](docs/plan.md).

## Manual review

Services without a connector, with the page where you revoke access: [docs/manual-review.md](docs/manual-review.md).
