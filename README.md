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

## Google Workspace administration (`workspace`)

```bash
./securizame inventory workspace                    # every configured tenant
./securizame inventory workspace:example.com      # one tenant
```

One instance per tenant, read-only through the Admin SDK (GET requests with read-only scopes):

| Finding | Severity |
|---|---|
| Account without 2-Step Verification enrolled, or enrolled but not enforced (admins first) | Admin not enrolled `critical`, user not enrolled `high`, admin not enforced `medium`, user not enforced `low` |
| Each super or delegated admin | `info`; `medium` for a super admin who signed in during the last 3 days, since the super admin role belongs on a separate account not used day to day |
| Account suspended or archived, or without a sign-in for more than `inactive_days` (counted from creation when it never signed in) | Inactive admin `high`, inactive user `medium`, suspended or archived `low` |
| Third-party app holding OAuth grants (`tokens.list` per active account), with its users and scopes | From the broadest scope: admin write scopes `critical`; full or read Gmail, all of Drive, Docs, Sheets or Slides, Cloud Platform and read-only admin scopes `high`; other data `medium`; files the app created `low`; Sign in with Google only `info` |
| App authorized or revoked in the last 30 days with no current grant (Reports API, `applicationName=token`) | `info`; the counts of apps with grants go in their evidence |

Without the Reports scope the token activity is skipped and the status says so. Fixes are manual;
each finding links the Google help page for it.

Config, one key per tenant in `~/.config/securizame/config.json`:

```json
"workspace:example.com":   {"config": {"domain": "example.com"}},
"workspace:example.org": {"config": {"domain": "example.org", "inactive_days": 60}}
```

| Key | Default | Meaning |
|---|---|---|
| `domain` | required | The tenant's primary domain |
| `cloudsdk_config` | `~/.config/securizame/gcloud-<domain>` | gcloud config folder holding this tenant's credentials |
| `quota_project` | the OAuth client's project | Sent as `X-Goog-User-Project`, for when the Admin SDK API is enabled in another project |
| `inactive_days` | 90 | Days without a sign-in before an account counts as inactive |
| `gcloud_path` | `PATH`, then the standard install folders | gcloud binary, as for `gcp` |

Credentials, once per tenant. securizame never signs in and never creates OAuth clients or
service accounts:

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

   gcloud requires `cloud-platform` on that login. The connector then runs only
   `gcloud auth application-default print-access-token` with the three read-only Admin SDK scopes,
   with `CLOUDSDK_CONFIG` pointing at the tenant's folder, and checks with Google's tokeninfo
   endpoint and the user list that the credentials belong to the configured domain.

- Without stored credentials the instance reports `missing_credentials` with these same steps and
  the tenant's path.
- A token from elsewhere: set the `WORKSPACE_ACCESS_TOKEN` secret reference on the instance
  (`"secrets": {"WORKSPACE_ACCESS_TOKEN": "keychain:..."}`); gcloud is then not used.

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
./securizame rotations ignore --path ~/src/app/log/test.log --reason "test fixtures"   # every item found only there
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
login and guest account, whether other accounts can read your home folder, TCP ports listening
outside loopback (instead of `systemsetup -getremotelogin`, which needs admin), each SMB share
point behind port 445 (from `sharing -l -f json`), login and background items (`sfltool dumpbtm`,
flagging those without a developer signature), and whether Brave runs with
`--remote-debugging-port`. Browser extensions are the `browser-extensions` connector, below.

- A passing check emits no finding (only a log line with `--verbose`); a check that cannot run here
  is an `unsupported` status. Findings are kind `setting`.
- The remote debugging port is a `high` finding even though the google-personal and connected-apps
  connectors need it: while the port is open, any local process can drive the browser with every
  signed-in session. Start Brave with the flag only for those connectors.
- File Sharing gives a medium finding for port 445 and one `share_point` finding per share point,
  with its name, path, whether the path exists, guest access and read-only. A share open to guests
  is `high`; so is an orphaned record whose folder no longer exists (Migration Assistant leaves
  these behind for users that were never recreated); any other shared folder is `medium`.
- Every command it runs is on an exact allowlist in `connectors/macos`. Takes about half a minute
  because of `softwareupdate` and `sfltool`.

## Browser extensions (`browser-extensions`)

```bash
./securizame inventory browser-extensions
```

Reads every Brave and Chrome profile (Preferences, Secure Preferences, Local State, and the
manifest of unpacked extensions) and emits one `grant` finding per extension and browser, with:
name, id, the profiles it is in, and per profile its version, install date (`first_install_time`),
last update (`last_update_time`) and source (web store, unpacked in developer mode, or sideloaded);
its permissions as risk capabilities (read and change all sites, debugger, cookies, webRequest,
nativeMessaging, clipboard read, history, downloads, management); a category hint (password
manager, crypto wallet, AI assistant, shopping, dev tool) from a short list of ids and name words in
`connectors/browserext/triage.go`; and a verdict with its reasons.

| Verdict | When | Severity |
|---|---|---|
| `remove` | Unpacked developer extension not updated in over a year; a second password manager in the same profile that is not the primary one; `debugger` permission on anything that is not a dev tool | `high` with access to all sites, `debugger`, `cookies` or `nativeMessaging`, else `medium` |
| `review` | Access to all sites plus a sensitive API; a crypto wallet in a profile used in the last 30 days; a store extension not updated in over a year; unpacked or sideloaded; disabled; two password managers installed the same day with no primary configured | `medium` for all sites plus a sensitive API or a wallet in a daily profile, else `low` |
| `keep` | None of the above | `info` |

- The primary password manager is the one named in the config, otherwise the one installed on a
  later day. Name it with `"browser-extensions": {"config": {"primary": ["<extension id>"]}}`.
- Not automatable: changing profile files while the browser runs is unsafe. Each finding links
  `brave://extensions/?id=<id>` (or `chrome://`) and names the profiles to open it in.
- No network calls. Checking the Web Store (an extension pulled from the store, a change of owner)
  is a future enhancement.
- To keep an extension the verdict disagrees with: `securizame accept <id> --reason "..."`.

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
| `macos.smb.share-remove` | `sudo /usr/sbin/sharing -r <name>` (orphaned records and shared folders without guest access) | `sudo /usr/sbin/sharing -a <path> -n <name> -S <smb name> -s <flag> -g <flag> -R <0/1>` with the record's current flags; not applicable for an orphan, whose folder no longer exists |
| `macos.smb.guest-off` | `sudo /usr/sbin/sharing -e <name> -g 000` (live shares open to guests) | `sudo /usr/sbin/sharing -e <name> -g 001` |
| `macos.home.private` | `/bin/chmod 700 <home>`, no sudo, when group or others can read the home folder (every user is in `staff`, so 750 is as open as 755; 711 passes, as CIS allows) | `/bin/chmod <old mode> <home>` |
| `file.chmod600` | Makes the file in the finding's `evidence.path` private (mode 600) | `chmod <old mode> <path>` |

The home folder path comes from the OS (`os.UserHomeDir`), never from the finding, and the octal
`chmod` leaves its ACL entries (macOS's `group:everyone deny delete`) in place; the finding's
evidence lists them.

The share point name comes from a fresh `sharing -l -f json` read at plan and at apply time, never
from the finding alone: a name that matches no record exactly is refused, and the apply-time
allowlist holds only the records that exist then. The name is one argument to `sharing`, never
passed through a shell, so spaces and quotes in it are safe. Turning guest access off changes the
finding's id (`smb-share-guest:<name>` becomes `smb-share:<name>`), which is how the re-check sees
the fix; the share itself stays reported as a medium finding.

Port 445 stays manual. `launchd` owns that socket (netstat shows pid 1) and hands connections to
`smbd` on demand, so it listens while File Sharing is on, with or without share points. After the
last share point is removed, the port finding says "with no shared folders" and points to System
Settings > General > Sharing > File Sharing. Turning off the `smbd` launchd service by hand is not a
supported way.

Manual, with the System Settings path in the finding: File Sharing itself (SMB, port 445), AirPlay Receiver (ports 5000 and 7000), Remote Login, Screen Sharing, FileVault,
Gatekeeper, SIP, update settings, screen lock, login items and browser extensions.

AirPlay Receiver is manual because the Terminal remediation the CIS benchmarks give (`defaults
-currentHost write com.apple.controlcenter AirplayRecieverEnabled -bool false`, then restarting
ControlCenter) left ports 5000 and 7000 open on macOS 15.6 (tried 2026-11-23).

After `--apply`, the check waits 5 seconds and needs the finding gone in two inventories in a row:
a restarted process can drop its ports for a moment and open them again.

## Accepted risks

```bash
./securizame accept <id> --reason "AI agents drive Brave over CDP" [--until 2027-03-31]
./securizame accept --list
./securizame unaccept <id>
```

A finding you keep on purpose stays in `out/<date>/*.jsonl` with an `accepted` field, but leaves
the summary and `remediate --list`, which print how many were hidden. With `--until`, it shows
again after that day, marked "(acceptance expired)". State: `~/.config/securizame/accepted.json`
(mode 0600; `SECURIZAME_ACCEPTED` names another file). Details:
[docs/architecture.md](docs/architecture.md#accepted-risks).

## Plan

Actions by area and priority, with verified sources and what a script can audit: [docs/plan.md](docs/plan.md).

## Manual review

Services without a connector, with the page where you revoke access: [docs/manual-review.md](docs/manual-review.md).
