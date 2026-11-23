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

## Plan

Actions by area and priority, with verified sources and what a script can audit: [docs/plan.md](docs/plan.md).
