# segurata

Segurata is a CLI for auditing accounts and computers you manage. It inventories connected
apps, cloud and AI credentials, browser extensions and secrets on disk. Its local tracker
keeps findings and decisions between scans, including which credentials you still need to rotate.

"Segurata" is Spanish slang for a security guard. See the [architecture](docs/architecture.md).

## Install

Build from a clone with Go 1.26 or later.

```bash
go build -o segurata ./cmd/segurata
./segurata version
```

Published releases provide standalone binaries for macOS and Linux, and preview builds for
Windows (amd64 and arm64). See the [installation and signature verification instructions](docs/releasing.md#installing)
for release archives, `go install` and Homebrew.

## Quickstart

```bash
./segurata connectors
./segurata doctor --connector browser-extensions
./segurata inventory browser-extensions
./segurata status
```

This first scan reads local Brave and Chrome profiles on macOS or Linux. It needs no provider
credentials. With an installed binary, use `segurata` in place of `./segurata`.

The config is `~/.config/segurata/config.json` (`SEGURATA_CONFIG` overrides it); each connector's
section below lists its keys. A key left out or set to `null` takes its default. A malformed value
stops that connector with an error naming the key (`aws config: "profiles" must be a list of
non-empty strings`), never a silent default: a value of another type, an empty or blank string or
list entry, a number below 1 where a count or a limit belongs, or an empty list where the list
picks what to inspect (`accounts`, `profiles`, `projects`, `services`), since it would inspect
nothing; leave such a key out to inspect everything. Pass a connector name to `inventory` to limit
what runs.

Before the first inventory, `segurata doctor` checks, read-only, the config and its secret
references (resolved, never printed), the browser's debugging port, each connector's CLIs and
sign-ins (expired gcloud accounts, AWS profiles, `az`, `gh` scopes, Workspace tokens, the
Cloudflare token's permissions, rg and gitleaks) and the modes of segurata's own files, with the exact fix for each problem
(`--connector name` checks one). Details: [docs/architecture.md](docs/architecture.md#doctor).

An external connector is any `segurata-<name>` executable on `PATH`, in any language; how to
write one, built-in or external: [docs/connectors.md](docs/connectors.md). Contributing:
[CONTRIBUTING.md](CONTRIBUTING.md).

Output goes to `~/.segurata/out/<date>/`. The inventory summary prints each JSONL path.
Unix runs use mode 0600 for those files in a 0700 directory because they contain account and
service details. Set `SEGURATA_OUT` or pass `--out` to choose another directory. Each inventory
ends with `segurata track sync`, which folds the latest runs into the tracker.

## Safety model

Every connector **inventories first, read-only**. Changing anything is a separate step, by hand or
with `segurata remediate`, which shows the exact plan and changes nothing without `--apply` and a
confirmation. The full list of guarantees, each of which counts as a vulnerability when broken:
[SECURITY.md](SECURITY.md#security-principles).

### What leaves your machine

- No telemetry, no segurata server, no update check.
- Read requests to the providers you configure, with your own credentials: the provider CLIs
  (`gh`, `gcloud`, `aws`, `az`), GET requests to provider APIs with the token your config
  references, and pages of your own signed-in browser through its local debugging port.
- Secrets found on disk are fingerprinted and attributed locally by default. If you enable
  [liveness checks](#liveness), supported checks authenticate against the provider with the
  candidate credential. AWS STS uses a request signed locally with the secret access key.
- Results stay on disk. Unix systems use mode 0600 for state files. On Windows, use folders
  with access restricted by Windows ACLs.
- `segurata remediate --apply` sends exactly the commands or requests its plan showed.
- External connectors (`segurata-<name>` on `PATH`) run as you and send what they send: the
  [hibp example](examples/hibp/README.md) sends your email addresses to Have I Been Pwned. Read one
  before you install it.

## Tracker and status

```bash
./segurata status                         # the briefing: what to do next, decisions, blockers, changes (read-only)
./segurata status --explain               # same, with the score behind each "Do next" entry
./segurata status --mark-seen             # same, and start "Since the last status" from now
./segurata status --priority P0,P1 --theme github-orgs
./segurata status --write                 # also ~/.segurata/status.md and status.html (mode 0600); implies --mark-seen
./segurata track list [--all] [--kind rotate] [--theme t] [--priority P0,P1] [--status s]
./segurata track show T-0042
./segurata track start|done|reopen T-0042 [--note "..."]
./segurata track note T-0042 "ordered a backup disk"
./segurata track snooze T-0042 --until 2027-01-15
./segurata track ignore T-0042 --reason "test fixture"
./segurata track ignore --path ~/src/app/log/test.log --reason "test fixtures"   # every item found only there
./segurata track expect T-3153 --reason "ephemeral key on purpose" [--dry-run]   # a setup item kept on purpose: config rule

./segurata track prioritize T-0042 P0 --reason "client data"   # `auto` goes back to the computed one
./segurata track decide T-0003 --answer "yes" [--ignore-scope path:~/src/old] [--accept-scope repo:acme/site]
./segurata track decide T-0002 --answer "rotate mine, ignore the rest" --ignore-scope path:~/src/legacyco --owner not-mine [--dry-run]
./segurata track add --title "Buy a hardware key" [--kind fix|setup|review] [--priority P1]
./segurata track add --kind decide --question "Keep the old VPS?" --option yes --option no
./segurata track add --kind decide --question "Are the legacy repos dead?" --option "yes=ignore:path:~/src/legacy" --option no
./segurata track sync [--out out]         # also run by inventory; rotations sync is the same, needing a local-secrets run
```

`~/.segurata/tracker.json` (mode 0600 in a 0700 folder; `SEGURATA_HOME` names another folder)
is the single record of what to do, what is done and what is pending, and survives restarts: one
item per thing a person would act on. Five GitHub orgs that do not require 2FA are one item; each
secret to rotate, each data dump and each Mac setting is its own item; a connector that needs a
fresh sign-in is a setup item; info findings make none. Items have a kind (fix, rotate, decide,
setup, review), a theme, a status (open, in_progress, done, accepted, ignored, snoozed, and two
segurata sets itself: reclassified, a secret a corrected rule now rates as noise, and expected), a computed
priority that `prioritize` can override, the findings they link, the next step and a history.

A decision can carry effects: answering it adds rules (`ignore` or `accept` a scope:
`path:<dir>`, `repo:<owner/name>`, `account:<glob>`, `gcp-project:<id>`) that close the items in
scope now and at every sync, with the decision named in the reason. A pending decision shows
how many open items each answer would close. `--owner not-mine` (or an option written
`yes=ignore@not-mine:path:~/src/old`) narrows the rules to secrets attributed to someone else (see
"Attribution" below): the owner's own and the unknown ones stay open, and `--dry-run` says so
before anything changes ("closes 120 open items (P0 100, P1 20) attributed not-mine, keeps 8 open
(mine 5, unknown 3)"). Details:
[docs/architecture.md](docs/architecture.md#decisions-and-rules).

A status other than `ok` that is kept on purpose (an ephemeral key, an IAM user limited by design,
other people's accounts) goes in the config as an expected rule, by hand or with `track expect`:
`{"connectors": {"anthropic:personal": {"expected": [{"state": "missing_credentials", "reason":
"…"}]}}}`, with optional `account` (a glob) and `detail` (substring, or `/regexp/`). It then opens
no setup item and is counted on one line, "N expected (by your config)", but its scope still
counts as not inspected. Details:
[docs/architecture.md](docs/architecture.md#expected-statuses).

Each connector instance's inventory runs under a deadline, one hour unless the connector declares
more (local-secrets 6h, prowler 12h) or the instance sets `timeout`:
`{"connectors": {"gcp": {"timeout": "2h"}}}`. A run that hits it ends failed, so nothing it left
out is closed. Details: [docs/architecture.md](docs/architecture.md#run-completeness).

A done item is verified when a later run no longer reports its findings, and reopened if one does;
an item whose findings vanish on their own is closed as "verified (no longer reported)", and a
setup item whose status a finished run no longer reports as "verified (status no longer
reported)", whatever that run inspected. Expired
snoozes and acceptances open their items again. Every change goes through the CLI; the file is
written atomically and the previous version kept as `tracker.json.bak`. A tracker that does not
parse is never overwritten: fix it or restore the backup. It holds redacted hints and fingerprints,
never a secret value, so the backup holds none either.

## Accounts

```bash
./segurata accounts list [gcp|google-personal] [--out out]   # accounts each connector saw: watched or not, last state, last seen
./segurata accounts unwatch google-personal colleague@example.com  # take it out of connectors."google-personal".config.accounts
./segurata accounts watch google-personal colleague@example.com    # put it back
./segurata accounts owned [--out out]                         # the owner's accounts attribution compares secrets with
```

`unwatch` writes the connector's `accounts` list (from the accounts the runs saw, when there is no
list yet) and closes the account's open setup items as ignored; `watch` adds it back and opens the
items `unwatch` closed. The config is rewritten atomically (mode 0600, keys in their order) and the
previous file kept as `config.json.segurata-bak-<time>`. An unwatched account is declared a skipped
scope at each run, so its earlier findings are never taken as resolved. `gcp` and
`google-personal` take an accounts list.

## Signing in

```bash
./segurata signin --list                 # what it would open and list; opens nothing
./segurata signin                        # open the pages, wait, run those connectors again
./segurata signin google-personal        # only this connector (or connector:label)
./segurata signin --all --timeout 20m    # also the commands of other setup items; wait longer
```

`signin` takes the open setup items where a browser connector reports `reauth` or `signedout`
(Google asks you to verify it's you, GitHub wants sudo mode, Microsoft Security info wants a fresh
MFA sign-in, Dropbox is signed out) and opens a
normal tab at each page where you act, in the browser at `cdp_url`. It prints a numbered list with
what to do on each page, then reads the pages every few seconds, read-only, with the test the
connector itself uses, until each shows what the connector reads (the list instead of the sign-in
or "Confirm access" page). It stops once every page is through, when you press Enter, or after the
timeout (10 minutes by default). Then it runs those connector instances again, syncs the tracker
and says which setup items closed. It never types a password or clicks anything, and the tabs stay
open: they are yours.

- GitHub sudo mode lasts minutes, so `connected-apps` runs as soon as you confirm on GitHub, while
  the other pages wait; it runs again at the end only if one of its pages was through after that.
- Commands for your terminal (`gcloud auth login <account>`, `gh auth refresh -s <scope>`) are
  listed with the rerun that follows them; `signin` never runs them, since they start a browser of
  their own. `--all` also lists the commands of the other setup items, such as storing a
  credential.
- Accounts taken out with `segurata accounts unwatch` are skipped.
- Tabs open only in the browser at `cdp_url`, through CDP. When it is not reachable, `signin`
  prints the URLs and stops; it never opens another browser or calls the system's `open`.
- `segurata status` ends the setup blockers with "`segurata signin` opens the pages that need
  you" whenever one of them is a browser sign-in.

## Google: linked apps (`google-personal`)

```bash
./segurata inventory google-personal
```

Walks every Google account signed in to the browser and reports each linked app with its scopes,
the date access was given and a severity: `high` for full Gmail, Drive, Sheets, Cloud data or Google
Ads. Apps linked for Sign in with Google only are one `info` finding per account listing them (with
their dates in the evidence). Accounts where Google asks for a fresh sign-in show up as `reauth`
statuses.

- An account that is the login (Sign in with Google or a grant) for financial or cloud services
  gets one more finding: "Google account X is the login for N financial/cloud services: use a
  passkey/security key and consider Advanced Protection". It is `high` when one of them can move
  money (crypto exchanges, Wise, Revolut, PayPal, Stripe, banks) and `medium` for investing
  platforms (Crowdcube, Wefunder, AngelList…) and cloud consoles (AWS, Cloudflare, Vercel…) only.
  The list of names is `loginServices` in `connectors/googlepersonal/accountview.go`.
- `{"connectors": {"google-personal": {"config": {"accounts": ["me@example.com"]}}}}` inventories
  only those accounts; other accounts signed in to the browser (a shared mailbox, a colleague's)
  get no status and are declared skipped scopes, so their earlier findings are not taken as resolved.

- Requires Brave started with `--remote-debugging-port=9222` (another address via
  `cdp_url` in the config or `SEGURATA_CDP`). Pages open as hidden targets, in no window and
  not in the tab strip, and always close: your tabs and focus are never touched.
- To remove access: the finding's remediation URL. On Google, "Remove all access" there also
  removes that app's Sign in with Google link.

## Connected apps outside Google (`connected-apps`)

```bash
./segurata inventory connected-apps
```

Reads each service's settings pages in the browser's existing sessions and reports every app with
access to the account: its permissions, the dates the page shows, and the page where access is
revoked (`remediation.url`). Severity is table-driven: write access, reading direct messages,
deleting repositories, administering organizations and billing are `high`; broad read-only access is
`medium`; profile or email only is `low` or `info`. When the page gives a last-used date older than
a year, the severity goes up one level.

- X and Dropbox apps approved more than 10 years ago are one finding per service ("Revoke N X apps
  authorized before <month year> (services mostly defunct)", "Disconnect N Dropbox apps linked
  before <month year>"), as severe as the worst of them and listing each with its date; newer apps
  are listed oldest first, each with `age_years`.
- A Notion integration whose owner is you ("(You)") is `low` and says "(your own integration)":
  its token is yours, and a leaked copy is a local-secrets finding.
- Grants segurata runs on are labelled "(segurata depends on it)" and never told to revoke: for the
  GitHub CLI the fix narrows it with `gh auth refresh -h github.com -r <scopes>` (`delete_repo`,
  `admin:org`, `admin:enterprise`, whichever it holds; `connected-apps.gh.drop-scopes` runs it) and
  a read-only token for segurata. In
  google-personal, the Google Cloud SDK grant gets the same label and the Firebase CLI grant
  "(developer tool)", with the CLI's own sign-out command as the fix.

| Service | What it lists |
|---|---|
| GitHub | OAuth apps (scopes, organizations with access, last use), installed GitHub Apps, web sessions; SSH, signing and GPG keys via `gh api` (title, type, dates, never the key). Authorized GitHub Apps and the permissions of installed ones need sudo mode: `reauth` |
| X | Connected apps with scopes and authorization date |
| Slack | Installed apps in every workspace the browser is signed in to, with the bot and user-token scopes the workspace's app list declares for each (read from the response the manage page fetches; no app page is opened). Graded by capability: admin scopes, reading messages with a user token, or posting together with reading history are `high`; posting, reading history or files alone `medium`; members' emails, an incoming webhook or metadata `low`. An app waiting for approval is `info`; one only the rows show is graded by its scope count (15 or more is `high`). A workspace whose app list did not load and shows no row is `unverified` |
| Notion | Developer connections of the active workspace, with capabilities, owner and date. Settings › Connections is a dialog with no URL: review it by hand |
| Facebook | Active apps under Settings › Apps and websites, with the information each one receives. Only the first page: the "See more" button is not clicked, and the status says so |
| Instagram, LinkedIn | Whether any app or service is connected. Only the empty list has been seen; a non-empty one is reported as `unverified`, to review by hand |
| Dropbox | Apps under Settings › Apps › "View Dropbox content", with access type, permissions, publisher and link date. Full Dropbox access is `high` (`medium` if read-only), an app folder `low`, a scoped app by its scopes, an unknown access type `medium`. "Launch from Dropbox" is not read. A list in a shape segurata does not know is `unverified` |
| Microsoft | Whether a personal Microsoft account has a session. The reader has never seen the signed-in page: `unverified`. Its sign-in form cannot tell "no personal account" from "signed out", so with only a work account leave `microsoft` out of `services` |
| Microsoft work (`microsoft-work`) | Enterprise apps in My Apps (`myapplications.microsoft.com`), each `low`: My Apps shows no permissions, and no user page lists delegated consents (a tenant admin reads them in the Entra admin center). Microsoft 365's own tiles are counted, not listed. Then Security info (`mysignins.microsoft.com/security-info`): a tenant that wants a fresh MFA sign-in there gives `reauth` for the scope `microsoft-work:security-info` only, naming the method the prompt asks for; past the prompt the page has not been seen: `unverified` |

Statuses: `ok`; `signedout`; `reauth` (the service wants identity confirmed: open the page,
confirm, run again; `segurata signin` does both); `noscope` (`gh` lacks a scope; the detail carries the exact
`gh auth refresh` command); `unverified`; `error`.

- Requires the browser setup of `google-personal`, plus a signed-in `gh` for GitHub keys.
- One instance per service, if you want them separate, through `services` (default: all):

  ```json
  "connected-apps:x":      {"config": {"services": ["x"]}},
  "connected-apps:github": {"config": {"services": ["github"]}}
  ```

- Read-only: it only navigates and reads. It never clicks a button, never submits a form, loads
  each listing page once per run, and closes every page it opens.
- X rate-limits its connected-apps API hard. The connector loads the list page once and reads the
  app list from that page's own API response; the grant tokens in it are dropped on decode, never
  stored. Opening each app's page would exhaust the limit. If X answers "Rate limit exceeded", wait
  15 minutes.
- Dropbox works the same way: the connected-apps page fetches its app list
  (`account/get_linked_apps`) and the connector reads that response, because each app's details sit
  in a collapsed panel that only a click opens.
- `microsoft-work` reads My Apps' own tiles response the same way. Loading Security info lets the
  tenant start its MFA prompt in a hidden page. When the prompt asks for a code from the
  Authenticator app, nothing reaches you and the page closes unanswered. When your default method
  is SMS or a push notification, Microsoft may send one on every run: do not approve a push you did
  not start, and leave `microsoft-work` out of `services` if that happens.

## GitHub security settings (`github`)

```bash
./segurata inventory github
```

Reads, through the signed-in `gh` CLI, the security settings of the account, of every
organization it owns and of every repository it administers. Apps, sessions and the account's own
keys stay in `connected-apps`. Every request is `gh api --method GET` on a path from a fixed list
(`connectors/github/allowlist.go`); anything else is refused before `gh` runs. The two
remediations (`github.secret-scanning.enable`, `github.workflow-token.read`, see
[Remediation](#remediation)) write only after a confirmed plan, through their own allowlist.

| Finding | Severity |
|---|---|
| Account without two-factor authentication | `critical` when it owns organizations, `high` otherwise |
| Organization that does not require 2FA; members or outside collaborators without 2FA (logins in the evidence) | `high` |
| Organization base permission `write` or `admin`; workflows get a read and write `GITHUB_TOKEN` by default; new private repositories get no default code security configuration with secret scanning and push protection (Team and Enterprise plans; Free cannot buy it, and the status says so) | `medium` |
| Members can create public repositories; any action from any author allowed; workflows can approve pull requests; new public repositories without secret scanning and push protection by default | `low` |
| Repository: one finding listing everything wrong with it, at the severity of the worst: webhook over `http://` or with SSL verification off (`high`, `medium` when inactive; only scheme and host are kept, since a hook URL can carry a token), deploy key with write access, secret scanning or push protection off in a public repository, public repository whose workflows get a write token while Actions are enabled (`medium`) | worst issue |
| Rolled up, one finding per owner listing the repositories, where one decision fixes them all: secret scanning or push protection off in private repositories (`medium`; they need the paid Secret Protection add-on) | `medium` |
| Rolled up likewise: Dependabot security updates off; secret scanning, push protection or a write workflow token in forks (a fork's workflows stay off until enabled in its Actions tab, which the API does not show); public default branch without classic protection or an active ruleset (opt-in) | `low` |

Config, optional, under `connectors.github.config`:

| Key | Default | Meaning |
|---|---|---|
| `max_repos` | 500 | Repositories inspected, sorted by name; the status says how many were left out |
| `branch_protection` | false | Also check the default branch of public repositories (one or two more requests each) |

- Scopes: `read:user` (account 2FA), `read:org` (organizations and their code security
  defaults), `admin:org` (owner-only settings, Actions permissions, members without 2FA), `repo`
  (private repositories, webhooks, deploy keys). A missing one is a `noscope` status with the
  command that adds it, such as `gh auth refresh -h github.com -s read:user`; the rest still runs.
  gh's default login lacks `read:user` and `admin:org`.
- Rate limit: it reads the quota first (free) and stops when fewer than 300 requests would remain,
  leaving them for your other tools. Repositories cut off by the limit are counted in the status,
  never half-reported. About 4 requests per repository, four at a time: 500 repositories take
  around four minutes.
- Archived repositories are skipped (GitHub makes them read-only); so are repositories you can
  read but not administer, and settings of organizations you do not own.
- Not checked: Actions secrets (a count says nothing about risk, costs a request per repository,
  and the names are on each repository's settings page); the fine-grained token policy of an
  organization (no REST endpoint for a user token). The organization's deprecated
  `*_enabled_for_new_repositories` fields are not read: code security configurations replaced them.

## Google Workspace administration (`workspace`)

```bash
./segurata inventory workspace                    # every configured tenant
./segurata inventory workspace:example.com      # one tenant
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

Config, one key per tenant in `~/.config/segurata/config.json`:

```json
"workspace:example.com":   {"config": {"domain": "example.com"}},
"workspace:example.org": {"config": {"domain": "example.org", "inactive_days": 60}}
```

| Key | Default | Meaning |
|---|---|---|
| `domain` | required | The tenant's primary domain |
| `cloudsdk_config` | `~/.config/segurata/gcloud-<domain>` | gcloud config folder holding this tenant's credentials |
| `quota_project` | the OAuth client's project | Sent as `X-Goog-User-Project`, for when the Admin SDK API is enabled in another project |
| `inactive_days` | 90 | Days without a sign-in before an account counts as inactive |
| `gcloud_path` | `PATH`, then the standard install folders | gcloud binary, as for `gcp` |

Credentials, once per tenant. segurata never signs in and never creates OAuth clients or
service accounts:

1. In a Google Cloud project of the tenant, enable "Admin SDK API" and create an OAuth client ID
   of type "Desktop app". gcloud's default client does not allow scopes outside Google Cloud.
2. Sign in with an admin account of the tenant in a separate gcloud config, so the usual ADC is
   left alone:

   ```bash
   CLOUDSDK_CONFIG="$HOME/.config/segurata/gcloud-example.com" \
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

## Cloud and AI providers

Each of these has its own page with endpoints or commands, severities, config keys and setup:

- `aws`, `azure`, `vercel`, `supabase` and `cloudflare`: [docs/cloud-connectors.md](docs/cloud-connectors.md)
- `gcp`: [docs/gcp-connector.md](docs/gcp-connector.md); Prowler's GCP checks on top of it:
  [plugins/prowler](plugins/prowler/README.md)
- `openai`, `anthropic` and `openrouter`: [docs/ai-connectors.md](docs/ai-connectors.md)

## Plaintext secrets on disk (`local-secrets`)

```bash
./segurata inventory local-secrets
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
- Incremental history: after the first full scan of a repository, later runs scan only the commits
  added since, and replay the earlier leaks from `~/.cache/segurata/gitleaks/<repo-hash>.json`
  (mode 0600; fingerprints, redacted hints, paths and commits, never values). A rewritten or
  deleted ref, a new gitleaks version or config, or a new fingerprint key means a full scan again.
  The status line says how many repositories were unchanged, incremental or full. Details:
  [docs/architecture.md](docs/architecture.md#incremental-git-history-scan).
- Database dumps in git: every repository's tracked files and every file ever added to its
  history are matched against dump names (`*.sql`, `*.sql.gz`, `*.dump`, `*.pgdump`, `*.sqlite3`,
  `*.db`, database `*.bak`, large `prod`/`backup` exports), minus schemas, migrations, seeds,
  vendored code and small files. Each hit is one `data_dump` finding with its size, first commit,
  whether it is still in the tree, whether it was pushed and, through `gh`, whether the remote is
  public; the first 4 KiB of one blob are read to recognise a dump header, nothing more. gitleaks
  matches inside a dump are marked `in_data_dump` and left out of rotation, except AWS, Stripe
  live, GitHub and GitLab keys and private keys. Results are cached per repository in
  `~/.cache/segurata/datadumps/`. What to do: [docs/secrets.md](docs/secrets.md#data-dumps-in-git);
  details: [docs/architecture.md](docs/architecture.md#data-dumps-in-git).
- SSH keys in `~/.ssh`: type, permissions and whether they have a passphrase
  (`ssh-keygen -y -P ""`). A key without one is an `exposure` finding; a key with one, an `info`
  `setting`.
- Severity is the rotation priority of that one copy (P0 `critical` … P3 `low`, see
  [Rotation ledger](docs/architecture.md#rotation-ledger)). Noise is `info`: generic matches
  (`assignment`, gitleaks `generic-api-key`), anon or expired JWTs, expired STS keys, public OAuth
  clients, encrypted private keys, copies in other people's repositories, and the other cases in
  [what counts against the owner](docs/architecture.md#what-counts-against-the-owner). Noise is
  not emitted by default: the run's status line counts it by type and by repository.
- A finding in a working file that group or others can read carries the `file.chmod600` action:
  `segurata remediate <finding-id>` closes the file. The secret still has to be rotated. A file
  whose own mode is open (644) but that a closed parent folder hides gets the same action as
  low-severity hardening, one plan per top folder (`~/src/acme/app`), in case the folder is opened
  later.
- Requirements: `rg` (ripgrep), `git`, `ssh-keygen`; `gitleaks` for history; `gh` (optional) for
  the visibility of repositories holding a dump. The disk scan takes
  about a minute; the history scan of ~330 repositories takes most of the run.
- Config (`connectors.local-secrets.config`): `repos_root`, `skip_git_history` (true skips
  gitleaks and keeps the fast scan), `git_cache` (default true; false scans every repository's
  whole history and leaves the cache alone), `gitleaks_workers` (default 6), `gitleaks_timeout`
  (per repository, default `"10m"`), `data_dumps` (default true; false turns the dump check off,
  `"only"` runs nothing else, about a minute cold and seconds from the cache), `emit_noise`
  (default false; true emits the noise findings too), `owned_owners` (GitHub users and
  organizations that are yours, added to what `gh api user` and `gh api user/orgs` say; see
  [repository origin](docs/architecture.md#what-counts-against-the-owner)), `liveness` (off by
  default; see "Liveness" below).
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

The key lives at `~/.config/segurata/fingerprint.key` (32 random bytes in hex, created with mode
0600 on first use). Keep it: with a new key every fingerprint changes and the rotation ledger sees
every secret as new.

### Rotation ledger

```bash
./segurata rotations sync                    # from the latest local-secrets inventory
./segurata rotations list --priority P0,P1   # what to rotate first
./segurata rotations list --owner not-mine    # secrets that name someone else's account (mine, not-mine, unknown)
./segurata rotations next --priority P0      # the most urgent item and exactly what to do (--log records it was shown)
./segurata rotations show <id>               # locations, where the new value goes, rotate URL, whose it is and why
./segurata rotations replace <id>            # after rotating: plan with the new value from the clipboard
./segurata rotations replace <id> --apply [--to-keychain ANTHROPIC_API_KEY]
./segurata rotations done <id> --note "rolled in the dashboard"
./segurata rotations snooze <id> --until 2027-01-15
./segurata rotations ignore <id> --reason "test fixture"
./segurata rotations reopen <id>
./segurata rotations ignore --path ~/src/app/log/test.log --reason "test fixtures"   # every item found only there
```

`rotations sync`, `done`, `snooze`, `ignore` and `reopen` are `track`'s verbs on secrets only.
Plaintext replacement requires a file owned by your account, outside the Git index and private
under POSIX permissions. The command checks the entire plan again before updating the Keychain
or writing files. See the [rotation instructions](docs/secrets.md#shell-variables-from-the-keychain).

One item per secret fingerprint, with its priority (P0 to P3), the reasons in plain words, every
location, `used_in` (the config, `.env` and rc files that hold it, where the new value must go)
and the provider page where it is rotated. These are the tracker's rotate items (see "Tracker and
status"); ids are the first 8 characters of the fingerprint, and the tracker's `T-` id works too.
They hold no secret values. A secret marked done that the next sync still finds with
the same fingerprint in a working file (config, `.env`, rc, repo working tree) is reopened: a
program still reads the old value there. Copies only in git history, transcripts or logs are dead
after revocation, so the item stays rotated with a one-time note. Generic matches are left out
unless `sync --include-noise`. Details: [docs/architecture.md](docs/architecture.md#rotation-ledger).

#### Attribution

Each secret is attributed `mine`, `not-mine` or `unknown`, offline: attribution never sends a
leaked secret to a provider to ask whose it is (the liveness check below, off by default, asks
whether it works, and only for owners you allow; its lookups with your own credentials may name the
account too). At scan time `local-secrets` reads what the value itself
names (the AWS account an access key id encodes, the Slack workspace of a webhook, the GCP project
number of an OAuth client id) and, for AWS and Google credentials, what the file around it names
(the key id next to a secret access key, `project_id` in a credentials file), plus the author of
the commit that added it; only those identifiers are stored. Sync compares them with the owner's
accounts: the AWS accounts, GCP projects, Slack workspaces, GitHub owners and emails the aws, gcp,
connected-apps, github and google-personal connectors report, the git email, and config `owned`
for what no connector reaches (an old AWS account):

```json
{"owned": {"aws_accounts": ["123456789012"], "gcp_projects": ["old-project"], "slack_teams": ["T0ABC1234"],
           "github": ["my-old-org"], "emails": ["me@old-domain.com"]}}
```

A secret naming one of them is `mine`; one naming only accounts that are none of the owner's known
ones is `not-mine`; anything else (no account named, or none of the owner's of that kind known) is
`unknown`. Who committed it and whose repository holds it are shown as hints and never decide.
`segurata accounts owned` lists every known account and where it comes from. Details:
[docs/architecture.md](docs/architecture.md#attribution).

#### Liveness

Most old leaked keys no longer work. With the liveness check on, `local-secrets` tries each
distinct secret once, at scan time, against its provider's read-only identity endpoint (OpenAI and
Anthropic models, OpenRouter key, GitHub and GitLab user, AWS `sts:GetCallerIdentity`, Google
Gemini models, Slack `auth.test`, Stripe balance, SendGrid scopes, Telegram `getMe`, Hugging Face
and npm whoami, xAI key info, Groq models, Notion bot user, Cloudflare token verify, DigitalOcean
account, Sentry organizations, Linear viewer). These calls read identity or account metadata.
Secrets seen only in cached git history are read again from their commit when needed.

```json
{"connectors": {"local-secrets": {"config": {"liveness": {"enabled": true, "owners": ["mine"]}}}}}
```

`owners` defaults to `["mine"]`. Candidates attributed to another owner are refused.
Adding `"unknown"` also tries credentials whose owner could not be determined.
`providers` narrows the list. A live key that left the machine is P0; a dead one (the provider's
body carries its documented signal for an invalid, revoked or expired key; a bare 401 is unknown)
is closed as done, "key no longer valid (checked <date>)", once no working file holds it, and opens
again if a later check finds it live or a working file holds it again; an unknown answer changes
nothing.
Results are cached by fingerprint in `~/.cache/segurata/liveness.json` (live 1 day, dead 7 days)
and hold no value. `rotations list` shows a LIVE column and, like `status`, "Liveness checked for N
of M secrets". Endpoints, documentation and limits:
[docs/architecture.md](docs/architecture.md#liveness).

Two kinds of secret cannot be tried by themselves, and are looked up with your own credentials
instead, without sending the secret anywhere (for mine and unknown secrets, whatever `owners` says):

- A lone AWS access key id (no secret key next to it) is compared with the IAM inventory of each
  of your aws CLI profiles (`iam list-users`, `iam list-access-keys`, `iam get-account-summary`):
  Active is live, Inactive dead, absent from an account read whole and without root keys dead.
  The profiles need what SecurityAudit grants; without it the key stays unknown and the status
  line says what to allow. `aws_profiles` picks the profiles (default: all).
- A private key's public half is derived in memory and looked up among your GitHub SSH and signing
  keys, the deploy keys of your 30 most recently pushed repositories (through `gh`, which needs
  `read:public_key` and `read:ssh_signing_key`), `~/.ssh/authorized_keys`, and with `ssh_hosts`
  (opt-in, at most 20) the `authorized_keys` of those hosts over `ssh -o BatchMode=yes`. Registered
  anywhere is live; registered nowhere is `unregistered`, one priority lower (not proof it is
  dead); a PEM key found nowhere may sign TLS or JWTs and stays unknown.

```json
{"liveness": {"enabled": true, "aws_profiles": ["prod"], "ssh_hosts": ["deploy@build1"]}}
```

The guided loop is `next`, rotate at the provider, `replace`, `next` again. `next` prints one item:
what it is (redacted), why it is urgent, where it leaked, the provider page with a few checked
steps for that service, the files that need the new value and the commands to run. `replace`
reads the new value from the clipboard (or a pipe with `--stdin`; never an argument), checks by
fingerprint that it is new and that the old value is still where the scan saw it, shows a plan
with redacted values and, with `--apply` and a confirmation, rewrites each `used_in` file
atomically, checks the result, marks the item rotated and clears the clipboard. With
`--to-keychain <service>` the new value goes to the Keychain and rc lines become
`export NAME="$(security find-generic-password -a "$USER" -s <service> -w)"`, as
[docs/secrets.md](docs/secrets.md#shell-variables-from-the-keychain) recommends. No backup unless
`--backup`: a backup is one more plaintext copy of the old value.

### Redacting trails

```bash
./segurata redact --trails                      # dry run: files, matches per file and per type
./segurata redact --item <id> --apply           # one secret, in every transcript, history and log
./segurata redact --trails --min-priority P1 --apply
```

Agent transcripts, shell histories and logs keep pasted secrets in plaintext. Rotation is still
needed (a transcript already reached the model provider), but the local copy can go: `redact`
replaces each secret `local-secrets` reports as non-noise with `[REDACTED:<type>:<fingerprint8>]`,
which still points at its rotation item. Without `--apply` it only lists files, match counts per
file and per type, and bytes replaced. With `--apply` it asks for confirmation, rewrites each
file atomically keeping its mode and modification time, scans the result again and notes
"redacted from N trail files" on each rotation item. It never touches working files (config,
`.env`, rc), files modified in the last two hours (`--min-age`) or files a running `claude` or
`codex` has open; JSONL lines stay valid JSON, zsh history keeps its `: <ts>:<d>;cmd` format. No
backup unless `--backup`. Details: [docs/architecture.md](docs/architecture.md#redaction).

## macOS and Brave posture (`macos`)

```bash
./segurata inventory macos
./segurata inventory --verbose macos   # also logs the checks that pass
```

Read-only checks without `sudo`: FileVault, SIP, Gatekeeper, firewall and stealth mode, automatic
update settings and pending updates (`softwareupdate -l`, capped at 120 s), screen lock, automatic
login and guest account, whether other accounts can read your home folder, local accounts and
what deleted ones left behind, Time Machine backups, endpoint security agents, TCP ports listening
outside loopback (instead of `systemsetup -getremotelogin`, which needs admin), each SMB share
point behind port 445 (from `sharing -l -f json`), login and background items (`sfltool dumpbtm`,
flagging those without a developer signature), and whether Brave runs with
`--remote-debugging-port`. Browser extensions are the `browser-extensions` connector, below.

- A passing check emits no finding (only a log line with `--verbose`); a check that cannot run here
  is an `unsupported` status, and one whose tool failed or timed out is an `error` status that says
  so. Findings are kind `setting`.
- Idle lock: the screen locks when the screen saver starts or the display sleeps. The check reads
  the screen saver's `idleTime` with `defaults -currentHost read com.apple.screensaver`, then the
  global domain when the per-host key is unset, and `displaysleep` from `pmset -g`. It passes when
  the earlier of the two is 10 minutes or less; longer is `low`, both off is `medium`, and a failed
  read is an `error` status naming what could not be read.
- Login and background items: `sfltool dumpbtm` gets two minutes (it slows down on a busy Mac). When
  it fails or answers nothing, the check lists one item per launchd label from the plists in
  `/Library/LaunchDaemons`, `/Library/LaunchAgents` and `~/Library/LaunchAgents` and the
  `launchctl list` jobs no plist names, leaving out Apple's and the transient `application.*` jobs
  launchd creates for running apps. Either way, a plist whose `Program` (or `ProgramArguments[0]`)
  does not exist, or a helper in `/Library/PrivilegedHelperTools` from a vendor no installed app
  belongs to (by the first two labels of the bundle id, e.g. `com.tunnelbear`), is a `low`
  "leftover privileged helper" finding instead of a background item. Binary plists are read with
  `plutil -convert xml1 -o - <file>`, allowed for that file only.
- A listening port that would be an `info` row (an app's own network feature) is added to the
  background item that runs the process, when there is one, instead of getting its own row.
- The remote debugging port is a `high` finding even though the google-personal and connected-apps
  connectors need it: while the port is open, any local process can drive the browser with every
  signed-in session. Start Brave with the flag only for those connectors.
- File Sharing gives a medium finding for port 445 and one `share_point` finding per share point,
  with its name, path, whether the path exists, guest access and read-only. A share open to guests
  is `high`; so is an orphaned record whose folder no longer exists (Migration Assistant leaves
  these behind for users that were never recreated); any other shared folder is `medium`.
- Local accounts (`dscl . list /Users UniqueID` and `NFSHomeDirectory`, `dseditgroup -o
  checkmember -m <user> admin`, `last -1 <user>`): every human account (UID 500 and up, not a
  `_service` account) other than yours is a `local_account` finding naming it and its last login:
  `high` when it is an administrator, `low` when it has no home folder or no login since wtmp
  begins, `medium` otherwise. The fix is to delete temporary accounts and give the next repair
  technician a standard account deleted afterwards, or the Guest User. The per-account commands are
  allowed only for the accounts the same run's `dscl` listing returned. The guest account is the
  existing `guest-account` check.
- Leftovers of deleted accounts: an orphaned File Sharing record under `/Users/<name>` whose home
  folder is gone is the share point finding above, which names the deleted account. Items owned by a
  UID no local account has, in `/Users/Shared` and `/Library/Application Support` (two levels) and
  in `/Library/LaunchAgents` and `/Library/LaunchDaemons`, are one `orphaned_files` finding per
  folder listing up to 20 paths: `low`, or `high` in the launchd folders because those start a
  program automatically. Outside the launchd folders only UIDs from 500 up count: an uninstalled
  security agent leaves folders owned by its removed service account below 500 (ESET's 404).
- Time Machine (`tmutil destinationinfo -X`, `tmutil latestbackup`, and
  `/Library/Preferences/com.apple.TimeMachine.plist` through `plutil -convert xml1`, whose
  `LastKnownEncryptionState` and `DiskImageKeychainUUID` say whether a destination is encrypted;
  tmutil does not): no destination is `high`, an unencrypted destination is `high`, a set-up
  destination that never completed a backup is `high`, a latest backup older than 7 days is
  `medium`. When `latestbackup` cannot mount the destination, the preferences' snapshot dates date
  the latest backup. If tmutil is refused (no Full Disk Access) the check is an `unsupported`
  status; `segurata doctor --connector macos` says so with the fix.
- FileVault's recovery key is not checked: `fdesetup haspersonalrecoverykey` and
  `hasinstitutionalrecoverykey` need root (checked on macOS 15.6.1).
- Endpoint agents (ESET, Sophos, CrowdStrike, SentinelOne, Microsoft Defender, Malwarebytes,
  Bitdefender, Kaspersky, Avast/AVG, Norton/Symantec, Trend Micro, Intego, Jamf), from launchd
  plists, `/Applications`, their folders, running processes and service accounts: an installed or
  running agent is an `info` `endpoint_agent` finding; one with no app and nothing running is a
  `low` leftover of an uninstall.
- Every command it runs is on an exact allowlist in `connectors/macos`. Takes about half a minute
  because of `softwareupdate` and `sfltool`.

## Browser extensions (`browser-extensions`)

```bash
./segurata inventory browser-extensions
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
  later day. Name it with `"browser-extensions": {"config": {"primary": ["<extension id>"]}}`;
  `primary` must be a list of extension ids, and anything else stops the run with an error.
- Not automatable: changing profile files while the browser runs is unsafe. Each finding links
  `brave://extensions/?id=<id>` (or `chrome://`) and names the profiles to open it in.
- No network calls. Checking the Web Store (an extension pulled from the store, a change of owner)
  is a future enhancement.
- To keep an extension the verdict disagrees with: `segurata accept <id> --reason "..."`.

## Report

```bash
./segurata report                                   # terminal text
./segurata report --format html --out report.html   # one self-contained page, mode 0600
./segurata report --format md --out report.md
```

One page from the latest run of every connector instance (`out/<date>/<name>.jsonl`, the same
files `remediate` reads), the accepted risks and the secrets to rotate, both from the tracker. The
report is the per-run view; `segurata status` is the tracker's:

- Headline: the tracker's items counted as `status` counts them (open by priority and theme,
  done, accepted, merged…), then the findings of the latest runs as a note and a table by
  connector instance (run date, severities, accepted, statuses needing attention).
- Setup blockers: the tracker's setup items, as in `status`, each with what to do and the
  `segurata inventory <name>` that checks it afterwards.
- Changes in the last 7 days: items found, closed, verified by a later run and reopened, from the
  tracker's history, the latest listed. Before the first `track sync` the report syncs a copy of
  the tracker in memory (nothing is saved), so every item reads as new.
- Top findings, worst first and grouped by connector, each with its remediation, its page and
  `segurata remediate <id>` when automatable.
- Rotation ledger: open rotate items by priority, the first P0 items (redacted hint, exposure, reason,
  rotate URL; never a location) and snoozes past their date.
- Accepted risks, with the expired ones and the ones the latest run no longer reports.

`--min-severity` (default `low`) and `--top` (default 10 per connector)
trim the lists; `--dir` names another inventory directory. The HTML page has no script and no
external asset, follows the system's light or dark mode and fits a phone. Written to a file, the
report gets mode 0600: it names accounts, services and paths. It never contains a secret value,
because findings and the tracker never hold one.

## Remediation

```bash
./segurata remediate --list                # automatable findings of the latest run, one line per group
./segurata remediate <id>                  # the exact plan; changes nothing
./segurata remediate <id> --apply          # asks "Apply? [y/N]", applies, re-checks
```

One finding at a time, or one group: some actions fix every finding of a group in one plan (all
public repositories of a GitHub owner, every expired secret of an Azure tenant), which `--list`
shows as one line and the plan lists finding by finding. The plan shows the commands or HTTP
requests, whether they need sudo, the side effects and how to undo them, or that they cannot be
undone. With `--apply` it asks for confirmation (and refuses without a terminal unless `--yes`),
then runs that connector again and checks that no finding of the plan still offers the action.
Commands that need root run as `sudo <command>` on your terminal, so sudo asks for your password
itself; segurata never sees it. An interactive command (`gh auth refresh` opens a browser) runs on
your terminal too and is refused without one, `--yes` or not. Design:
[docs/architecture.md](docs/architecture.md#remediation).

| Action | What it runs | Undo |
|---|---|---|
| `macos.firewall.enable` | `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on` | `--setglobalstate off` |
| `macos.firewall.stealth` | `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on` | `--setstealthmode off` |
| `macos.smb.share-remove` | `sudo /usr/sbin/sharing -r <name>` (orphaned records and shared folders without guest access) | `sudo /usr/sbin/sharing -a <path> -n <name> -S <smb name> -s <flag> -g <flag> -R <0/1>` with the record's current flags; not applicable for an orphan, whose folder no longer exists |
| `macos.smb.guest-off` | `sudo /usr/sbin/sharing -e <name> -g 000` (live shares open to guests) | `sudo /usr/sbin/sharing -e <name> -g 001` |
| `macos.home.private` | `/bin/chmod 700 <home>`, no sudo, when group or others can read the home folder (every user is in `staff`, so 750 is as open as 755; 711 passes, as CIS allows) | `/bin/chmod <old mode> <home>` |
| `file.chmod600` | Makes the file in the finding's `evidence.path` private: mode 600, or 700 when its owner could execute it. With a group, every file of the group once | `chmod <old mode> <path>` per file |
| `github.secret-scanning.enable` | Per GitHub owner: `gh api --method PATCH --silent /repos/<owner>/<repo> -f 'security_and_analysis[secret_scanning][status]=enabled' -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'` for each public repository you administer where either is off (only the fields that are off). Private repositories are left out: there it needs GitHub Secret Protection, a paid add-on | the same request with `disabled` |
| `github.workflow-token.read` | Per GitHub owner: `gh api --method PUT --silent /orgs/<org>/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=<as it is>` for the organization first, then `/repos/<owner>/<repo>/actions/permissions/workflow` for each repository whose default is write | the same request with `write` |
| `connected-apps.gh.drop-scopes` | `gh auth refresh -h github.com -r delete_repo,admin:org[,admin:enterprise]`, the removable scopes gh's token holds now, in your terminal (browser approval) | `gh auth refresh -h github.com -s <the same scopes>` |
| `azure.app-secret.delete-expired` | Per tenant: `az ad app credential delete --id <appId> --key-id <keyId> --only-show-errors` for each client secret that is still registered and already expired | none: a deleted secret cannot be restored (it had expired) |
| `openai.key.delete-unused` | `DELETE /v1/organization/projects/<project>/api_keys/<key>` or `DELETE /v1/organization/admin_api_keys/<key>`, for a key never used or idle for over 90 days, with `OPENAI_ADMIN_WRITE_KEY` | none |
| `openrouter.key.delete-unused` | `DELETE /api/v1/keys/<hash>`, for an enabled key never used, idle for over 90 days or without recorded use since the end of 2025, with `OPENROUTER_MANAGEMENT_WRITE_KEY` | none |

Every plan is computed from a fresh read (the repository, the token's scopes, the tenant's app
registrations, the key's last use), not from the finding: what changed since the inventory is left
out and named, and a key back in use, or the key segurata reads with, is refused. The allowlist of
exact command lines and HTTP routes is built from that same read at apply time.

Dropping `admin:org` from gh's token makes the github connector report each organization's
settings as `noscope` ("organization settings need admin:org"), and `github.workflow-token.read`
can then no longer change an organization's default. Give segurata a read-only fine-grained token
in `GH_TOKEN` for its runs if it should hold no write scope at all; `gh auth refresh` cannot change
a token that comes from the environment, and the plan refuses then.

### Write credentials

The inventory keys stay read-only. A remediation that writes through a provider's API uses a
separate write key, referenced under `remediation_secrets` of the same connector instance. Only
`remediate --apply` resolves it, after you confirmed the plan; no inventory ever reads it, and a
`*_WRITE_KEY` under `secrets` is rejected when the config loads. Without it, the dry run shows the
plan marked blocked, with these instructions, and `--apply` refuses before asking.

```sh
security add-generic-password -s segurata-openai-admin-write -a "$USER" -w      # admin key with write access to API keys
security add-generic-password -s segurata-openrouter-admin-write -a "$USER" -w  # management key, access level read/write
```

```json
"openai":              {"secrets": {"OPENAI_ADMIN_KEY": "keychain:segurata-openai-admin"},
                        "remediation_secrets": {"OPENAI_ADMIN_WRITE_KEY": "keychain:segurata-openai-admin-write"}},
"openrouter:personal": {"secrets": {"OPENROUTER_MANAGEMENT_KEY": "keychain:segurata-openrouter-personal"},
                        "remediation_secrets": {"OPENROUTER_MANAGEMENT_WRITE_KEY": "keychain:segurata-openrouter-personal-write"}}
```

You can create the write key for the session and delete it afterwards. A 401 or 403 on apply
means the key cannot write; the error names it.

External connectors speaking protocol 2 add their own actions (`segurata connectors` lists
them after `remediates:`). The plan, the confirmation and the check afterwards are the same; the
connector runs its own plan as you, and segurata refuses any plugin plan that needs sudo
([docs/connectors.md](docs/connectors.md#plan-v2)).

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

After `--apply`, the check waits 5 seconds and needs the finding fixed in two inventories in a row:
a restarted process can drop its ports for a moment and open them again. Fixed means no fresh
finding with the same id still offers the action: a GitHub repository finding that keeps a deploy
key issue is fixed as far as secret scanning goes, and then offers the next action
(`github.workflow-token.read`) if its workflow token is still writable.

## Accepted risks

```bash
./segurata accept <id> --reason "AI agents drive Brave over CDP" [--until 2027-03-31]
./segurata accept --list
./segurata unaccept <id>
```

A finding you keep on purpose stays in `out/<date>/*.jsonl` with an `accepted` field, but leaves
the summary and `remediate --list`, which print how many were hidden. With `--until`, it shows
again after that day, marked "(acceptance expired)". Acceptances are tracker items with status
`accepted`; accepting one finding of a grouped item (one of five orgs) moves it to an item of its
own first. `unaccept` takes the finding id or the item id. Details:
[docs/architecture.md](docs/architecture.md#accepted-risks).

## Scheduled runs

```bash
./segurata schedule install                         # print the launchd agent; changes nothing
./segurata schedule install --every 12h --apply     # write and load it, after "Apply? [y/N]"
./segurata schedule status
./segurata schedule uninstall --apply
```

A launchd user agent (`~/Library/LaunchAgents/com.segurata.inventory.plist`) runs an inventory
every day (or `--every`), writes `~/.segurata/last-report.md`, and posts a macOS
notification when its tracker sync opens a P0 or P1 item, new or reopened. By default
it runs every connector; `--connectors macos,local-secrets,hibp` picks them. The browser connectors
(`google-personal`, `connected-apps`) run only when Brave answers at `cdp_url`, in hidden pages that
never take focus; when it does not, or another browser holds the port, they are recorded as not
inspected ("browser not reachable over CDP"), nothing they found is closed, and no other browser is
started. After `"browser_stale_days"` (default 7) of that, one notification says so. Logs go to `~/Library/Logs/segurata/`, inventories to
`~/.segurata/out`, pruned to the last 30 days after each run (`"keep_runs_days"` in the config; the
latest run of each connector and the one before it always stay). Install it from the binary you
will keep: the agent runs that
exact path, with the PATH you had when installing. On Linux it prints a systemd user timer to
install by hand. Details: [docs/architecture.md](docs/architecture.md#scheduled-runs).

## Plan

Actions by area and priority, with verified sources and what a script can audit: [docs/plan.md](docs/plan.md).

## Manual review

Services without a connector, with the page where you revoke access: [docs/manual-review.md](docs/manual-review.md).

## Security

Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes; it also lists the
properties segurata promises (read-only inventory, no secret values in output, confirmed and
allowlisted changes, standard library only). Releases: [docs/releasing.md](docs/releasing.md).

## License

[Apache License 2.0](LICENSE).
