# Architecture

segurata inventories the digital footprint of a person or a small company (consumer accounts,
clouds, AI providers, secrets on disk), assesses it and, only when asked, cleans it up.

Everything in this repository is written in English: code, comments, finding text, docs and commit
messages.

## Pieces

```
segurata (Go binary)
├── core: config, secret references, connector execution, output, report
├── built-in connectors (compiled in)
└── external connectors: segurata-<name> executables on PATH, in any language
```

Both kinds of connector share one contract. A built-in one implements the Go interface
`connector.Connector`; an external one speaks the protocol below over stdin/stdout and the core
wraps it in that same interface. The rest of the program cannot tell them apart.

### Verbs

Every verb in the `commands` table of `cmd/segurata/main.go` has a row here, and a test checks that.

| Verb | What it does | Changes anything outside |
|---|---|---|
| `connectors` | Lists the built-in and external connectors | Never |
| `inventory` | Lists what exists: grants, keys, settings, spend; each connector assigns severity and remediation to its findings | Never |
| `remediate` | Applies one remediation plan, for one finding or a named group of findings | Yes, one plan at a time, dry run unless `--apply`, explicit confirmation |
| `status` | The briefing from the tracker: what to do next, decisions, setup blockers, changes since the last status, accepted risks | Nothing by default; with `--mark-seen` segurata's own `tracker.json` (the "since" mark); with `--write` that mark plus `status.md` and `status.html` |
| `track` | Lists, shows and changes tracker items; `track sync` folds the latest runs in | Only segurata's own `tracker.json` |
| `accept` / `unaccept` | Marks a finding as a risk kept on purpose, or stops doing so | Only segurata's own `tracker.json` |
| `accounts` | Lists the accounts each connector saw and the owner's accounts; `watch` and `unwatch` change which accounts a connector inspects | `watch` and `unwatch`: the config (atomically, previous file kept) and segurata's own `tracker.json` |
| `signin` | Opens the pages where a browser connector needs a fresh sign-in, waits until they are through, then runs those connectors again | New browser tabs; segurata's own run files and `tracker.json` |
| `doctor` | Checks prerequisites: config, secret references, browser port, CLIs and sign-ins, state file modes | Never |
| `rotations` | Keeps the ledger of secrets to rotate (the tracker's rotate items) and guides each rotation | Only segurata's own `tracker.json`, except `replace --apply`: the `used_in` files and the Keychain, after confirmation |
| `report` | Summarises the latest runs, what changed, the secrets to rotate and the accepted risks | Never (writes only the `--out` file) |
| `redact` | Replaces the secrets `local-secrets` finds in trail files (agent transcripts, shell histories, logs) with `[REDACTED:<type>:<fingerprint8>]` | With `--apply` and confirmation: those trail files, never a working file; a history note in `tracker.json` |
| `schedule` | Installs, removes or shows the scheduled inventory (a launchd user agent on macOS) | With `--apply` and confirmation: the agent's plist, loaded with `launchctl` |
| `version` | Prints the version, commit and build date | Never |

`remediate` always states the exact scope of what it will remove before acting. On Google,
"Remove all access" on an app's permissions page also removes that app's Sign in with Google
link; that has to be said up front, not discovered afterwards.

## Finding model

A connector emits JSON records (`internal/finding`): one `finding` per thing worth looking at
(connector, account, resource, kind, severity, title, evidence, dates, remediation) and one
`status` per account saying whether it could be inspected (`ok`, `reauth`, `signedout`,
`noscope`, `unverified`, `missing_credentials`, `unsupported`, `error`). The core fills the
derived fields: the stable id (a hash of connector, instance, account, resource type and resource
id), the connector name, `observed_at`, `automatable` and `accepted`. `evidence` never holds a
secret. Fields, kinds, stable-id and severity rules: [connectors.md](connectors.md#finding-model).
The core ends each run with a `run_end` record (next section).

## Run completeness

A finding missing from a run is resolved only if that run looked where the finding was. A run
killed halfway, a connector that stopped at the GitHub rate limit, a gitleaks scan that timed out
on one repository, a GCP project with permission denied or a signed-out service all leave findings
out without fixing anything. So every run says what it covered, and every consumer checks it
before calling a finding gone.

**Envelope.** `run.Inventory` writes one last record per connector instance:

```json
{"type": "run_end", "connector": "github", "started_at": "…", "ended_at": "…", "complete": false,
 "scopes": {"inspected": ["github:octo", "repo:octo"], "inspected_count": 2,
            "skipped": [{"scope": "repo:acme/api", "reason": "the GitHub API rate limit ran low"}],
            "skipped_count": 1}}
```

`complete` is true when nothing was skipped and the connector returned no error (then `error`
holds it). `secret_fingerprints` names, by key, the fingerprint of each secret the core resolved for
the instance (never the value; see "Correlation"). The lists are capped (50 inspected, 200 skipped); the counts are not. A file without
`run_end` was killed, is still running, or was written before this record existed.

**Scopes.** A finding belongs to a scope: its `scope` field when the connector inspects the
account in parts, otherwise its account (`finding.ScopeOf`). Examples: `repo:<owner>/<name>` and
`repo:<owner>`, `user:<login>` and `org:<org>` (github), `history:<repo>`, `dumps:<repo>` and `files` (local-secrets), the project
id and `billing:<id>` (gcp), the service name (connected-apps), `profile <name>` (aws),
`check:<id>` (macos). The run's
coverage is derived (`finding.Tally`):

- a status `ok` marks its account (or `scope`) inspected;
- any other status, `unverified` included, leaves its `scope`, or else its account, uninspected; a
  status with neither leaves everything uninspected;
- a connector declares what no status carries with `Emitter.Scope(id, false, reason)` (external
  connectors: a `scope` record);
- a connector error, a cancelled context, a timeout, a record that could not be written, or a run
  where no status said `ok` and nothing was declared inspected, leaves everything (`*`)
  uninspected; so does a skipped list over the cap;
- a skipped scope ending in `*` covers every scope with that prefix.

**Deadlines.** Each instance's inventory runs under a deadline: the instance's `timeout` in the
config (`"connectors": {"prowler": {"timeout": "10h"}}`, a Go duration), else the `timeout` its
connector declares in `describe` (local-secrets `6h`, prowler `12h`), else one hour. At the
deadline the connector's context ends, and the run ends with `error` "timed out after … (raise
connectors.<key>.timeout)", so nothing it left out closes. Every child process the core and the
connectors start is killed when its context ends and waited on for at most three seconds more
(`internal/proc`), so a wrapper script that does not exec its program cannot outlive a timeout.

A finding is not checked by a run when the run has no `run_end`, when everything was skipped, or
when a skipped scope matches its scope or its account (`finding.Coverage`).

**Consumers.**

- `runfile.LatestRuns` (and `LatestFiles`) take, per instance, the newest run with `run_end`,
  and the newest such run before it as the previous one; a newer file without `run_end` is passed
  over and named. When that run inspected nothing (its `run_end` skips `*`: the connector failed,
  or a scheduled run could not reach the browser), they also name the newest finished run that
  inspected something as its evidence. `runfile.Read` drops a half-written last line of such a file.
- `report` shows each instance's latest run and never calls a finding resolved; closing is the
  tracker's job (below). Its "Run completeness" section names
  partial runs and their skipped scopes, runs without `run_end`, and newer runs that did not
  finish; the headline marks them `(partial)` or `(no run_end)`. A latest run that inspected
  nothing and reported no finding is passed over for its evidence run, whose findings the report
  shows, and named there ("the run of … inspected nothing"). An accepted risk counts as no
  longer reported only when its scope was inspected.
- `track sync` marks a finding gone only when its scope was inspected, so it never closes or
  verifies an item on an incomplete run, and logs `not checked in run <label> of <ended_at>
  (<reason>)` once per run on each item it held back. Completeness protects findings, not
  statuses: a setup item's status ref counts as gone in any finished run (with `run_end` and no
  connector error) that does not report it, whatever that run inspected, so an aws `error`
  replaced by `noscope`, or a `reauth` an r2 profile no longer gets, closes its item as done,
  "verified (status no longer reported)". A run without `run_end`, or whose connector failed (it
  may have stopped before reporting), proves no status gone, except that one reporting the item's
  key again with other details (stale details, or a ref recorded before one ref per detail), or
  the same state for the whole instance (no account, which covers the per-account one), still
  retires the old ref.
- `remediate --apply` returns "could not verify the fix" (`remediate.ErrUnverified`) when the
  check run did not inspect the finding's scope, instead of reporting it fixed.

**Older files.** Files without `run_end` (from before this record, or killed) stay usable for
display: the report lists their findings and notes the unknown completeness. They never prove a
finding gone: nothing in them closes or verifies an item, and a finding missing from one is not
checked. Findings and tracker refs recorded before scopes existed carry no scope; for them any
skipped scope counts, so only a complete run proves them gone.

## Tracker

Runs and findings are ephemeral: each inventory rewrites them. The tracker (`internal/tracker`) is
the one durable record of what to do, what is done and what is pending.

State: `~/.segurata/tracker.json`, mode 0600 in a 0700 folder (`SEGURATA_HOME` names another
folder), outside any repository. Generated views live beside it (`status.md`, `status.html`) and
are never edited by hand. The file is JSON with a `schema_version`; it is the single source of
truth, and every change goes through the CLI.

### Ontology

- **Run** and **finding**: as above, with stable finding ids.
- **Item**: one thing a person would do.

```json
{"id": "T-0042", "key": "group:github|github_org_setting|check:org-2fa-not-required",
 "kind": "fix", "theme": "github-orgs", "title": "Two-factor authentication not required in 5 GitHub orgs",
 "status": "open", "priority": "P1", "priority_override": null, "severity": "high",
 "findings": [{"id": "b312fe6437ca5c65", "connector": "github", "account": "github:acme-labs",
               "title": "acme-labs does not require two-factor authentication", "severity": "high",
               "last_seen": "…", "gone": false}],
 "next": {"who": "you", "action": "Turn on \"Require two-factor authentication\" …",
          "command": "segurata track show T-0042", "url": "https://github.com/organizations/acme-labs/settings/security"},
 "status_at": "…", "verified_at": null, "created_at": "…", "updated_at": "…",
 "history": [{"at": "…", "event": "found", "action": "found", "detail": "5 findings"}]}
```

  - `id` is `T-` and a number from `next_id`: stable, never reused. `key` says what makes findings
    the same item; sync finds items by key.
  - `kind`: `fix`, `rotate` (one secret, by `fingerprint`, with its locations under `secret`),
    `decide` (with `decision`: question, options, answer, answered_at), `setup` (what keeps
    segurata from seeing an account) or `review` (a list to keep or prune).
  - `status`: `open`, `in_progress`, `done`, `accepted` (with `accepted`: reason, until,
    accepted_at), `ignored` (by the owner), `snoozed` (with `snoozed_until`), `reclassified`
    (closed by segurata: every current sighting of the secret is now noise, see "Rotation
    ledger"), `expected` (a setup item the config says to expect, see "Expected statuses") or
    `merged` (closed by segurata: another item, named by `merged_into`, owns the same problem, see
    "Correlation").
  - `priority` is computed: a rotate item's comes from the rotation model below; others map the
    worst linked severity (critical P0, high P1, medium P2, low P3). `priority_override`
    (priority, reason, at) wins when set.
  - `history` events are `found`, `seen`, `status`, `note`, `verified`, `reopened`, `decided`,
    `priority`, `reclassified` or `merged`; `action` keeps the precise verb (`done`, `auto-done`, `auto-reopen`,
    `snooze-expired`, `acceptance-expired`, `history-only`, `redacted`, `next`, …).
- **Theme**: `{id, title, description}`, seeded in every tracker: `rotations`, `data-dumps`,
  `transcripts`, the shared connector themes (`mac`, `browser-extensions`, `github-orgs`,
  `connected-apps`, `google`, `cloud`, `ai-spend`, from `finding.Themes`), `coverage`, `setup`,
  `decisions`, `other`. Each connector declares its theme in `describe`, a shared one or its own,
  which the first run that declares it adds (see connectors.md, "Theme and grouping"); the run's
  `run_end` carries it. local-secrets is filed by the tracker itself: data dumps apart from the
  secrets to rotate.

### Grouping

Info findings never make an item. The rest group as their connector declares on each finding
(`track`, see connectors.md, "Theme and grouping"); the tracker applies the declaration
(`group.go`) and keeps one rule of its own, for data dumps. What the connectors declare today:

| Findings | One item per | Kind |
|---|---|---|
| local-secrets secrets | fingerprint (rotate items, below) | rotate |
| local-secrets secrets in transcripts, shell histories and logs | local-secrets instance: "Redact secrets from N trail files", next step `segurata redact --trails`, severity capped at medium | fix |
| local-secrets `data_dump` | repository: "3 database dumps in the git history of ~/src/api (11 MB)", one `git filter-repo` for all its files, the files and sizes listed, docs/secrets.md#data-dumps-in-git as the page and the AEPD and EDPB breach guidance as the secondary step | fix |
| github org and repository-setting checks | check, across orgs ("Two-factor authentication not required in 5 GitHub orgs") | fix |
| github repositories | organization | fix |
| connected-apps Slack apps | workspace and severity | review |
| other connected-apps | account and title family ("27 X apps can post and delete posts as you"); the predicate agrees with the count (`textfmt.PluralPredicate`: "shared with them", "they are installed on") | review |
| google-personal OAuth grants | account and severity | review |
| gcp API keys, service-account keys, service-account roles | project | fix |
| openai, anthropic, openrouter API keys | instance, account and severity | fix |
| macos, aws | finding | fix |
| browser-extensions | extension | review |
| prowler (plugin) failed checks | check, across projects: "Log sink created fails in 40 projects (Prowler logging_sink_created)" | fix |
| anything that declares no group | account, resource type and title family (the title without the resource's name, quoted names and numbers blanked), titled by the worst finding: `Expired client secret of app "Billing" is still registered, and 69 more like it` | fix |
| a connector status other than `ok` | instance, account and state | setup |

A group's severity and priority are its worst finding's. When its scopes (projects, orgs,
accounts) sit at different severities, the title ends with how many sit at each, worst first:
"Log sink created fails in 40 projects (Prowler logging_sink_created) (1 medium, 39 low)". The
one production project that keeps a hygiene check at medium still makes it P2 work, and the split
shows that it is one project of P2 work, not forty.

A setup item keeps one ref per distinct status detail (`status:<key>#<hash of the detail>`), so
gcp's six "project X: permission denied …" statuses for one account are six refs of one item,
titled "gcp: permission denied on 6 projects for <account>" (or "… failed on 6 projects" when
the problems differ, "(N problems)" when the details name no common kind of scope). Its next step
puts the command the detail names into `next.command` (`gcloud auth login <account>` for "run
gcloud auth login for this account", `gh auth refresh -h github.com -s read:user`, a backquoted
`security add-generic-password …`), with the rerun at the end of the action; without one, the
command is the rerun. Actions are state-specific and name the real config key:
`connectors."<label>".secrets` for missing credentials, `connectors."connected-apps".config.services`
for a signed-out service, and `segurata track expect <id>` (see "Expected statuses") for a
limitation kept on purpose. An `unsupported` check that needs administrator rights asks for no
install.

A run whose `run_end` names no theme was written before connectors declared themes and grouping.
Its findings stay in the items that already hold them, under their titles and with the repository
and project their refs know, so upgrading segurata never moves a finding to another key; the next
run of that connector regroups them as it declares.

A finding that has an item of its own (key `finding:<id>`) goes there before any rule when it was
accepted or ignored on its own, or when its rule groups per finding anyway. Otherwise its rule now
groups it (data dumps were one item per file): the finding moves to the group and the old item,
left with nothing reported, closes as `merged` into the group's item.

An item can be blocked by a pending decision: the decision's option effects would close it, or it
is a data-dump item and the decision is about dumps (its key or question names them, as
"Purge the data dumps from git history?" does). Its next step then starts "Blocked by decision
T-0001 (…): answer it first." until the decision is answered, and status counts what each
decision unblocks (see "segurata status"). The title and next step come
from the rule and the worst finding's remediation (`segurata remediate <id>` and `who:
segurata` when the only finding is automatable). Only generic decisions are seeded, once each
(whether to install the daily schedule). Questions about an owner's own projects are added with
`segurata track add --kind decide` and live only in that owner's tracker, never in the code.

### Expected statuses

Some statuses other than `ok` are known and kept on purpose: an ephemeral key, an IAM user limited
by design, other people's accounts signed in to the same browser. The config says so per connector
instance, under the key that runs it (`connectors.<name>` or `connectors.<name:label>`):

```json
{"connectors": {"anthropic:personal": {"expected": [
   {"state": "missing_credentials", "reason": "admin key only set when I audit"}]},
 "google-personal": {"expected": [
   {"state": "reauth", "account": "*@example.com", "reason": "colleagues' accounts in my browser"}]},
 "gcp": {"expected": [
   {"state": "error", "account": "a@x.com", "detail": "/^project (app-one|app-two)-play:/", "reason": "Play-only projects"}]}}}
```

Empty fields match anything. `account` is a glob (`*`, `?`, `\` escapes); `detail` is a
substring of the status detail, or a regular expression between slashes; `reason` is required.
`config.Load` rejects a rule without a reason, with a bad glob or regular expression, or matching
`ok`.

- A matching status gets state `expected` (`finding.StateExpected`), with `expected` (the
  reason) and `was` (the state the connector reported). The core applies the rules as each
  status is written, and again whenever it reads a run (`track sync`, `report`), so a rule
  added or removed after the run counts.
- Expected is not inspected: run completeness counts the scope as skipped, exactly as before, so
  nothing in it is ever taken as resolved.
- A setup item whose every current status is expected closes as `expected` (history `status` /
  `expected`, next step "Nothing: expected by your config (…)"); a new one is created already
  closed, so no setup item is ever opened for it. Its key keeps the reported state, so the item
  it closes is the one that state opened. If one of several statuses under a key is not
  expected, the item stays open. When a status no rule covers comes back the item opens again
  (`auto-reopen`); when the status is gone the item is done like any other, and when only
  expected statuses come back it is expected again, not open.
- `status` and `report` list them once: "N expected (by your config): <reason> (n); …", under
  setup blockers; `inventory` prints one line
  per instance and reason.
- `segurata track expect <setup-id> --reason "…" [--detail text] [--dry-run]` writes the rule
  that matches the item (its instance's key, the reported state, the account with glob characters
  escaped, the detail only when given) into the config and closes the item as expected. The
  config is rewritten atomically, mode 0600, with two-space indentation and its keys in their
  original order; the previous file is kept as `config.json.segurata-bak-<UTC time>`. An equal
  rule already there is not added twice. `--dry-run` prints the rule and changes nothing.

### Decisions and rules

A decision can carry effects. `track add --kind decide --question "Are the legacy repos dead?"
--option "yes=ignore:path:~/src/legacyco" --option "no"` stores the option labels and, for each
`label=effect:scope`, an entry in `decision.effects` (`{option, effect, scope}`). Effects are
`ignore` or `accept`; scopes are `path:<dir>` (rotate items whose every location, and other
items whose every reported finding, lie under it: the `repo` or `path` a local finding names),
`repo:<owner/name>` (GitHub findings of that repository, case-insensitive), `account:<glob>`
(findings of matching accounts) and `gcp-project:<id>`. Decide and setup items are never in scope.

`track decide <id> --answer "…" [--ignore-scope s]... [--accept-scope s]...` answers it and adds
a rule to the tracker's top-level `rules` for the option the answer picks (the label, or the
label followed by ":" or a space) and for every scope given:

```json
"rules": [{"effect": "ignore", "scope": "path:~/src/legacyco", "reason": "Are the legacy repos dead? yes",
           "decision": "T-0002", "at": "…"}]
```

Rules apply at once and at the end of every sync: an open, in-progress or snoozed item in scope
is ignored (or accepted, with no end date) with the reason "by decision T-0002: …", so a finding
in scope found later never stays open. An item reopened by hand after the rule was added is left
alone. Reopening the decision removes its rules; the items they closed stay as they are. Answering
an answered decision again does the same before adding the new answer's rules, so answers never
accumulate rules. A pending
decision with effects shows its leverage in `status` and `track show`: `answering "yes" closes 128
open items (P0 120, P1 8) by ignore path:~/src/legacyco`.

A rule can be narrowed to owners (`"owners": ["not-mine"]`): it then closes only rotate items
whose attribution (see "Attribution") is one of them, and its reason adds the attribution's first
reason ("…; attributed not-mine: AWS account 999988887777 is none of your 1 known"). Items in
scope with another attribution, and items that have none (anything but a secret), stay open. The
flag says what the rule closes, like the effect and the scope: `track decide <id> --answer "rotate
mine, ignore the rest" --ignore-scope path:~/src/legacyco --owner not-mine` narrows the rules of the
scopes given there; an option carries its own owners as `yes=ignore@not-mine:path:~/src/legacyco`.
`--dry-run` prints, per rule, what answering would close and keep open, and changes nothing:
`closes 120 open items (P0 100, P1 20) attributed not-mine, keeps 8 open (mine 5, unknown 3) by
ignore@not-mine path:~/src/legacyco`; the leverage of pending decisions reads the same. An item a
narrowed rule closed opens again (`auto-reopen`, "now attributed mine, which … leaves open") when
a later sync attributes it to an owner the rule does not name: the key turned out to be the
owner's after all. Ignoring it by hand afterwards sticks.

### Lifecycle: `segurata track sync`

`track sync` runs at the end of `inventory`, as `rotations sync`, or by hand. It reads the latest
finished run of every connector instance (`runfile.LatestFiles`) and:

1. Skips a run older than the one the tracker last folded for that instance (`sources`), so
   syncing two output folders (interactive and scheduled) never makes items flap. A run's time is
   its `run_end` `ended_at` (a file without one: its newest `observed_at` not in the future, else
   its modification time). A source after now counts as absent, and `out/` days after today are
   never read, so one wrong clock cannot freeze a connector. A latest run that cannot be read (a
   torn line) is skipped with a warning; its instance counts as not run.
2. Folds local-secrets findings into rotate items (below) and every other finding at low or above
   into the item its rule names, creating it (`found`) or adding the new finding (`seen`).
3. Marks a linked finding `gone` when its connector instance ran and did not report it, unless
   that run did not inspect the finding's scope (see "Run completeness"); then it logs
   `not checked in run …` once per run on an item that would otherwise have closed.
4. Moves items on (a setup item counts its status refs gone by the rule in "Run completeness"):
   - open, in progress, snoozed or expected, with every finding gone: done, `verified (no longer
     reported)`;
   - a setup item whose every current status is expected: `expected`; an expected one with a
     status no rule covers: open again (see "Expected statuses");
   - done: verified once every finding is gone in a run after it was marked done; reopened
     (`auto-reopen`) if a run after it was marked done or verified reports one again. A sync
     that only reads the run from before the item was marked done changes nothing;
   - accepted, ignored, reclassified and expected items only get their findings updated;
   - a snooze past its date, or an acceptance past its last day, opens the item again. An
     expired acceptance stays on the item, so its findings show "(acceptance expired)" until the
     owner acts.
5. Adds the owner's accounts the runs report to the tracker's `owned` and attributes every rotate
   item (see "Attribution").
6. Applies the decisions' rules (see "Decisions and rules").
7. Adds any missing theme or seeded decision.

Rotate items keep the rotation rules below instead: they are never closed because a secret
stopped being reported (git history and transcripts do not forget, and a redacted copy still
reached the model provider).

### Restart resistance

- Writes are atomic (`statefile`: temporary file, fsync, rename), mode 0600 in a 0700 folder.
- Before each write the file being replaced is copied to `tracker.json.bak` (one copy, 0600). The
  tracker holds no secret value (rotate items carry redacted hints and HMAC fingerprints, findings
  none), so the backup holds none either.
- Load validates: JSON with no unknown field, a known `schema_version`, unique `T-` ids below
  `next_id`, unique keys, known kinds and statuses, rotate items with a secret and decide items
  with a decision. A file that fails is an error for every command, never an empty tracker, and
  is never overwritten (Save re-reads it and refuses): fix it or restore the backup.
- Save also refuses a file that is not the one the command loaded or last saved (compared by
  SHA-256): another command saved it in between, and writing would drop that change silently.
  The command fails with "changed since this command loaded it; … run it again" and writes
  nothing, the backup included. `track sync` alone folds its runs once more into that version.
- Commands that change the tracker hold a lock from load to save: an exclusive `flock` on
  `tracker.json.lock` (released by the system if the process dies), waiting up to two minutes for
  another command, so the scheduled `inventory` → `track sync` and an interactive command run one
  after the other. Views (`status` without `--mark-seen`, `track list|show`, `report`) take no
  lock. `rotations replace` and `redact` hold the tracker across a confirmation and file rewrites,
  so they take no lock for that; they record their outcome (rotated, a failed attempt, the
  redaction notes) with `tracker.Update`, which loads the tracker fresh under the lock. Without
  `flock` (Windows) the lock is a no-op and the SHA-256 check still refuses lost updates.
- `schema_version` 6 is the current format. A format change adds an upgrade step from version n
  to n+1 on the raw JSON, applied in order when loading; a newer file than the binary knows is
  refused. 2 added the statuses `reclassified` and `expected`, the top-level `rules` and decision
  `effects`; 3 added the top-level `owned`, a secret's `attribution` and a rule's `owners`; 4 added the
  status `merged` with an item's `merged_into`, a finding ref's `type`, `resource` and `match`, and
  the top-level `runs` (see "Coverage"); 5 added a location's `gone`; 6 added a secret's `liveness`, the history action `dead` and attribution facts' `github_logins`. An older file holds none of them, so it loads as it is and is saved as the current version (the
  older file stays as `tracker.json.bak`).

### `segurata status`

```
segurata status [--theme t] [--kind k] [--priority P0,P1] [--format text|md|html] [--explain] [--write] [--mark-seen]
```

The briefing, built with the report's document model and renderers (`internal/doc`), so text,
Markdown and HTML say the same thing: a headline (open items by priority and theme, done and
verified in the last 7 days, accepted, ignored, merged, snoozed, and how many areas are not
audited here), the coverage line (see "Coverage"), "Do next" (the ten entries worth most, see
below), pending decisions, setup blockers, what is not audited on this machine, the changes since
the last seen status (events counted, the latest listed) and the accepted risks. Long next steps show their first sentences
and fold the rest (`doc.Fold`: a collapsed `<details>` in HTML and Markdown, `[…]` in text), never
cut inside a `code span`.

#### Do next

Entries are ranked by a score (`internal/tracker/score.go`), every factor from a table, and
`--explain` prints each entry's formula ("27.0 = impact 6 (P1) × blast 3 (one stolen password
opens every repository of those orgs) ÷ effort 1 (one change) × quick win 1.5 (one fix closes 5
findings)"):

    score = impact × blast × exposure × liveness × confidence ÷ effort × quick win

| Factor | Values |
|---|---|
| impact | the priority: P0 10, P1 6, P2 3, P3 1, none 0.5 |
| blast | what is at stake beyond one finding's severity, as the connector declares it (the finding's `blast`, see docs/connectors.md), the first of these one of the item's findings declares: `login` (a Google account that is the login for other services) 3, `org-access` (2FA not required, or members without it, in GitHub orgs) 3, `device` (no Time Machine backup) 2.5, `mail-and-files` (high-risk Google OAuth grants) 2.5, `browser` (a remote debugging port) 2, `personal-data` (data dumps) 2, `all-repositories` (apps that can delete or write every repository) 1.5, `org-write` (every org member can write every repository) 1.5, `posts` (X apps) 0.6, `money` (spend limits and budgets) 0.7, `leftovers` (endpoint agents) 0.5; else 1. Titles are never read |
| exposure (secrets) | worst copy remote 1.5, shared 1, local 0.7 |
| liveness (secrets) | live and leaked 2 (see "Correlation" and "Liveness"), live 1.5, attributed mine 1.3, attributed not-mine 0.3 |
| confidence | a secret nothing shows still valid (no connector, no liveness check) 0.8, a review list 0.8, every finding `unconfirmed` (a file only named like a dump) 0.7 |
| effort | rotate with `rotations replace` 1, rotate by hand 1.5, a history rewrite (dumps) 3, a review list 1 + entries/20 (3 at most), else 1; doubled when a pending decision blocks the item |
| quick win | 1.5 when segurata does it after confirmation, or one fix closes 3 findings or more |

A pending decision that blocks items (see "Grouping") is an entry worth half of what it unblocks,
as a quick win, with "Unblocks: 9 items (P1 9)". Secrets are one entry per priority, scored as the
next secret: it names that secret, its first two reasons, its next step and command, and `segurata
rotations next --priority P0` to go on. Coverage items (see "Coverage") and setup items have
sections of their own. Reading it changes
nothing: an unfiltered `status --mark-seen` records the "since" mark, and `--write` (which implies
`--mark-seen`) also writes `status.md` and `status.html` next to the tracker, mode 0600. `report`
stays the per-run view. Likewise `rotations next` only logs a `next` history event with `--log`.

### Coverage

What segurata looked at, and what it cannot look at here (`internal/tracker/coverage.go`).

**Runs.** Each sync keeps, per connector instance, its newest folded run in the tracker's `runs`:
when it ended, whether it has `run_end`, whether it was complete, the connector's error, and the
first five scopes it skipped with the count. A scope left out by a status the config expects (when
the run was written or by a rule added since), or one the connector skipped with a reason starting
`expected` (the owner's config told it to, as Prowler's `skip_projects`), is counted as expected
and does not make the run partial, here or in the report (`finding.Coverage.CompleteAsConfigured`).
It still proves nothing gone there. `status` prints one line for every configured instance (the targets an unfiltered
`inventory` runs) and any other that ran:

```
Coverage: aws: 3 h ago (1 scope left out as expected); cloudflare: never run; gcp: 9 h ago, failed: …; github: 3 h ago, partial: user:octocat not checked.
```

**Gaps.** Areas of the plan ([plan.md](plan.md)) that no connector audits on this machine are
review items of theme `coverage` (key `coverage:<slug>`, no priority), each with the step that
would cover it:

| Item | Open while | Step |
|---|---|---|
| your own GitHub account's 2FA | the github run reports a `user:<login>` scope other than ok (gh lacks `read:user`) | `gh auth refresh -h github.com -s read:user && segurata inventory github` |
| Google recovery options and passkeys | always (no connector) | Security Checkup and passkeys on every account |
| Apple Account devices and Sign in with Apple | always | account.apple.com, see manual-review.md |
| Stripe API keys | always | restricted keys, delete unused ones |
| breaches of your addresses (HIBP) | no hibp run has read the addresses | install examples/hibp and run it |
| the password manager's password report | always | 1Password Watchtower or Bitwarden Reports |
| Google Workspace administration | a workspace tenant ran and none reported ok | README, "Google Workspace administration" |

The connectors that audit an area declare it in `describe` (`covers`, see connectors.md,
"Theme and grouping"): github `github-owner-2fa` under its `user:` scope, workspace `workspace`,
hibp `hibp`. A sync keeps, per connector instance, whether its newest run audited each area it
covers (a status of the area says ok, or none says otherwise). A gap is covered when any run
audited it, open when one could not, and otherwise left as it is, except hibp's, which is open
while no run reports it; while a run from before declarations is kept, it is left as it is too.

A sync opens the item when the gap is there and closes it as done and verified ("covered: github
audited it") when a run covers it; one segurata closed opens again when the gap
comes back. An item the owner marks done (the manual areas) stays done. They stay out of the
headline counts and "Do next", in a section of their own, "Not audited on this machine": they say
what is unknown, not what is failing.

## Remediation

```
segurata remediate --list                      automatable findings of the latest run, one line per group
segurata remediate <finding-id>                print the plan; changes nothing
segurata remediate <finding-id> --apply        print the plan, ask "Apply? [y/N]", apply, check
segurata remediate <finding-id> --apply --yes  same without asking
```

The finding comes from the latest `out/<date>/*.jsonl` (a unique id prefix is enough). The plan
(`connector.Plan`) states the whole scope before anything runs: a summary, the exact commands, the
file changes, whether it needs sudo, the side effects and the exact commands that undo it.

- One finding per run, or one group. A finding with `remediation.group` is planned with every
  finding of the same connector instance that has the same action and group (`remediate.Members`,
  accepted ones left out) by a `connector.GroupRemediator`; `--list` shows the group as one line,
  under its worst member, and ranks every line by `remediation.severity` when set (a hardening
  step on a finding graded for something else) or the finding's severity.
- Without `--apply` it stops after the plan. With `--apply` it asks on the terminal and refuses
  when stdin is not a terminal, unless `--yes`. A plan with `blocked` set (a write credential not
  configured) is refused before asking; a plan with a `terminal` step (interactive: `gh auth
  refresh` opens a browser) is refused without a terminal even with `--yes`.
- After applying, the core runs that connector instance's inventory again and checks each finding
  of the plan: it is fixed when no fresh finding with its id still offers its action. So the same
  finding without that action (a repository that keeps other problems, a grant with fewer scopes)
  counts as fixed for this action. A finding still offering it, a check that could not run, or a
  check run that did not inspect a finding's scope ("could not verify the fix") is an error.
- A built-in connector remediates by implementing the optional `connector.Remediator` interface
  (`Plan`, `Apply`). The confirmed plan is the plan that runs: after the confirmation the core asks
  the remediator for the plan again, from the state as it is then, and refuses to call `Apply` when
  it differs in any field from the one shown. A remediator carries no check of its own for this.
- Every command an action may run is on a per-action allowlist of exact argument lists, written by
  hand (`connector.Allowlist`). There is no pattern matching; anything else is refused before the
  first command runs. An action whose argument names a live object (an SMB share point, the home
  folder, a GitHub repository, gh's token scopes, an Azure client secret) gets its entries at apply
  time from a fresh read of what exists, never from the finding: the finding only says which
  object, and a name that matches nothing exactly is refused. The plan is built from the same
  read, so what changed since the inventory is left out and named in the plan.
- Packages: `internal/remediate` is the verb's core (the session, the plan check, the generic file
  actions and protocol 2), and only `cmd/segurata` imports it; a test enforces that. Connectors
  build on the contract in `internal/connector` (`Plan`, `Allowlist`, `Executor`,
  `ActionChmod600`), other commands confirm through `internal/prompt`, and the latest-run reader
  is `internal/runfile`.
- HTTP writes (`plan.calls`: method, URL and the name of the credential) go through
  `connectors/internal/httpw`, a client separate from the GET-only `httpx` (which follows
  redirects but drops the credential headers on a hop to another host or port): it sends bodiless
  requests only when method and path match one of its routes (`DELETE /keys/<id>`, ids limited to
  `[A-Za-z0-9_-]+`) and follows no redirect. A test fails if any connector file other than
  `remediate.go` imports it, so no inventory code path can reach it.
- Write credentials are never inventory secrets. They live under `remediation_secrets` in the
  instance's config; `run.InstanceCredentials` hands a remediator the inventory request plus their
  unresolved references (`connector.Credentials`, for remediators implementing
  `connector.CredentialedRemediator`), and only `Apply` resolves one, after the confirmation. A
  name ending in `_WRITE_KEY` under `secrets` is rejected when the config loads, since every
  inventory resolves `secrets`.
- sudo: a command that needs root runs as `/usr/bin/sudo <argv>` with the terminal's stdin, stdout
  and stderr attached, so sudo asks for the password itself. segurata never reads, stores or
  pipes a password.
- Generic actions belong to the core, so any connector can attach them. `file.chmod600` takes the
  file in `evidence.path` (absolute or `~/`), refuses symlinks and non-regular files, and changes the
  mode in-process to 600 (700 when the owner could execute it); the undo is `chmod <old mode>
  <path>`. With a group it changes every file once and leaves out, by name, files already private.
- An external connector remediates through protocol 2: it declares its actions in `describe`
  (`remediates`), returns a plan from `segurata-<name> plan` and runs it in
  `segurata-<name> apply` (`remediate.External`). As for a built-in, the core shows the plan, confirms
  and refuses a plan that changed since it was shown; it also refuses any
  plan that needs sudo: a plugin's command line is never on the hand-written allowlist, so the core
  cannot vet it and will not run it as root. The plugin runs its plan as the owner; the allowlist
  binds built-in actions only. Details: [connectors.md](connectors.md#plan-v2).

## Accepted risks

```
segurata accept <finding-id> --reason "..." [--until YYYY-MM-DD]
segurata accept --list
segurata unaccept <finding-id>
```

Some findings describe a risk the owner keeps on purpose (Brave's remote debugging port, which
local AI agents drive). `accept` looks the finding up in the latest run (a unique id prefix is
enough) and records it in the tracker (`internal/accept` on `internal/tracker`): the item that
links the finding gets status `accepted` with `{"reason", "until", "accepted_at"}`. When that item
groups other findings too (one of five orgs), the finding first moves to an item of its own, so
the others stay open. `unaccept` takes the finding id (or a unique prefix) or the item id and
opens the item again.

- The core stamps every finding of an inventory with `"accepted": {"reason", "accepted_at",
  "until", "expired"}` when an item holding its id carries an acceptance. The finding stays in the JSONL; the summary
  and `remediate --list` leave it out and say "N accepted findings hidden; see segurata accept
  --list". `remediate` re-reads the file, so an acceptance made after the run counts.
- `until` is the last day it applies. After it the finding shows again, its title followed by
  "(acceptance expired)", and the next sync opens the item again.
- This only works with stable ids: a finding id hashes connector, account, resource type and
  resource id, so a resource id must not hold anything that changes between runs (a pid, a port).
  The debugging-port finding's resource id is `brave-remote-debugging`, whatever port Brave uses.
- A broken tracker is an error, never an empty list: a typo must not unhide or hide anything silently.

## Report

`segurata report [--format text|md|html] [--out file]` (`internal/report`) reads, and never
changes:

- the latest finished run of every connector instance, through `runfile.LatestRuns` and `runfile.Read`
  (findings, statuses and `run_end`);
- the tracker's acceptances, which annotate every finding as `inventory` does, so an acceptance
  made after the run counts and an expired one shows again;
- the tracker's rotate items.

The only write is the one-time import of the former state files, when the tracker does not exist
yet.

The report counts what `status` counts: its headline is the tracker's (`Tracker.Headline`: items
by priority and theme), followed by the findings of the latest runs as a note ("an item groups the
findings one action fixes") and the table by connector instance; its setup section is the
tracker's setup blockers (`tracker.Blockers`); and its changes are the items found, closed,
verified and reopened in the last 7 days (`tracker.Changes`, the same counts `status` gives since
the last status). Runs are compared in one place, the tracker's sync: a tracker that never synced
(`last_sync_at` unset) is synced in memory from the same runs for the report, and not saved.

The report is built once as a small document (headings, paragraphs, lists, tables) and rendered as
text, Markdown or HTML, so the three formats carry the same content. Markdown escapes markup in
titles; HTML escapes everything, links only absolute http(s) URLs, has no script, loads nothing
(its CSP is `default-src 'none'`) and switches colours with `prefers-color-scheme`. `--out` writes
atomically with mode 0600 (`statefile.Write`).

What it shows of the rotate items is the secret's short id, service, type, redacted hint, worst exposure, first
reason and rotate URL; never a location path. Findings never hold a value, so neither does the
report.

## Scheduled runs

```
segurata schedule install [--every 24h] [--connectors a,b] [--apply [--yes]]
segurata schedule uninstall [--apply [--yes]]
segurata schedule status
segurata schedule run [--every 24h] [--connectors a,b]   what the agent executes
```

`internal/schedule`. On macOS, `install` builds a launchd user agent,
`~/Library/LaunchAgents/com.segurata.inventory.plist`, that runs `segurata schedule run` every
`--every` (default 24h, at least 1h; `StartInterval`, not at load) from
`~/.segurata`, with the PATH of the shell that installed it and its output in
`~/Library/Logs/segurata/`. Without `--apply` it prints the plist and the
`launchctl bootstrap gui/<uid> <plist>` command and changes nothing; with `--apply` it asks on the
terminal as `remediate` does (`--yes` skips it), writes the plist (mode 644), boots out an agent
already loaded and bootstraps the new one. `uninstall` boots it out and removes the plist, keeping
reports and logs. `install` refuses a binary under the temp directory (`go run`), which would be
gone by the first run.

One `schedule run` ends before the next is due: it has 90% of the interval, and its inventory 80%,
which leaves time for the report. At the deadline the inventory gets an interrupt, so it writes
`run_end` (with the interruption as `error`) and syncs the tracker, and a kill two minutes later.
`install` puts an interval other than 24h on the agent's command line (`schedule run --every 6h`),
so an agent installed before that runs with the 24h bound until it is installed again.

1. Runs `segurata inventory --out ~/.segurata/out <connectors>`, which ends in `track sync`.
   Without `--connectors`, every installed connector. The browser connectors (those whose
   `describe` needs `cdp`) run only when Brave answers at `cdp_url`; see "Browser connectors in a
   scheduled run" below.
2. Posts one macOS notification (`osascript -e 'display notification …'`) naming up to three of
   the open P0 and P1 items that sync found, reopened or raised to P1 or P0 (history `found`,
   `reopened`, or `priority` with action `raised`, since the run started), by title: the tracker is the one place runs are compared. Titles never carry
   secrets; evidence is never shown. Each is also written to the log.
3. Runs `segurata report --format md --out ~/.segurata/last-report.md --dir
   ~/.segurata/out`.
4. Once the report is written, prunes `~/.segurata/out` (`runfile.Prune`): it removes the
   `<date>/*.jsonl` files and leftover `*.partial` files of days older than `keep_runs_days` in
   the config (default 30; a negative value keeps everything), except the latest finished run of
   each instance and a newer unfinished one, which the tracker, `report` and `remediate` read,
   and the finished run before it, kept in case the latest proves unreadable, and the evidence run
   of a latest run that inspected nothing, so weeks of skipped or failed runs never delete the last
   one that inspected something. Nothing else under `out/` is touched, and empty days are removed.
   `accounts list` reads every remaining run, so it shows accounts seen within that window.

### Browser connectors in a scheduled run

Only Brave is driven, however a run was started. `cdp.Connect`, the one way into the browser,
first proves the browser at `cdp_url` (from the config, default `http://127.0.0.1:9222`, or
`SEGURATA_CDP`) is Brave: `/json/version` with a 3-second timeout, then
`navigator.brave.isBrave()` in a hidden `about:blank` target that is closed at once. Brave reports
itself as `Chrome/…` in the `Browser` field and in its user agent (Brave 156, 2026-11-25), so that
field cannot tell it from Chrome. `run.Inventory` makes the same check once (`cdp.Brave`, under a
15-second bound) before any connector that needs `cdp`, built-in or external, so a plugin that
connects by itself never reaches another browser either.

- Brave answers: the browser connectors join the inventory and scan in hidden targets (see
  "Browser connectors"). Each instance keeps its own timeout. A signed-out account or a "verify
  it's you" wall is a `signedout` or `reauth` status; nothing waits for the owner and `signin`
  never runs unattended.
- Nothing answers, or the browser is not Brave: nothing is started in its place (no other browser,
  no `open`). Each instance of each browser connector does not run; its run ends at once with
  "browser not reachable over CDP" (or "the browser on the debugging port is not Brave") and the
  probe's error as `error`, and its `run_end` skips `*`, so `track sync` closes neither its
  findings nor its statuses, and the report shows the newest run that inspected something with a
  line naming the skipped one; pruning always keeps that run. Secrets are not resolved for it. A
  scheduled run probes too and logs one line, `skipped <connectors>: <reason> (<the probe's
  error>)`.
- `~/.segurata/schedule-browser.json` holds `not_run_since`, when the browser connectors last ran
  on schedule (or first were skipped), and `notified`. When a skipped run finds them idle for more
  than `browser_stale_days` (config, default 7, negative for never), it posts one notification,
  "browser connectors haven't run in N days", with the reason as subtitle; the next one comes only
  after they have run again. On Linux the line goes to the log.

Scheduled inventories live apart from the interactive `out/`; `segurata remediate --out
~/.segurata/out --list` works from them.

On Linux `install` prints the equivalent systemd user service and timer
(`~/.config/systemd/user/segurata-inventory.{service,timer}`) and the `systemctl --user` commands
to enable them; `--apply` is refused there, and new findings go to the journal instead of a
notification.

## Doctor

```
segurata doctor [--connector name|name:label] [--out out]
```

`internal/doctor`, read-only. Prints one line per check, `OK`, `WARN` or `FAIL`, each `WARN` and
`FAIL` with the exact fix, then the counts; exits 1 when anything failed. `--connector` checks one
connector or instance (the config and state are always checked).

- Config: the file is found and valid; a key that names no connector is a warning.
- Secret references: every reference of every selected instance is resolved through
  `run.NewRequest`, the path an inventory takes, and reported by key and reference; the values are
  only handed to the connector's own check, never printed. Whether a Keychain item's ACL would
  prompt cannot be read without prompting, so it is not checked.
- Browser: when a selected connector needs `cdp`, `cdp_url` must answer `/json/version`
  (`cdp.ReadVersion`, the first half of `cdp.Connect`). The OK line restates the accepted-risk
  tradeoff of an open debugging port.
- Connectors: a built-in connector implementing the optional `connector.Doctor` checks its own
  prerequisites through the same runners, allowlists and classifiers its inventory uses. For any
  other connector (externals included) the core checks the `describe` needs: `cli:x` on `PATH`
  (`(optional)` makes a miss a warning), `secret:X` configured (a warning when not: the connector
  is skipped, not broken). `os:` needs are checked for every connector.

| Connector | Checks |
|---|---|
| `gcp` | gcloud found as the inventory finds it (`gcloud_path`, `PATH`, SDK folders); `auth list`; per account `projects list --limit=1`, so an expired token fails with `gcloud auth login <account>` |
| `workspace` | Per tenant: the token is obtained as the inventory does (secret, or gcloud with the tenant's `CLOUDSDK_CONFIG`) and checked with tokeninfo for scopes and domain; the token is discarded |
| `aws` | `sts get-caller-identity` per profile; SSO, static-key and missing-credential failures get different fixes |
| `azure` | `az account show` |
| `cloudflare` | `GET /user/tokens/verify` (status and expiry), then one page of tokens, accounts and zones and the first zone's SSL setting and DNSSEC, each failure naming the permission group to add |
| `connected-apps` | `gh auth status --json hosts` (JSON, never the token; the one gh command added to its allowlist); scopes the key lists need (`admin:public_key`, `admin:ssh_signing_key`, `admin:gpg_key`, from `ghKeyEndpoints`) |
| `macos` | `dscl` lists the local users; `tmutil destinationinfo -X` and the Time Machine preferences are readable (a warning with the Full Disk Access fix otherwise) |
| `local-secrets` | rg, gitleaks (optional; not needed with `skip_git_history`), git and ssh-keygen on `PATH`; `rg --version` and `gitleaks version` (added to the gitleaks guard) |

- State: the fingerprint key exists (a warning before the first `local-secrets` run), is a valid
  key and has mode 0600; `tracker.json` loads and has mode 0600 when present; the tracker
  folder and the output directory (`--out`) have mode 0700 (a warning otherwise, since their files
  are 0600).

## External connector protocol (v1, v2)

An external connector is a `segurata-<name>` executable on `PATH`, in any language, discovered
at start (`connector.Discover`) and wrapped in the `connector.Connector` interface
(`connector.External`). It answers `describe` with a JSON object and `inventory` with JSON Lines
records, reading one JSON request (protocol, config, resolved secrets, CDP address) on stdin.
Protocol 2 adds `plan` and `apply` for remediation. The core speaks both versions and sends each
connector the version it declared, so a version 1 connector keeps working unchanged. Full protocol
with examples: [connectors.md](connectors.md#external-connector-protocol).

## Secrets used by connectors

Admin keys (OpenAI, Anthropic, OpenRouter, Vercel, Supabase, Cloudflare…) do not live in plain files. The
config says where each one is; the core resolves it on the fly and passes it to the connector in
the request, without writing it to disk. A literal value in the config is rejected.

| Reference | Resolved with |
|---|---|
| `env:NAME` | Environment variable |
| `keychain:service` | `/usr/bin/security find-generic-password -s service -w` (macOS Keychain) |
| `op://vault/item/field` | `op read` (1Password CLI) |

Both programs run through `internal/keychain` with a 30 s timeout inside the run's deadline, so a
prompt nobody answers in a scheduled run fails the reference instead of hanging. A missing
Keychain item and a denied read (`User interaction is not allowed`) are reported apart, with
security's reason for the latter.

Config at `~/.config/segurata/config.json` (override with `SEGURATA_CONFIG`):

```json
{
  "cdp_url": "http://127.0.0.1:9222",
  "connectors": {
    "openai": {"secrets": {"OPENAI_ADMIN_KEY": "keychain:segurata-openai-admin"}},
    "gcp": {"config": {"projects": ["my-project"]}}
  }
}
```

### Several accounts of one provider

A config key `name` is the connector's unnamed instance; `name:label` adds a labelled one, with
its own config and secrets. A label is letters, digits, `_`, `.` and `-` only. Each instance runs
separately, writes `out/<date>/<name>-<label>.jsonl`, and stamps `"instance": "<label>"` on its
records (part of the finding id). On the command line, `name` selects every instance and
`name:label` just one; an instance named twice runs once.

```json
"openrouter:work":     {"secrets": {"OPENROUTER_MANAGEMENT_KEY": "keychain:segurata-openrouter-work"}},
"openrouter:personal": {"secrets": {"OPENROUTER_MANAGEMENT_KEY": "keychain:segurata-openrouter-personal"}}
```

## v0 connectors

| Connector | How it looks | What it looks for |
|---|---|---|
| `google-personal` | CDP over the signed-in browser | Linked apps, scopes, dates, accounts that need a fresh sign-in |
| `connected-apps` | CDP over the signed-in browser, `gh api` | Apps connected to GitHub (OAuth apps with scopes and organization access, GitHub Apps, sessions, SSH/signing/GPG keys), X, Slack (every signed-in workspace, from the manage page's own `admin.apps.installed.list` response: declared bot and user scopes, graded by capability in `slackscopes.go`), Notion (developer connections), Facebook (first page of Apps and websites), Dropbox (from the page's own app-list response), Instagram and LinkedIn (empty list verified only), Microsoft personal accounts (session check only), Microsoft work accounts (My Apps enterprise apps from the page's own tiles response; Security info's MFA step-up as a scoped `reauth`). `services` in the config selects some; one instance per service is allowed |
| `local-secrets` | `rg`, `gitleaks`, `git`, `ssh-keygen`, `gh` (optional) | Plaintext secrets in config and `.env` files, shell histories, logs, agent transcripts and git history; database dumps committed to git, one finding per file; SSH keys without a passphrase; HMAC fingerprints so one secret is recognised in every place it appears |
| `github` | `gh api`, GET on allowlisted paths | Account 2FA; organizations you own: 2FA requirement and members or outside collaborators without it, base permission, public repository creation, Actions (allowed actions, default workflow token, PR approval), code security defaults for new repositories; repositories you administer: insecure webhooks, write deploy keys, secret scanning and push protection, write workflow token on public repositories, Dependabot security updates, optional default-branch protection. Missing scopes are `noscope` with the `gh auth refresh` command |
| `gcp` | `gcloud` CLI | Unrestricted API keys, service-account keys and their age, service accounts with broad roles, billing budgets judged by the shared spend rules (connectors.md, "Spend and budgets"), local ADC credentials and their scopes |
| `aws` | `aws` CLI | Root keys or no root MFA, old or unused access keys, budgets judged by the shared spend rules |
| `azure` | `az` CLI | Budgets judged by the shared spend rules, app registration secrets that never expire or expire soon |
| `openai` | Admin API | Keys, last use, projects, limits and spend |
| `anthropic` | Admin API | Keys, last use, workspaces, limits and spend |
| `openrouter` | API | Keys, per-key credit limit, spend |
| `vercel` | API | Tokens, spend management |
| `supabase` | Management API | Projects, service keys, spend cap |
| `cloudflare` | API, read-only user token | User API tokens (no expiry, idle, edit without an IP filter, edit on all zones or accounts), Global API Key reminder, account 2FA enforcement, members without 2FA, super administrators, per zone SSL mode, Always Use HTTPS, minimum TLS and DNSSEC. One instance per login |
| `macos` | macOS tools, read-only and without sudo | FileVault, SIP, Gatekeeper, firewall and stealth mode, update settings and pending updates, screen lock, automatic login, guest account, home folder readable by other accounts, local accounts other than yours (admin, home folder, last login), items owned by deleted accounts' UIDs in shared folders and launchd folders, Time Machine (no destination, unencrypted destination, latest backup age), endpoint agents and their leftovers, TCP ports reachable from the network, SMB share points (guest access, orphaned records), login and background items, Brave's remote debugging port. Remediates the firewall, stealth mode, share points (remove a record, turn guest access off) and the home folder mode |
| `workspace` | Admin SDK, token from a per-tenant gcloud config | One instance per tenant: accounts without 2SV enrolled or enforced, admins (super admins used day to day), suspended or inactive accounts, third-party apps with OAuth grants ranked by scope and users, token authorizations and revocations over 30 days |
| `browser-extensions` | Brave and Chrome profile files, read-only, no network | Every extension in every profile: capabilities, source, install and update dates, category hint, and a `remove`/`review`/`keep` verdict with reasons (README, "Browser extensions"). Not automatable; each finding links the extension's page in the browser. Web Store lookups (pulled extensions, new owners) are a future enhancement |

`browser-extensions` is its own connector rather than part of `macos`: it reads browser data, not
OS settings, the same files exist on Linux, and the triage compares extensions across all profiles
of a browser at once (duplicates, one finding per extension).

Every connector is written in Go. The Node prototypes (`google/`, `connected-apps/`, `workspace/`,
`secrets/`, `macos/`) were deleted once their connectors matched them on a live run.

## Browser connectors

`google-personal` and `connected-apps` read the browser the owner already uses (Brave, and only
Brave, with `--remote-debugging-port`, address `cdp_url`) through `internal/cdp`, a standard-library CDP
client. They never start a browser and never call the system's `open`; a source test
(`internal/signin/nobrowser_test.go`) keeps `internal/cdp`, `internal/signin` and `cmd/segurata`
from naming a launcher or a browser binary.

- Scan pages (`Client.WithPage`) are hidden targets: `Target.createTarget` with `hidden: true`
  and `background: true`. They load with the owner's cookies but sit in no window and not in the
  tab strip, report themselves visible, and close when the page is read (or when the CDP
  connection drops). A browser that refuses `hidden` gets background tabs, as before. Concurrency
  is the connectors' own (six pages at once at most).
- A dedicated scan window was tried first and dropped after checking Brave 156 (2026-11-24):
  `Target.createTarget` has no window parameter, so a window made with `newWindow` gets only its
  first tab and later targets land in the owner's last active window; `window.open` from the
  window's tab does put tabs there, but brings the window to the front each time (and restores a
  minimized one).
- Pages where the owner acts (`Client.OpenTab`) are normal foreground tabs, never closed.

### `segurata signin`

A browser connector may implement `connector.SignInner`: for a `reauth` or `signedout` status it
returns the page to open, what the owner does there, a read-only expression and a `Done` test,
built from the same readiness predicates its run uses (GitHub: a settings URL without "Confirm
access"; Google: that account's connections without "Verify it's you"). `Brief` marks what lasts
minutes (GitHub sudo mode).

`internal/signin` collects, from the tracker, the active setup items of the selected instances:
an item whose statuses name a command (`tracker.Item.StatusCommands`) is a command for the owner's
terminal, listed and never run (for `reauth`, `signedout` and `noscope`, or any state with
`--all`); an item that is a browser sign-in (`tracker.Item.BrowserSignIn`: reauth or signedout of
a connector that needs `cdp`, no command) gets the connector's page, or the item's URL with no
`Done` test. Accounts outside an instance's `accounts` list are skipped. `Wait` opens the tabs and
evaluates each page's expression every 3 seconds; a page is through after two passing reads in a
row (one read can land mid-redirect). A tab that goes away stops being read. A brief page that is
through runs its instance at once; `Reruns` then picks the instances to run at the end: every
instance with a page, except one already run early whose pages were all through before that run
or never through. The runs go through `run.Inventory`, then `track sync`, then each item is
reported closed or still open. Commands are never run because `gcloud auth login` and
`gh auth refresh` start the system's default browser.

## Incremental git history scan

gitleaks over every repository under `repos_root` is most of a `local-secrets` run (about 30
minutes for ~330 repositories). History only grows, so each repository is scanned in full once and
then only for the commits added since (`connectors/localsecrets/historycache.go`).

Cache: `~/.cache/segurata/gitleaks/<sha256(repo path)[:16]>.json`, mode 0600, one per
repository. It holds the repository path, the cache format version, a hash of the gitleaks
version and configuration (`GITLEAKS_CONFIG`, `GITLEAKS_CONFIG_TOML`, the repository's
`.gitleaks.toml` and `.gitleaksignore`), a probe fingerprint of the machine key, the tips (every
commit a ref or HEAD pointed to, from `git rev-list --no-walk --all`) and the leaks found, as
prepared evidence: fingerprint, redacted hint, path, line, commit. The evidence is cached after
the check that it does not contain the value, so the cache never holds one.

Each run:

1. Lists the current tips.
2. Loads the cache. A different format, repository, gitleaks version or configuration, or
   fingerprint key (the probe differs) discards it.
3. Checks that every old tip is still reachable from a current one: `git rev-list -n 1 <old tips>
   --not <current tips>` must print nothing. A rewritten or deleted ref fails the check (its
   commits, and their leaks, may be gone), and so does an old tip whose object no longer exists:
   gitleaks itself would scan nothing and exit 0 on a bad object.
4. Passing the check, it scans `gitleaks git --log-opts "--full-history <new tips> --not <old
   tips>"`, exactly the commits no earlier run saw, or nothing when no tip is new. Failing it, it
   scans `--full-history <current tips>` in full. Tips are passed explicitly rather than with
   gitleaks' default `--all`, so the cache records exactly what was scanned. A tip list longer
   than 256 KiB falls back to gitleaks' default.
5. Replays the cached leaks plus the new ones, recomputing what can change without a new commit:
   whether the repository has a remote, and whether a cached JWT has expired since.

`git_cache: false` in the connector config turns it off: every repository is scanned in full and
the cache is neither read nor written. A cache that cannot be written is logged and costs the next
run a full scan, nothing more. The connector runs only `git rev-list`, `git ls-files`, `git log`
with a fixed set of listing flags, `git cat-file -s` and `git cat-file blob` (the data-dump check
below), `gitleaks git` and `gitleaks version`, and `gh repo view <owner/name> --json visibility`,
each on an allowlist (`guards.go`). A repository's own config cannot make that git run a program:
every git process, gitleaks' included, overrides `core.fsmonitor`, `core.hooksPath`,
`log.showSignature` and `core.pager` and forbids every transport (`protocol.allow=never`,
`GIT_NO_LAZY_FETCH`), and gitleaks' `git log -p` runs with `--no-textconv --no-ext-diff`.

## Data dumps in git

A database dump committed to a repository is reported once per file, as an `exposure` finding of
resource type `data_dump`, rather than as the thousands of gitleaks matches its hash columns
produce (`connectors/localsecrets/datadump.go`, `dumpscan.go`). It runs inside `local-secrets`, not
as a separate connector: it needs the same repository discovery, git runner, guards and tips, and
its results change how the gitleaks matches of the same run are judged.

For each repository under `repos_root`:

1. Candidates by name: every path in the index (`git ls-files -s -z`) and every path ever added
   (`git log --all --no-renames --diff-filter=A --name-only --format= -z`) whose name looks like a
   dump: `*.sql`, `*.sql.gz|zip|bz2|xz`, `*.dump`, `*.pgdump`, `*.sqlite`, `*.sqlite3`, `*.db`,
   `*.bak` with a database word, and `.csv`/`.json`/`.xlsx` with `prod`, `production`, `backup` or
   `dump` in the name (those only above 1 MiB). Never: names containing `schema`, `structure` or
   `seed`, migration folders (`migrations`, `migrate`, `drizzle`, `flyway`, `alembic`,
   `liquibase`), vendored code (`vendor`, `third_party`, `node_modules`), `Thumbs.db`. Under test
   folders (`test`, `spec`, `fixtures`, `testdata`…) a file must exceed 1 MiB. The test and vendor
   folders are those of `secretrisk.RoleOf`, the classifier secrets use too.
2. History of the candidates: `git log --all --full-history --no-renames --diff-filter=AM --raw
   --no-abbrev -- :(literal)<path>…` gives every blob id and the commit that first added each
   path. `--full-history` matters: a dump added and deleted on a merged branch is otherwise
   simplified away. `git log --remotes …` says whether a remote-tracking ref holds the addition.
3. Size: the largest blob of the path (`git cat-file -s`, at most the 32 newest versions); files of
   4 KiB or less are dropped.
4. Content: the first 4 KiB of one blob (the current one if tracked, else the largest), read by
   `git cat-file blob` through a reader that stops git after 4 KiB, never more. gzip is inflated
   as far as those bytes go and UTF-16 is read as ASCII. Headers: `PGDMP`, `SQLite format 3`,
   mysqldump and pg_dump banners (`data`), `INSERT INTO` / `COPY … FROM stdin` (`rows`), `CREATE
   TABLE` (`schema`).
5. Visibility: for a repository with a GitHub remote and at least one hit, `gh repo view
   <owner/name> --json visibility`, cached for 7 days. No gh, no GitHub remote or no access: unknown.

Severity. A file is a real dump when it has a production or backup name (or folder), a `data`
header, `rows` in a file of 64 KiB or more, or `schema` in a file of 1 MiB or more. A real dump in
a repository with a remote is `critical` when the remote is public and `high` otherwise; a local
one is `medium`. Other candidates are `medium` (remote) or `low` above 1 MiB, and `info` below.
The title says whether the addition is on a remote branch ("pushed") or only in a repository that
has a remote.

gitleaks matches inside a detected dump get `in_data_dump: true` and `secretrisk.ImpactOf` makes
them noise, so the rotation ledger skips them; the dump finding counts them in
`gitleaks_matches`. AWS access keys, Stripe live keys, GitHub and GitLab tokens and private keys
keep their impact: those are more often the owner's own credentials than a column of user data.

Cache: `~/.cache/segurata/datadumps/<sha256(repo path)[:16]>.json`, mode 0600, beside the
gitleaks cache and named the same way. It holds the tips the history was read at (the same
`git rev-list --no-walk --all` as the gitleaks cache), the candidates' history facts, sizes and
header classes by blob id, and the visibility. With unchanged tips a repository costs one
`rev-list` and one `ls-files`; with new tips the history is read again but known blobs are neither
sized nor read again. Never any content beyond the header class.

`data_dumps` in the connector config: `true` (default), `false`, or `"only"` to run just this
check (with `skip_git_history: true`, no rg, gitleaks or ssh-keygen pass runs).

## Rotation ledger

`segurata rotations` turns `local-secrets` findings into a list of secrets to rotate, one item per
fingerprint. The items are the tracker's rotate items (`internal/tracker/secret.go`: folding,
priority, reopen rules); `internal/rotation` is the command family on top (list, next, show,
replace). `rotations sync`, `done`, `snooze`, `ignore` and `reopen` are `track`'s own verbs, run
on rotate items only (`tracker.CLI.Rotations`): the same code and output, except that ids and
`--path` name secrets only and `sync` refuses to save without a local-secrets run. The risk model it shares with the connector lives in
`internal/secretrisk`, so a finding's severity and an item's priority never disagree.

State: in the tracker (see "Tracker"). A rotate item holds redacted hints and fingerprints, never values. Its status is the
tracker's (`done` reads "rotated" in these commands):

```json
{"id": "T-0007", "key": "rotate:3f9a12c4…", "kind": "rotate", "theme": "rotations",
 "title": "Stripe live secret key sk_live_…a1b2(107) in ~/src/shop/.env", "status": "open", "priority": "P0", "severity": "critical",
 "fingerprint": "3f9a12c4…(16 hex)",
 "secret": {"id": "3f9a12c4", "service": "stripe", "type": "stripe-live", "redacted": "sk_live_…a1b2(107)",
   "impact": "high", "reasons": ["Stripe live secret key; pasted into an agent transcript, so it reached the model provider"],
   "first_seen": "…", "last_seen": "…",
   "locations": [{"path": "~/src/shop/.env", "line": 3, "bucket": "3-local", "tracked": false, "mode": "600",
                  "source": "scan", "kind": "repo", "last_seen": "…"}],
   "used_in": ["~/src/shop/.env"], "rotate_url": "https://dashboard.stripe.com/apikeys"},
 "next": {"who": "you", "action": "Rotate it at https://dashboard.stripe.com/apikeys and copy the new value; segurata puts it in 1 file.",
          "command": "segurata rotations replace 3f9a12c4", "url": "https://dashboard.stripe.com/apikeys"},
 "history": [{"at": "…", "event": "found", "action": "found", "detail": "found in 2 places"}]}
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
  expired JWTs, encrypted private keys and the cases below. `sync --include-noise` tracks them
  without a priority, but the connector emits noise only with `emit_noise: true`.
- A secret that already has an item and whose best current sighting is now noise (a corrected
  rule) is updated, not skipped: impact `noise`, no priority, and an open, in-progress, snoozed or
  ignored item closes as `reclassified` (history event `reclassified`, detail "every current
  sighting is noise (<type>)"; an ignored item's detail starts "was ignored: <owner's reason>").
  Done and accepted items keep their status. Reclassified items are not counted as ignored: the
  ignored count is what the owner judged. If a later sighting is not noise, the item opens again
  (`auto-reopen`), or goes back to ignored with the owner's reason when it was ignored before.
- `sync` merges locations (never drops one: git history and transcripts do not forget) and
  refreshes `last_seen` only for secrets it saw. A working location (config, `.env`, rc or repo
  working tree) that a finished local-secrets run did not report although it read the files is
  marked `gone`: kept for the record, left out of `used_in`, the exposure, the title and path
  rules until a sighting there brings it back. Expired snoozes go back to `open`.
- After a real rotation the old value is revoked, so only a working file that still holds it
  matters. `done` and `replace` record the locations known at that moment (`rotated_locations`).
  A `rotated` item seen again is reopened, with the reason "still present after rotation (old
  value still in a working file)", only when a sighting is in a working file (config, `.env`, rc
  or repo working tree; the kinds that feed `used_in`), whether known at rotation time (the new
  value never reached it) or new since; the history note says which. Copies only in git history,
  transcripts, logs or shell history leave it `rotated` and add one `history-only` note per
  rotation ([docs/secrets.md](secrets.md#after-a-rotation)).
- `used_in` lists the working files (config, `.env`, rc files) that hold the secret now (not
  `gone`): where the new value has to go once it is rotated.
- `rotate_url` is the provider console page for that kind of secret, checked against each
  provider's documentation. Types without a stable, account-independent page (npm tokens, Shopify,
  private keys) have none.
- `secret.id` is the first 8 characters of the fingerprint, longer on collision. Commands accept
  any unique prefix of it or of the fingerprint, or the tracker's `T-` id.
- `done`, `snooze`, `ignore` and `reopen` (of `track` and `rotations`) also take `--path <prefix>`
  instead of an id: every item whose current locations (a secret's) or reported findings' paths
  (any other item's) all lie under that path. A test log or a data file full of fixtures goes away
  in one command, while a secret that also appears elsewhere stays. A secret answers with its own
  line (`3f9a12c4 stripe/stripe-live sk_live_…: rotated`).

### What counts against the owner

`secretrisk.ImpactOf` adjusts a copy's impact by where it is, and the connector adds the facts it
needs to the evidence. Every rule is a pure function of the evidence, so the finding's severity,
the rotate item's priority and `segurata redact` agree, and cached git history is re-judged on
every run without a new scan.

- Repository origin (`origin`). From each repository's GitHub remotes, origin first, and the
  owner's names: `owned_owners` in the config plus the login and organizations from `gh api user`
  and every page of `gh api user/orgs`, asked once a week and cached in
  `~/.cache/segurata/github-owners.json` (both calls are on the gh guard's allowlist). Only a
  complete answer is cached; when either call fails, gh names nobody for that run. `owned`
  when origin's owner is one of them, `third-party` otherwise (a clone of instructure/canvas-lms).
  A copy committed to a third-party repository is noise and its spot is local: the upstream's
  secret. An owned repository with another remote whose owner is not the user is a fork: commits
  reachable from that remote's branches (`git rev-list <leak commits> --not --remotes=<upstream>`)
  are `fork-upstream`, judged like third-party, and so is the working copy of the same value at
  the same path. Limits: a repository without a GitHub remote, or every repository when neither gh
  nor `owned_owners` names anyone, has no origin and counts as the owner's; a fork's inherited
  history is recognised only when its upstream remote has fetched branches.
- Reused (`reused`). A third-party or inherited copy of a value that also sits in one of the
  owner's own files (config, `.env`, a working file or commit of an owned repository) is the
  owner's secret leaked into someone else's repository, and counts in full. Transcripts, logs and
  histories do not make a value the owner's: an agent that read a third-party file leaves its
  value there.
- Attributed mine. Attribution wins over the repository: a secret whose claims name one of the
  owner's accounts (an AWS key id decoding to an account the aws connector reaches, see
  "Attribution") is the owner's leaked secret wherever it sits. `track sync` marks its third-party
  and fork-upstream copies `reused`, so they keep full impact and exposure (a key pushed to a
  clone of someone else's repository is P0, not noise), and its reasons say "yours by attribution
  (AWS account … is yours), so its copies in other people's repositories count in full". For the
  tracker to see such copies at all, the connector emits a third-party or fork-upstream copy that
  would count if it were the owner's and that names an account (`aws_account`, `gcp_project`,
  `slack_team`; the commit author is not enough) as a noise finding, instead of only counting it.
  The tracker knows the owner's accounts before it folds secrets, so this holds from the first
  sync, and a noise summary never reclassifies an item attributed mine that has such a copy.
- Paths (`secretrisk.RoleOf`, repository files only). Checksum lists (`*.md5`, `*.sha1`,
  `*.sha256`, `*.sha512`, `*.sum`) and lockfiles are noise. Test folders and files (`test`, `spec`,
  `fixtures`, `__tests__`, `cassettes`, `*_test.*`, `*.test.*`, `*.spec.*`, `test_*`), examples
  (`examples`, `samples`, `demo`, `*.example`, `*.sample`, `*.template`, `*.dist`), documentation
  (`docs`, `README*`, `*.md`) and vendored code lower the impact one level, to noise when the value
  reads like test data (`sample`: "test", "fake", "demo", "1234", "abcd", a run of four equal
  characters). The sample flag needs the value, so git history cached before it existed is judged
  by path alone until its repository is scanned in full again.
- segurata's own repositories (a `go.mod` declaring `github.com/segurata/segurata`, worktrees
  included) are not scanned for secrets: their test corpus is synthetic. The status line counts
  what was skipped.
- AWS temporary credentials (`ASIA…`) live 36 hours at most: one whose commit date (end of that
  day) or file modification time is older is expired (`public`, note "expired"). Pre-signed URLs
  (`X-Amz-Credential=` or `AWSAccessKeyId=` before the key id) are their own type, low impact, and
  the temporary keys and pre-signed URLs of one file collapse into one finding counting them all.
- AWS secret access keys (`aws-secret-key`) are 40 characters of base64 and nothing in them names
  AWS, so the key name decides. One that holds `secret_access_key` (`aws_secret_access_key`, an
  Ansible `app_secret_access_key`, the SDKs' `secretAccessKey`) makes the value one anywhere; a
  weaker secret-ish name (`secret_key`, `app_secret`) only within five lines of a long-term (AKIA)
  key id in the same file, or file and commit, outside trails. Without that, the value stays a
  generic match. gitleaks has no rule for these keys and reports them as `generic-api-key`, which
  is noise; the same rule reads them from the key name gitleaks matched (`markAWSSecretLeaks`). 40
  hex digits (a git commit hash) never are one. The history cache's format went to version 2 with
  this, so cached history is scanned in full once more.
- URL credentials (`url-credentials`, `url-token-param`) are judged by host, written into the
  note (`postgresql://…@host`, `https://host/…?access_token=…`): localhost, loopback, `example.*`,
  `.local`, `.test`, `.invalid` are noise; private, CGNAT and link-local addresses, single-label
  names, `.internal` and `.lan` are low; public hosts keep medium, high for managed databases
  (Neon, Supabase, RDS, MongoDB Atlas, Upstash, PlanetScale, Railway) or a `prod`, `production`,
  `prd` or `live` label. ripgrep prints only the match, so the line of a query-string token is read
  back from its file to find the URL it belongs to.
- Jupyter notebooks: only cell source counts. A match on a line of the notebook's JSON that holds
  no source text (outputs, metadata, attachments) is dropped; history reads the notebook as
  committed (`git cat-file blob <commit>:<path>`).
- Public OAuth clients: the client secrets of gcloud (`CLOUDSDK_CLIENT_NOTSOSECRET`) and of
  `gcloud auth application-default login` are published in its source; they are recognised by
  their first seven and last four characters and length, and are noise. The refresh token beside
  them is not. `~/.config/gcloud/logs` is not scanned.
- Bare 40-hex values matched by gitleaks' `sourcegraph-access-token` without the `sgp_` prefix
  are noise. gitleaks 8.30 has no other rule that takes a bare hex value: `facebook-secret` and
  `codecov-access-token` require the provider's name next to the value.
- Noise is counted, not emitted, unless `emit_noise: true`, except a noise copy of a value that
  has a real copy elsewhere (a generic gitleaks match in pushed history of the key in
  `~/.aws/credentials`): that one is one more place the secret went and stays. The run's status
  line ends with
  `noise not emitted …: N; by type: …; by place: …` (the 25 largest places, the rest summed), and
  one `info` finding of resource type `noise_summary` carries the same counts plus
  `noise_fingerprints`, every fingerprint whose copies are all noise with its type. `track sync`
  applies it like a noise sighting (`SyncNoise`): an item whose secret a corrected rule made noise
  closes as `reclassified`. Fingerprints without an item are ignored, so `sync --include-noise`
  needs `emit_noise: true` to track noise-only secrets.

Hints. Every value hint the connector writes is `secretrisk.Redact`'s: the known prefix, `…`, the
last four characters when the value is long and random, and the length, `sk_live_…a1b2(107)`;
`secretrisk.ParseHint` reads it back. Keys and whole files have no value hint (`PEM`, empty).
Every other connector that reports a key writes its hint in the same format, from what the
provider shows: `secretrisk.Masked` keeps every character the provider shows in front, at most the
last four at the end, and the length, or `(?)` when the provider does not give it
(`sk-or-v1-27e…d4d(?)`, `sk-ant-api03-R2D…igAA(?)`, Azure's first characters `abc…(?)`);
`secretrisk.RedactID` writes an identifier that names a key (`AKIA…WXYZ(20)`). `ParseHint` reads
`(?)` as an unknown length (`Hint.Len` 0): such a hint agrees with any length and locates no value
(`Hint.Fits` needs a length). `secretrisk.ReadHint` also reads a provider's raw masked form, for
findings written before this convention.

Titles. A rotate item is named `<label> <hint> in <repo>:<file> (+N places), committed YYYY-MM`,
with ` = "<key name>" (in use, $N this month)` after the hint when a provider's live key matched it
(see "Correlation"): the location that exposed it most (among equals the owner's repository, then the latest commit),
the number of other locations, and the earliest commit date. Within a priority, secrets that are
live and leaked come first (see "Correlation"), then by exposure, then those a working file holds
(`used_in`), with a copy in an owned repository, with the most recent commit, and found in more
places. `rotations next` and the "Rotate N P0 secrets" entry of `status` follow that order.

### Guided rotation: `next` and `replace`

- `next [--priority P0] [--service x]` prints the first active item in list order with its
  reasons, locations (worst first, eight at most), `rotate_url`, the service's rotation guide,
  `used_in` with the recorded line, and the commands to run next. Guides live in
  `internal/secretrisk/guides.go`: two to four steps per type, each citing the provider page it
  was checked against.
- `replace <id>` never stores, prints or passes the new value as an argument. It reads it from
  `pbpaste` or a pipe (`--stdin` refuses a terminal, which would echo it). A value must be one
  line of `[A-Za-z0-9._~+/=:@%-]`, so it can go unquoted into a shell, `.env` or JSON line;
  anything else is edited by hand.
- Locating the old value without having it: the redacted hint gives its length, prefix and last
  four characters (`secretrisk.ParseHint`), so every window of the line that fits is HMAC'd with
  the fingerprint key (`internal/fingerprint`) and compared with the item's fingerprint. The
  recorded line must still hold it, or the file changed since the scan and `replace` refuses.
  Other lines of the same file that hold it are replaced too. Types that are not one value on
  one line (PEM keys, service-account files, keystores) are refused.
- The new value's fingerprint must differ from the item's: a clipboard still holding the old key
  is refused.
- `--apply` confirms like `remediate` (a terminal on stdin, or `--yes`), re-reads each file and
  refuses one that changed since the plan, writes it with `statefile.Replace` (temporary file,
  fsync, rename; mode kept; a symlink's target is written, the link stays), then re-reads every
  file: the old fingerprint must be gone from all of it and each edited line must hold the new
  value. Only then is the item marked `rotated` and the clipboard cleared (`pbcopy` with empty
  stdin).
- `--to-keychain <service>`: for shell rc files whose line is a plain `[export ]NAME=value`, the
  value is stored with `security -i` reading `add-generic-password -U -a $USER -s <service> -w
  <value>` from stdin (no argument list carries it), read back with `find-generic-password -w`
  and compared by fingerprint before any file changes; the line becomes
  `export NAME="$(security find-generic-password -a "$USER" -s <service> -w)"`.
- `--backup` keeps a 0600 copy of each file as it was. It is off by default because the copy
  holds the old value in plaintext.
- History: `next` (once per run of consecutive calls), `replace-plan` (dry run),
  `replace-failed` (with what was already written), `done` (with the files and Keychain service).

## Attribution

The owner of old projects wants to rotate only what links to them personally. `internal/attribution`
decides, for each secret, `mine`, `not-mine` or `unknown`, offline: attribution asks no provider
about a leaked secret. The liveness check (see "Liveness"), off by default, does call providers,
and only with secrets attribution already allows; what it learns (the AWS account, GitHub login or
Slack workspace a key signs in as, the account whose IAM inventory holds a key id, the GitHub login
that registered a key) is one more claim. Its only call that names a leaked value is `sts
get-access-key-info`, with the owner's profile, for an AWS key id of the older format whose account
cannot be decoded.

**Claims, at scan time.** Only local-secrets has the raw value, so it derives the identifiers there
(`connectors/localsecrets/attribution.go`) and stores them in the evidence (`aws_account`,
`slack_team`, `gcp_project`, `author_email`), never the key id or the value:

| Claim | From | How |
|---|---|---|
| `aws_account` | an access key id (AKIA, ASIA), alone or in a pre-signed URL | base32-decode the 16 characters after the prefix; the first 6 bytes, big-endian, masked with `0x7fffffffff80` and shifted right 7 bits, are the account id (Tal Be'ery, "A short note on AWS KEY ID", 2023; reproduced at [hackingthe.cloud](https://hackingthe.cloud/aws/enumeration/get-account-id-from-keys/); `AKIASP2TPHJSQH3FJXYZ` gives `171436882533`, the example of the [aws_account_id_from_key_id](https://docs.rs/aws_account_id_from_key_id) crate). Key ids of the older format, fifth character `I` or `J`, carry no account |
| `aws_account` | a secret access key | the key id in the same file (or the matched line, in git history), when the file names one account only |
| `slack_team` | an incoming webhook URL | its first path element (`hooks.slack.com/services/T…/…`); tokens (`xox…`) carry no documented team id |
| `gcp_project` | an OAuth client id (`<number>-….apps.googleusercontent.com`) | the project number it starts with |
| `gcp_project` | a Google API key, OAuth client secret or service-account key | the file around it: `project_id`, `project_number`, `GCM_SENDER_ID`, or a client id, when it names one project only. An API key alone names none |
| `author_email` | a git history finding | the author of the commit gitleaks reports |
| `aws_account`, `github_login`, `slack_team` | the liveness check | the account the provider says the key signs in as (`secret.liveness.account`): STS `Account`, GitHub `login`, Slack `team_id`; for lookups, the account whose IAM inventory holds a key id (or that `sts get-access-key-info` names) and the GitHub login (or repository owner) that registered a private key's public half. A GitHub login is compared with `owned.github` |

History findings replayed from the incremental cache (see "Incremental git history scan") keep
the claims of the run that first scanned them; ones cached before claims existed gain them at the
next full scan.

**The owner's accounts.** `attribution.Discover` reads them from connector runs: aws accounts
reported by id, and an info finding `aws_account` (`account_id`) when an alias stands in for the
id; one info finding `gcp_projects` per gcp account with the id and number of each project it
sees, and the gcp accounts (people, not service accounts) as emails; the google-personal accounts
inspected (status `ok`) as emails; one info finding `slack_workspace` (`team_id`, read from the
manage page's URL or the links of its apps) per Slack workspace connected-apps reads;
the GitHub login and every organization the github and connected-apps connectors name. Each sync adds what it finds to the
tracker's top-level `owned` and never drops a value, so a sync without an aws run still knows the
account. Config `owned` (`aws_accounts`, `gcp_projects` (ids or numbers), `slack_teams`, `github`,
`emails`) adds what no connector reaches, and `git config user.email` adds the commit email.
`segurata accounts owned` prints them all, each with its source.

**Verdict.** Every sync folds the claims of each sighting into the item's
`secret.attribution.facts` (kept, like locations, when a later scan no longer sees them), adds the
GitHub owner of each repository a location lies in (its `origin` remote in `.git/config`, worktrees
followed to the main repository), and recomputes `secret.attribution` before the decisions' rules
run:

- `mine` (confidence high) when a claim names one of the owner's accounts, projects or workspaces;
  medium when another claim names someone else's (a file holding two accounts);
- `not-mine` (medium) when the claims name only accounts that are none of the owner's known ones,
  and at least one of the owner's of each kind named is known;
- `unknown` (low) otherwise: no claim, or a claim of a kind where none of the owner's accounts is
  known ("run its connector or set owned.aws_accounts").

A verdict of mine also restores full impact to copies in third-party repositories and inherited
fork history (see "What counts against the owner").

Not-mine is a comparison with the accounts known, not proof: an old AWS account the owner still
holds but no profile reaches reads as someone else's until it is listed in `owned.aws_accounts`.
Commit authorship ("committed by you (me@x.com)", "committed by someone else") and repository
ownership ("in a repository of instructure, none of your GitHub accounts or organizations") are
listed as hints and never change the verdict.

`rotations show` prints the verdict, its reasons and the facts; `rotations list --owner
mine|not-mine|unknown` filters by it and shows an OWNER column; `rotations sync` counts open
secrets by owner. Decision rules use it through `owners` (see "Decisions and rules").

## Liveness

Most leaked secrets are long dead, so a P0 should mean "leaked and still works". With
`liveness.enabled` in local-secrets' config, the connector tries each distinct secret once against
its provider's cheapest read-only identity endpoint and records live, dead or unknown
(`connectors/internal/liveness`, `connectors/localsecrets/liveness.go`).

```json
{"connectors": {"local-secrets": {"config": {"liveness": {"enabled": true, "owners": ["mine", "unknown"], "providers": ["github", "aws"]}}}}}
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Off unless set |
| `owners` | `["mine"]` | The attributions whose secrets may be tried; `not-mine` is refused as a config error |
| `providers` | every provider below | Allowlist of providers to ask |

**When and with what.** The scan is the only moment segurata holds a value, so the check runs at the
end of the scan, before the findings are emitted, for at most 10 minutes and ending a minute before
the run's deadline. The findings are emitted whatever happens to the check: a run cancelled or out
of time while it probes still reports the scan, and is marked interrupted. The
values of secrets of a supported type stay in memory for the run. An AWS secret access key is tried
with the long-term (AKIA) key id written nearest it in the same file (or file and commit), at most
five lines away (`awsPairLines`: a credentials file, an `.env` or an Ansible vars block puts the two
on consecutive lines, sometimes a region or bucket between), on the side the file writes its key
ids (above the secret key when the file's first key id comes before its first secret key), one key
id to one secret key, nearest first (`awsPlace.pair`). A file of several pairs so tries each secret
key with its own key id. A secret key with no key id that close takes the file's only key id,
however far; with none, or with several all further away, it is tried alone (unsupported). A
temporary (ASIA) key id never pairs: it needs its session token. A secret is tried when the run reports it (noise never is, which leaves copies in other
people's repositories alone) and its attribution, computed as the next sync would (the tracker's
facts plus this scan's claims, against the tracker's accounts and config `owned`, lent by the core
in `connector.Request.Known`, never sent to an external connector), is one of `owners`: for an AWS
key pair, the key id's attribution as well as the secret key's, which counts the key id's claims as
its own (in a file of two accounts it names none by itself). The checker applies the owner and
provider gates to every fingerprint of a probe before it looks in the cache or recovers a value, so
someone else's key is neither sent nor answered from the cache. A run without a tracker gets no
attribution and tries nothing.

Secrets seen only in history replayed from the git history cache have no value in memory. When the
liveness cache has no fresh answer for one and the check still has time, its value is read again
at check time: `git cat-file -s` and `git cat-file blob <commit>:<path>` (files up to 8 MiB) give
the file as committed, and on the line gitleaks reported, or the one before or after, the window
that fits the redacted hint and has the secret's fingerprint is the value
(`fingerprint.Key.Find`, the search `rotations replace` uses to locate an old value). An AWS secret
key brings the key id it pairs with, by the same rule, in the same file and commit. The value lives in the probe for
that one call. One that cannot be read (a commit gone, a file too big, a hint without a length)
stays unchecked, counted as "without a value at hand".

**Safety.** Every call is a GET, except two POSTs: Slack's auth.test, which Slack documents as POST,
sent without a body, and Linear's GraphQL endpoint, whose documentation shows only POST, sent the
fixed query `{ viewer { id } }` (a query, never a mutation). None changes state, costs money or sends anything; slack webhooks (trying
one posts), Twilio and Mailgun keys (they need a second credential or a region segurata cannot
know) and npm `_authToken` lines (any registry) are not tried. One call at a time per provider and
at most four a second overall, through `httpx`, following no redirect: a 3xx is unknown, and the
key goes nowhere but the provider's URL. Results are cached in `~/.cache/segurata/liveness.json` (0600) by fingerprint: live for 1
day, dead for 7, unknown never; a result dated after now (a clock that jumped forward) is never
fresh, and the tracker drops one too. A result holds the state, the date, the provider, the endpoint,
segurata's own reason (`HTTP 401`, `invalid_auth`, `InvalidClientTokenId`) and the account the
provider names; never the value and never the provider's message, which may echo part of the key.
Every word read from a provider's answer (a code, a reason, a status, an account id) passes one
sanitizer, `providerText`: at most 64 characters of letters, digits and `_ . @ -`, else dropped.
After it, any result field that holds 8 characters in a row of the value or key id is dropped too,
and a failed call's error names the scheme, host and path with Telegram's token masked, never the
query.
The status line counts what was asked, read from the cache, recovered from git history, refused by
owner or provider, unsupported, left without a value and interrupted.

**Providers.** Live is a 2xx; dead is only the signal in the body that the provider documents for an
invalid, revoked or expired key (`deadWhen` in `providers.go`). A status alone is never dead: a 401
can be a key of another instance, region or partition, an IP allowlist or a missing scope. Anything
else (network, 5xx, rate limits, a 403 that may be a region, a bare 401) is unknown, except where a
403 or 429 proves the key was accepted. Every result records the version of these rules
(`secretrisk.LivenessRules`, now 2); version 1 also read a bare 401 as dead.

| Provider (types) | Endpoint | Live | Dead | Docs |
|---|---|---|---|---|
| OpenAI (`openai-*`) | `GET api.openai.com/v1/models`; admin keys (`sk-admin-`) `GET /v1/organization/projects?limit=1` | 2xx; 429 (out of quota or over the rate limit: the key was accepted) | never: the error-code guide lists a 401 for a wrong, deleted or revoked key, for an IP outside the allowlist, for an account out of its organization and for a key without the endpoint's permission, and documents no body code that tells them apart | [models](https://developers.openai.com/api/reference/resources/models/methods/list), [error codes](https://developers.openai.com/api/docs/guides/error-codes), [projects](https://developers.openai.com/api/reference/resources/projects/methods/list) |
| Anthropic (`anthropic`) | `GET api.anthropic.com/v1/models` with `x-api-key`; admin keys (`sk-ant-admin`) `GET /v1/organizations/me` | 2xx; 403 `permission_error` | 401 with `error.type` `authentication_error` ("malformed, revoked, or expired"; for admin keys by the same error model) | [models](https://platform.claude.com/docs/en/api/models/list), [errors](https://platform.claude.com/docs/en/api/errors), [Admin API](https://platform.claude.com/docs/en/manage-claude/admin-api) |
| OpenRouter (`openrouter`) | `GET openrouter.ai/api/v1/key` | 2xx; 402 (no credits) | 401 with `error.code` 401 ("disabled/invalid API key") | [key](https://openrouter.ai/docs/api-reference/limits), [errors](https://openrouter.ai/docs/api-reference/errors) |
| GitHub (`github`, `github-pat`) | `GET api.github.com/user`; account `github:<login>` | 2xx | never: GitHub Enterprise Server and GHE.com issue tokens of the same formats, which api.github.com rejects with the 401 a revoked token gets. A 403 tells nothing either: installation tokens (`ghs_`) cannot call `/user`, and GitHub may answer 403 to any credential after many invalid ones | [get the authenticated user](https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user), [authenticating](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api), [installation token endpoints](https://docs.github.com/en/rest/authentication/endpoints-available-for-github-app-installation-access-tokens) |
| GitLab (`gitlab`) | `GET gitlab.com/api/v4/user` with `PRIVATE-TOKEN`; account `gitlab:<username>` | 2xx; 403 `insufficient_scope` | never: a 401 is unknown, the token may belong to a self-managed instance | [users](https://docs.gitlab.com/api/users/), [troubleshooting](https://docs.gitlab.com/api/rest/troubleshooting/) |
| AWS (`aws-secret-key` with its key id) | `GET sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15`, Signature Version 4 by hand (us-east-1, `sts`); needs no IAM permission; account `aws:<id>` | 200 | never: the global endpoint answers 403 `InvalidClientTokenId` to a deleted key id and to every key of the GovCloud and China partitions alike; `SignatureDoesNotMatch` says the pair found is not a pair | [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html), [common errors](https://docs.aws.amazon.com/STS/latest/APIReference/CommonErrors.html), [GET for Query APIs](https://docs.aws.amazon.com/IAM/latest/UserGuide/programming.html), [Signature Version 4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html); the signer is tested with AWS's `get-vanilla` vector |
| Google (`google-api-key`) | `GET generativelanguage.googleapis.com/v1beta/models?pageSize=1` with `x-goog-api-key`; free | 2xx; 403 with an `ErrorInfo` reason (`SERVICE_DISABLED`, a restriction): the key exists | 400 `API_KEY_INVALID` | [API keys](https://aistudio.google.com/docs/api-key), [troubleshooting](https://aistudio.google.com/docs/troubleshooting), [error model](https://google.aip.dev/193) |
| Slack (`slack-token`) | `POST slack.com/api/auth.test`, no body; account `slack:<team_id>` | `ok: true` | `ok: false` with `invalid_auth`, `token_revoked`, `token_expired` or `account_inactive` (`not_authed`, "no token provided", is unknown: segurata sent one) | [auth.test](https://docs.slack.dev/reference/methods/auth.test) |
| Stripe (`stripe-live`, `stripe-test`) | `GET api.stripe.com/v1/balance` | 2xx; 403 (a restricted key without that permission) | 401 with `error.code` `api_key_expired`. Any other 401 is unknown: Stripe documents no code for a wrong key | [retrieve balance](https://docs.stripe.com/api/balance/balance_retrieve), [authentication](https://docs.stripe.com/api/authentication), [keys](https://docs.stripe.com/keys), [error codes](https://docs.stripe.com/error-codes#api-key-expired) |
| SendGrid (`sendgrid`) | `GET api.sendgrid.com/v3/scopes`, then `api.eu.sendgrid.com` | 2xx; 403 | never: the documented 401 is "authorization required", the caller "doesn't have the authorization to view the list of scopes"; the EU host is asked whenever the global one does not accept the key | [scopes](https://www.twilio.com/docs/sendgrid/api-reference/api-key-permissions/retrieve-a-list-of-scopes-for-which-this-user-has-access) |
| Telegram (`telegram-bot`) | `GET api.telegram.org/bot<token>/getMe` (the recorded endpoint hides the token); account `telegram:@<username>` | 2xx | never: the Bot API says `error_code` "is subject to change" | [getMe](https://core.telegram.org/bots/api#getme) |
| Hugging Face (`huggingface`) | `GET huggingface.co/api/whoami-v2`; account `huggingface:<name>` | 2xx | never: no error is documented | [OpenAPI](https://huggingface.co/.well-known/openapi.md) (lists the endpoint, documents only its 200) |
| npm (`npm-token`) | `GET registry.npmjs.org/-/whoami`; account `npm:<username>` | 2xx | never: no error is documented | [npm whoami](https://docs.npmjs.com/cli/v10/commands/npm-whoami) (says it calls `/-/whoami`) |
| xAI (`xai`) | `GET api.x.ai/v1/api-key` | 2xx with no flag set; 403 (lacks a permission) | 200 with `api_key_blocked`, `api_key_disabled` or `team_blocked` true. A 401 is unknown: xAI documents no body code for it | [API key](https://docs.x.ai/developers/rest-api-reference/inference/other), [errors](https://docs.x.ai/developers/debugging) |
| Groq (`groq`) | `GET api.groq.com/openai/v1/models` | 2xx | never: the errors page gives a 401 no body code | [API reference](https://console.groq.com/docs/api-reference), [errors](https://console.groq.com/docs/errors) |
| Notion (`notion`) | `GET api.notion.com/v1/users/me` with `Notion-Version: 2026-03-11`; account `notion:<workspace_id>` | 2xx; 403 `restricted_resource` | 401 with `code` `unauthorized` ("The bearer token is not valid") | [retrieve your bot user](https://developers.notion.com/reference/get-self), [status codes](https://developers.notion.com/reference/status-codes) |
| Cloudflare (`cloudflare-token`) | `GET api.cloudflare.com/client/v4/user/tokens/verify`, only for a token whose key names Cloudflare (a bare `CF_TOKEN` may be any provider's; gitleaks' rule requires the word) | `result.status` `active` | `result.status` `disabled` or `expired`. Any error is unknown: account-owned tokens verify at `/accounts/{account_id}/tokens/verify` and a Global API Key needs the account email | [verify user token](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify/), [account-owned tokens](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/) |
| DigitalOcean (`digitalocean`) | `GET api.digitalocean.com/v2/account`; account `digitalocean:<uuid>` | 2xx | 401 with `id` `unauthorized` | [account](https://docs.digitalocean.com/reference/api/reference/account/index.html.md) |
| Sentry (`sentry-token`) | `GET sentry.io/api/0/organizations/` | 2xx | never: a token of a self-hosted Sentry or of another region may be refused by sentry.io, so any error is unknown | [list your organizations](https://docs.sentry.io/api/users/list-your-organizations/), [data storage location](https://docs.sentry.io/organization/data-storage-location/) |
| Linear (`linear`) | `POST api.linear.app/graphql`, query `{ viewer { id } }`, the key in `Authorization` without `Bearer`; account `linear:<id>` | `data.viewer.id` | never: the GraphQL guide lists no error code for an invalid key | [GraphQL API](https://linear.app/developers/graphql) |

Known gap: OpenAI answers 403 from unsupported regions, which reads as unknown. Fail closed costs
dead verdicts: GitHub, GitLab, AWS, OpenAI, SendGrid, Telegram, Hugging Face, npm, Groq, Sentry and
Linear never say dead, so their dead keys stay open until the owner closes them.

**Lookups with the owner's credentials.** Two kinds of secret cannot be tried by themselves: an AWS
access key id with no secret key beside it, and a private key. They are looked up instead
(`connectors/internal/liveness/lookup.go`) with the owner's own aws CLI profiles, gh login and
`~/.ssh`, and the secret is never sent: the key id is compared in memory with the owner's IAM
inventory, the private key's public half with the keys the owner registered. A lookup runs for
secrets attributed mine or unknown whatever `owners` says (it tries nothing), never for not-mine,
and only for the providers `aws-keys` and `ssh-keys` the allowlist names (both by default). Its
result has `by_owner: true`; its endpoint is what was read and its reason what that says. Each
command goes through a read-only guard: aws `configure list-profiles`, `sts get-caller-identity`,
`sts get-access-key-info`, `iam list-users`, `iam list-access-keys`, `iam get-account-summary`; gh
`api [--paginate]` with five GET paths; ssh with one fixed shape. No command output or error text
is kept (a CLI's error may echo its arguments): a failure is reduced to a code ("AccessDenied",
"not installed") and a setup hint at the end of the status line.

| Secret | Read once per run | Live | Dead | Otherwise |
|---|---|---|---|---|
| AWS key id (AKIA) alone (`aws-keys`) | per profile in `liveness.aws_profiles` (default `aws configure list-profiles`; a profile holding a Cloudflare R2 token or another S3-compatible key is skipped, the same test the `aws` connector applies): `sts get-caller-identity`; per account reached: `iam list-users` (at most 1000), `iam list-access-keys --user-name` for each, `iam get-account-summary` (`AccountAccessKeysPresent`, the root user's keys) | Active in an account's inventory | Inactive there; or not among the keys of the account it belongs to, when that account's inventory was read whole and its root user has no keys (deleted) | unknown: an ASIA id (temporary credentials, never listed); an account no profile reaches (its id is a claim, so attribution decides); an inventory not read whole; root keys present; a profile that does not sign in |
| Private key (`private-key`, `ssh-key`; `ssh-keys`) | gh `api user`, `api --paginate user/keys`, `api --paginate user/ssh_signing_keys`, `api user/repos?affiliation=owner&sort=pushed&per_page=30` and `api repos/<repo>/keys` for each; `~/.ssh/authorized_keys` and `~/.ssh/*.pub`; with `liveness.ssh_hosts` (at most 20), `ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -T -- <host> cat .ssh/authorized_keys` | its public half's SHA256 fingerprint is a GitHub SSH or signing key, a deploy key, or in an authorized_keys: "GitHub SSH key \"laptop\"", "authorized on host build1" | never | `unregistered` when found nowhere and both GitHub lists were read; unknown when it is only the `.pub` of a key in `~/.ssh` (used from here), when it is not in the OpenSSH container and not from `~/.ssh` ("may sign TLS certificates or JWTs"), when GitHub's lists could not be read, and for a PKCS#8 key encrypted or a body cut short |

The account of an AKIA key id comes from the key id itself (see "Attribution"); for one of the older
format (fifth character I or J), `sts get-access-key-info` with the first profile that signs in,
the one command given the key id. GetAccessKeyInfo "does not indicate the state of the access key",
so absence is read from the inventory, never from it. The public half comes from
`connectors/internal/sshkey`, standard library only: the OpenSSH container stores it in clear (even
when the private part is encrypted); PKCS#1, PKCS#8 and SEC 1 keys are parsed with `crypto/x509`,
and EC keys with explicit curve parameters (macOS's ssh-keygen writes them) by hand; the SSH wire
format (RFC 4253 6.6, RFC 5656 3.1, RFC 8709 4) is built field by field and fingerprinted as
ssh-keygen does. Tests compare it with ssh-keygen's output for every type and container.

A PEM key (PKCS#1, PKCS#8, SEC 1; RSA, ECDSA or Ed25519) is looked up like an OpenSSH one, wherever
it is found: a `.pem` in a project that matches a registered key is live, since the match proves the
key works for SSH whatever else it signs. Only the miss differs: outside `~/.ssh` such a key may be
a TLS or JWT signing key that no SSH registry holds, so it stays unknown and is never
`unregistered`. Tests generate these keys with `ssh-keygen -m PEM`/`-m PKCS8` and `openssl` and
match them against the public half `ssh-keygen -y` derives.

Unregistered is not proof of death: the key may be authorized on a host segurata does not read. It
lowers the item's priority one step (P0 to P1) unless a connector reports the key live, counts as
checked in the liveness line, and is cached for a day, like live: a key can be registered any day.

| API | Permission | Docs |
|---|---|---|
| `sts:GetCallerIdentity` | none | [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html) |
| `iam:ListUsers`, `iam:ListAccessKeys`, `iam:GetAccountSummary` | the same names (all in SecurityAudit) | [ListAccessKeys](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html) (Status `Active`, `Inactive`), [ListUsers](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html), [GetAccountSummary](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html) |
| `sts:GetAccessKeyInfo` | `sts:GetAccessKeyInfo` (an action of access level Read) | [GetAccessKeyInfo](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetAccessKeyInfo.html), [STS actions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssecuritytokenservice.html) |
| GitHub `GET /user/keys` | `read:public_key` | [keys](https://docs.github.com/en/rest/users/keys?apiVersion=2022-11-28#list-public-ssh-keys-for-the-authenticated-user) |
| GitHub `GET /user/ssh_signing_keys` | `read:ssh_signing_key` | [SSH signing keys](https://docs.github.com/en/rest/users/ssh-signing-keys?apiVersion=2022-11-28) |
| GitHub `GET /repos/{owner}/{repo}/keys` | admin on the repository; a repository gh may not read is skipped | [deploy keys](https://docs.github.com/en/rest/deploy-keys/deploy-keys?apiVersion=2022-11-28#list-deploy-keys) |

**In the tracker.** A rotate item keeps the newest result of its sightings in `secret.liveness`
(`internal/tracker/liveness.go`):

- **Live** is proof the key works, as a connector's report is (see "Correlation"): the reason
  "live: GET api.github.com/user accepted it on 2026-11-25 as github:octocat", P0 and first among
  secrets once a copy left the machine (pushed history, a transcript), liveness 1.5 (2 when leaked)
  in "Do next" and no confidence discount. An ignored item opens again ("proven live by the
  liveness check of …"), as does a done one when the check is newer than the done.
- **Dead** closes an open, in-progress or snoozed item as `done` (history action `dead`, "key no
  longer valid (checked 2026-11-25: GET api.notion.com/v1/users/me answered unauthorized)") once
  no working file holds the key, and its reasons say "dead: … rejected it on …". A key nobody can
  use is where a rotation ends too, so the item ends the same way instead of staying open at P3.
  A copy in a working file keeps the item open, or opens a closed one again ("new working
  location …"): the owner still has a file to clean. A later check that finds it live opens it
  again; the owner reopening it by hand after the check keeps it open. Ignored and accepted items
  are not touched, nor an item a connector reports live: two sources disagree and the item stays
  open. A dead verdict of rules older than `secretrisk.LivenessRules` (a bare 401 under version 1)
  is dropped, held or seen, and an item such a verdict closed opens again ("the dead verdict that
  closed it no longer stands") unless a check of the current rules finds the key dead. The liveness
  cache's version went up with the rules, so the first run after the upgrade asks every secret
  again.
- **Unregistered** (lookups only) lowers the priority one step; see above.
- **Unknown** changes nothing: it never replaces a held live, dead or unregistered result, however
  newer (a 429 after the live result's day would otherwise drop a P0).

`rotations list` has a LIVE column (live, dead, unregistered, unknown, unchecked) and ends, like the
status briefing after its coverage line, with "Liveness checked for N of M secrets: …", where M
counts the tracked secrets (not noise, not merged) and N those found live, dead or unregistered.
`rotations show` prints the answer, its date, what was read and the account.

## Correlation

Two connectors can report one secret: the aws connector finds the long-lived key in
`~/.aws/credentials`, and local-secrets finds the same key there and pushed to a repository's
history. The rotate item owns the problem (`internal/tracker/correlate.go`). At every sync, before
grouping, each credential finding of a folded run is matched with a rotate item:

| Connector | Findings | Rotate items it may match |
|---|---|---|
| aws | `aws_local_credentials` | service aws |
| aws | `r2_local_credentials`, `s3_local_credentials` | any |
| gcp | `local_credential` (ADC, service-account key files) | services gcp, google, oauth, private-key |
| openai, openrouter, anthropic | `api_key` (info ones too: a key in use) | the same service |

The match is, in order: the fingerprint, when the finding carries one (the aws connector gives the
key id's); a finding with a fingerprint matches nothing else, since the key in the file may have
been rotated since the copy leaked. Else the service, prefix, last characters and length: both
hints are read into prefix, tail and length (`secretrisk.Hint`, see "Hints"), and they agree when
one prefix starts the other, one tail ends the other and known lengths are equal
(`Hint.Agrees`); a hint match needs at least three characters of tail, enough to tell keys apart.
A hint that fits two or more secrets merges into none: each of them records the finding under
`possible` (match `possible`, title "… (its hint fits 2 secrets)", reason "possibly: <instance>:
<title>"), which never raises a priority, and the connector's item stays. Else the file: a rotate
item with a location at the finding's path (`file`, `path`) whose hint, when both have one, fits;
among several the most urgent wins, since a file can hold several parts of one credential (ADC's
client secret and refresh token). A finding whose item the owner accepted is left alone.

Each match has a `confidence`: `certain` by fingerprint (and for a secret a connector signs in
with), `high` by a hint with four or more tail characters and the same known length on both sides,
`medium` by a shorter tail, an unknown length or the file. A provider's key (openai, openrouter,
anthropic) also brings its facts (`key`: name, last use, spend this month when the connector
reports it, OpenRouter's `usage_month`), and the rotate item's title names the key from the
surest live ref that has them: `OpenRouter API key sk-or-v1-…fd4d(73) = "Claude Code" (in use,
$42.00 this month) in ~/.claude/projects/p/s.jsonl` (in use: used within 90 days of that run,
`finding.IdleAfter`; else "last used YYYY-MM-DD").

A matched finding is not grouped: it goes on the rotate item as a finding ref with `match`
(`fingerprint`, `hint` or `path`) and `confidence`, replaced at every sync that folds its connector instance. The
connector's item loses that ref; left with nothing reported, an open, in-progress, snoozed or done
one closes as `merged` (history `merged`, "the same secret as T-0404, which owns it now",
`merged_into` set, next step "Nothing here: T-0404 owns this secret"). When a later sync no longer
matches the finding (another fingerprint, another key), it goes back to its item, which opens again
(`auto-reopen`, "no longer the same secret as T-0404").

The core also writes, in each run's `run_end`, the fingerprints of the secrets it resolved for the
instance (`secret_fingerprints`, by name, never the value). A rotate item with one of them gets a
ref `uses:<instance>:<name>`, "segurata's vercel connector signs in with it (VERCEL_TOKEN) and its
run of 2026-11-24 worked": the token segurata uses is one of the leaked ones.

On the rotate item, the refs still reported are evidence the secret is live:

- its priority is the worse of its own and its refs' severities (critical P0, high P1, …);
- a live secret whose worst copy left the machine (pushed history, a transcript) is P0, its first
  reason is "live key, leaked in <repo>:<file>", and it sorts first among secrets;
- each ref adds a reason "live: <instance>: <title>" ("live: aws: Long-lived AWS access key for
  profile "default" stored in plain text; aws sts says it works for account 123456789012",
  "live: openrouter:personal: API key "Claude Code": in use with a credit limit");
- an ignored item opens again (history `reopened` / `proven-live`, "proven live by aws; it was
  ignored: …"), since the connector's own item merged into it and the key would otherwise have no
  open item. A decision's rule that ignored it does not close it again. Ignoring it by hand after
  the proof sticks. An accepted item stays accepted (the risk was kept on purpose; the priority
  still rises);
- a done item opens again when a connector signs in with the old value itself (a fingerprint
  match: a hint or a path would also fit the new key in the same file) in a run after it was marked
  rotated: "proven live by aws; after it was marked rotated: …". Marking it rotated again holds
  until a later run proves the old value live again. Otherwise a done item is reopened only by the
  working-file sightings of "Rotation ledger".

## Redaction

```
segurata redact --trails                       dry run: files, matches per file and per type, bytes
segurata redact --path ~/.claude/projects/-src-shop
segurata redact --item 3f9a12c4                one rotation item's secret, in every trail
segurata redact --trails --min-priority P1 --apply [--yes] [--backup]
```

A remediation that rewrites local trail files (`internal/redact`). Transcripts, shell histories
and logs keep secrets in plaintext long after they were pasted. Those copies already went
wherever they went (a transcript reached the model provider), so rotation is still required;
redaction removes the copy that stays on disk, in backups and in sync tools.

- Scope: `--trails` is every trail `local-secrets` scans (its history, log and transcript ripgrep
  passes); `--path` narrows to trail files under a prefix; `--item` takes only that ledger item's
  secret. `--min-priority` uses the item's priority when the ledger knows the secret, otherwise
  that copy's. A working file (config, `.env`, rc, repo working tree) is never touched, whatever
  the scope: a program still reads its value.
- Matching is `local-secrets`' own (`localsecrets.Trails`): ripgrep with the same passes finds
  the candidate lines, and the same patterns, classification and judgement, joined into one
  leftmost-first alternation as ripgrep joins several `-e`, place each secret on its line. Go's
  regexp has no DFA and runs that alternation at about 2 MB/s, so `matcher.go` produces the same
  matches another way: each pattern's syntax tree gives literals every match contains at a
  bounded offset from its start; one pass finds them and each pattern is tried alone, anchored,
  where they allow, in the order the alternation would pick. Texts it cannot handle that way go
  through the alternation of the patterns whose literals occur. Tests and a fuzz target check
  both give identical spans. Files are planned in parallel. A value is replaced only if an
  inventory would report it as non-noise (`--include-noise` adds generic `assignment` matches,
  public, expired and encrypted values). Each becomes `[REDACTED:<type>:<fingerprint8>]`, so the
  copy still points at its rotation item.
- Plain lines (shell history, logs) change only in the secret's bytes, which keeps zsh's
  `: <ts>:<d>;cmd` format. A line that is valid JSON is edited inside its strings: where the
  secret stands byte for byte inside one string, and only when the bytes before, the secret and
  the bytes after are each whole string content (no escape cut in two, no quote crossed); then,
  for strings that hold escapes, in the decoded value, re-encoding that one string. Field order
  and every other byte are kept, each rewritten line must parse, and a whole file that was valid
  JSON must stay so. A match that cannot be replaced this way stays and is counted.
- Safety: files modified within `--min-age` (default 2h) and any file a running `claude` or
  `codex` process has open (`lsof -Fn -c claude -c codex`, read-only; if lsof fails the command
  refuses) are left alone, as are symlinks and files of another account. `--apply` confirms like
  `remediate`, then, per file, checks the guards again, refuses a file whose size or modification
  time changed since the plan, writes with `statefile.Replace` (mode kept) and puts the
  modification time back, so tools that sort sessions by date are not confused.
- After applying, ripgrep scans the rewritten files again: no secret in scope may remain beyond
  what the plan said would stay, and mode and modification time must be unchanged. Each rotation
  item whose secret was replaced gets a history note, "redacted from N trail files". Its
  locations stay: the copies were exposed before they were cleaned.
- No backup by default: a backup is one more plaintext copy. `--backup` keeps a 0600 copy next to
  each file and says so loudly.

## Why Go, and why so few dependencies

- One static binary for macOS, Linux and Windows, no runtime to install.
- A security tool with a hundred dependencies is a supply-chain risk in itself. The core uses only
  the standard library (including a minimal WebSocket client for CDP). Cloud connectors call the
  official CLIs (`gcloud`, `aws`, `az`), already authenticated on the machine, instead of
  vendoring their SDKs.
- Any new dependency goes through a 4-day quarantine and is pinned to an exact version.

## Prior art

Prowler and ScoutSuite already audit AWS, Azure and GCP security posture in depth. When that depth
is needed they get wrapped as external connectors rather than rewritten
([plugins/prowler](../plugins/prowler/README.md) runs Prowler's GCP checks). segurata covers what they
don't: consumer accounts, personal OAuth grants, AI-provider keys and spend, and local secrets.
