# Writing a connector

A connector inventories one kind of account or system and emits findings and statuses. This page
is for whoever writes one. How the core runs connectors, remediates and stores state is in
[architecture.md](architecture.md).

Rules every connector follows, whatever its language:

- **Inventory is read-only.** It lists, reads and computes. It never revokes, deletes, clicks a
  button that changes something, or writes outside its own process. Changes happen only through a
  remediation, one finding at a time, after the owner saw the plan and said yes.
- **No secret values anywhere**: not in findings, statuses, logs, stderr, test fixtures or commit
  messages. At most a redacted prefix and the length (`finding.Redact` in Go).
- **English** for code, finding text and docs.

## Built-in or external

| | Built-in | External |
|---|---|---|
| Language | Go, standard library only | Any |
| Lives in | `connectors/<name>/`, registered from `init` and imported in `connectors/connectors.go` | A `segurata-<name>` executable anywhere on `PATH` |
| Contract | The Go interface `connector.Connector` (`Describe`, `Inventory`) | The protocol below, over stdin and stdout |
| Remediation | Optional `connector.Remediator` (`Plan`, `Apply`); the core runs its commands from a hand-written allowlist and may use sudo | Protocol 2 (`plan`, `apply`); the connector runs its own plan, never as root |
| Prerequisite checks (`doctor`) | Optional `connector.Doctor`: checks its own CLIs, sign-ins and tokens with the inventory's read-only code paths | The core checks the `cli:`, `secret:` and `os:` needs of `describe` |
| Ships with segurata | Yes | No: installed by the owner |

Write a built-in connector when it belongs in the binary for everyone and can be written with the
Go standard library. Write an external one for anything else: another language, a heavy
dependency, a private integration, an experiment. The core wraps an external connector in the same
Go interface, so the rest of the program (inventory, summary, accepted risks, remediation, the
rotation ledger) treats both alike. A built-in name wins over an external one with the same name.

A minimal built-in connector:

```go
package example

type Connector struct{}

func init() { connector.Register(&Connector{}) }

func (*Connector) Describe() connector.Description {
	return connector.Description{Name: "example", Version: "0.1.0", Protocol: connector.ProtocolVersion,
		Summary: "What it inventories", Needs: []string{"secret:EXAMPLE_API_KEY"}}
}

func (*Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	key := req.Secrets["EXAMPLE_API_KEY"]
	if key == "" {
		emit.Status(finding.Status{Account: "example", State: finding.StateMissingCredentials,
			Detail: "create a read-only key at https://example.com/keys and reference it in the config"})
		return nil
	}
	// ... read, then emit.Finding(...) for each thing worth looking at
	return nil
}
```

`connectors/openrouter` is a short real one; `connectors/internal/httpx` and `httpxtest` hold
the HTTP client and the test server that provider-API connectors share.

## Finding model

One JSON object per finding (`internal/finding`):

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
  "remediation": {"summary": "…", "url": "https://…", "action": "", "automatable": false},
  "observed_at": "2026-11-23T21:00:00Z"
}
```

| Field | Who sets it | Rule |
|---|---|---|
| `type` | Connector (external) or core | Always `finding` |
| `id` | Core | Leave it empty; the core computes it (see "Stable IDs") |
| `connector`, `instance` | Core | Taken from `describe` and the config, never from the record |
| `account` | Connector | The account inspected: an email, an org id, `mac` |
| `scope` | Connector | Optional: the part of the account the finding belongs to when the connector inspects the account in parts (a repository, a project, a service); see "Coverage". Not part of the id |
| `resource` | Connector | `type` and `id` identify the thing; `name` is for people |
| `kind` | Connector | `grant` (third-party access), `credential` (key, token, service account), `setting` (security configuration), `spend` (spend, budget or limit), `exposure` (secret or personal data in plain sight) |
| `severity` | Connector | `info`, `low`, `medium`, `high`, `critical` (see "Severity") |
| `title` | Connector | One line a person understands without the evidence. No secret, no token |
| `evidence` | Connector | Whatever backs the finding: scopes, dates, paths, counts. Never a secret value |
| `created_at`, `last_used_at` | Connector | What the provider reports, RFC 3339. `null` when it reports nothing, never a made-up date |
| `remediation` | Connector | `summary` says what to do by hand; `url` is the page where it is done; `action` names an automatable remediation or is empty; `automatable` is computed by the core |
| `observed_at` | Core | When the record was written |
| `accepted` | Core | Set from the accepted-risks file |

Besides findings, a connector emits per-account status records saying whether something could be
inspected:

```json
{"type": "status", "account": "org-…", "state": "missing_credentials", "detail": "create a key at …"}
```

| `state` | Meaning |
|---|---|
| `ok` | Inspected |
| `reauth` | The service wants a fresh sign-in or identity check |
| `signedout` | No session |
| `noscope` | Signed in, but the credential lacks a permission; `detail` says which and how to grant it |
| `unverified` | Signed in, but the reader was never checked against a real page |
| `missing_credentials` | No credential configured; `detail` says how to get one and where to put it |
| `unsupported` | The check cannot run on this system |
| `error` | Anything else; `detail` says what failed |

A `detail` is read by the owner at the terminal: say what to do next, with the exact command or
page. Log lines (`{"type": "log", "msg": "…"}`) are shown only with `--verbose`. A status may also
carry a `scope` (next section).

## Coverage

The core compares runs: a finding missing from the latest run counts as resolved, closes its
tracker item and passes a remediation check. That is only true if the run looked where the finding
was. So **a connector must say what it did not inspect**; the core records it in the run's
`run_end` record ([architecture.md](architecture.md#run-completeness)) and never takes a finding
of an uninspected scope as gone.

- **Emit one `ok` status per account inspected.** A run where no status says `ok` counts as having
  inspected nothing.
- **An account not inspected gets a status other than `ok`**, named exactly as the account of its
  findings. A failure reported under another name (`profile dev` while findings say
  `123456789012`, `github` while findings say `github:octo`) covers none of them.
- **When the account is inspected in parts, give findings a `scope`** and name it in the status of
  a part that failed: `{"account": "me@example.com", "scope": "my-project", "state": "error",
  "detail": "permission denied"}` leaves only `my-project` uninspected, not the account. A status
  whose `scope` is `*` leaves everything uninspected (use it when you cannot tell which accounts a
  failure hid).
- **Declare what no status carries** with `emit.Scope(id, false, reason)` (external connectors: a
  `{"type": "scope", "scope": "…", "inspected": false, "reason": "…"}` record): repositories the
  rate limit left unread, items past a configured cap, parts the config turns off. `reason` is one
  line for the owner. `inspected: true` may name a scope that was read, for the record only.
- **A scope ending in `*` covers every scope with that prefix.** Declare `repo:*` when a listing
  failed or when hundreds of items are left over, rather than listing each: the record keeps at
  most 200 skipped scopes, and a run over that counts as having inspected nothing.
- **Do not catch an interrupted context and return nil.** The core treats a cancelled context, or
  an error returned from `Inventory`, as nothing inspected.

Scope names are the connector's own; keep them stable across runs and distinct from account
names. The built-in connectors use, for example, `repo:<owner>/<name>` (github), `history:<repo>`
(local-secrets), the project id (gcp) and the service name (connected-apps).

## Stable IDs

The core hashes connector, instance, account, `resource.type` and `resource.id` into the finding
id. Runs are compared by id (`remediate` checks that a fixed finding is gone, `accept` keeps a
risk across runs, `schedule` notices new findings), so:

- `resource.id` must be the same for the same thing on every run: the provider's id of the key or
  app, a file path, a fixed name such as `brave-remote-debugging`.
- Never put anything in it that changes between runs: a pid, a port, a timestamp, a counter, an
  index in a list.
- Two different things must not share one: when one breach affects two emails, the account or the
  resource id must tell them apart.
- When the state of the thing is part of what the finding says, it may be part of the id on
  purpose: `macos` uses `smb-share-guest:<name>` for a share open to guests and `smb-share:<name>`
  once guest access is off, so the check after a remediation sees the change.

## Severity

Severity is impact if the thing is abused, adjusted by exposure and age. Keep the table in code,
next to a test, so every finding of a kind gets the same answer.

| Severity | Typical cases |
|---|---|
| `critical` | Admin write access to a tenant held by a third party; a live production secret in a place others read (pushed git history, an agent transcript); admin accounts without 2-Step Verification |
| `high` | Full mailbox, drive or cloud access held by an app; keys with no limit; a password exposed in a breach; the browser's debugging port open |
| `medium` | Broad read-only access; a stale but valid key; an exposure of personal data without passwords |
| `low` | Narrow access; old exposures of low-value data; a setting below best practice with little impact |
| `info` | Inventory worth seeing but not acting on: Sign in with Google only, a key that is fine |

- Raise one level when the provider shows the thing unused for over a year, or very recent
  (an exposure in the last year); lower one level for old exposures. Say why in the evidence.
- Never `high` or above for something the owner cannot act on.
- A noise match (a generic pattern, a test fixture) is `info`, not `low`.

## Spend and budgets

A budget only notifies; it does not stop spend. Every connector that reads budgets judges them with
the same rules, so a finding means the same on GCP, AWS and Azure. Built-in connectors map their
provider's budgets to the model in `connectors/internal/budget` and call `budget.Evaluate`; they add
nothing but the mapping and the provider's wording. An external connector cannot import Go: it
applies the rules below itself and emits findings with the same resource types, severities and
title shapes.

### Model

| Term | Meaning |
|---|---|
| Container | What the budgets belong to: a GCP billing account, an AWS account, an Azure subscription. It may have units (the GCP projects it pays for). |
| Budget | `name`, `amount`, `currency`, `period` (`day`, `month`, `quarter`, `year`, `custom`), whether the amount follows last period's spend, thresholds, scope, notification channels, automatic actions. Only budgets that measure money count (not usage or reservation budgets). |
| Threshold | A percentage of the amount (100 is the whole amount) and whether it fires on forecasted or actual spend. Absolute thresholds become a percentage of the amount. Alerts that fire below a value (AWS `LESS_THAN`) and disabled ones are left out. |
| Scope | The units the budget is limited to (none: every unit), any other narrowing worded for people ("14 services", "tag env: prod"), and the exact narrowing those words leave out (the 14 service ids), compared but never shown. Filters narrow what is counted but never count as leaving a unit out, since they cannot be matched to units. |
| Channels | Who is told: `email-admins`, `email-list`, `email-roles`, `email-project`, `monitoring`, `subscribers`, `pubsub`, `action-group`. |
| Actions | Automatic hooks that can stop spend: `pubsub-topic` and `spend-cap` (GCP), `budget-action` (AWS), `azure-action-group` (Azure). |
| Risk | A count of things this run found in the container, or in one of its units, that let someone run spend up: unrestricted API keys and user-managed service account keys (GCP, per project), active IAM user and root access keys (AWS), non-expiring client secrets (Azure, per tenant). |

A budget *alerts* when it has a threshold and at least one channel or action.

### Rules

| Rule | Resource type | Severity | Title shape |
|---|---|---|---|
| No budget alerts | the connector's own (kept from earlier versions) | high | `<Container> has no budget with alerts: nothing warns you when spend runs away` |
| Summary, when some budget alerts | same resource as above | info | `<Container> has 2 budgets: 'A' 110 EUR/month, all projects; 'B' …` (three shown) |
| An alerting budget has no actual-spend threshold at or above 100% | `budget_thresholds` | medium | `Budget 'A' (110 EUR/month, all projects) alerts only at 50%: add 90%, 100% and a forecasted threshold` (90% is asked only when nothing reaches it; the forecast only when missing) |
| An alerting budget reaches 100% but has no forecasted threshold | `budget_thresholds` | low | `Budget 'A' (…) has no forecasted threshold: add one at 100% to hear before the money is spent` |
| Budgets with the same amount, currency, period and scope, exact filters included (thresholds ignored) | `budget_duplicates` | low | `2 budgets named 'A' on <container> are the same (…): delete one`, or the names listed when they differ; one finding per group |
| Some budget alerts, none has an action, and the provider could say so | `budget_enforcement` | info, **medium** when the container has risks | `Budgets on <container> only notify: none is wired to <action>, so nothing stops spend; 2 unrestricted API keys in projects billed here` |
| No budget covers every unit, and a filtered alerting budget leaves out units that have risks | `budget_scope` | low | `Budget 'A' (20 EUR/month, blog) leaves out shop (2 unrestricted API keys)` |
| A unit no alerting budget covers | `<unit>_budget` | high | `Project shop is billed to <container> but no budget with alerts covers it` |

Resource ids are `<container id>/<budget id>` for budget findings, the container id joined to the
sorted budget ids for duplicates, and the container id for enforcement, so they are stable across
runs. Evidence holds the budget as mapped (amount, thresholds, scope, channels, actions) and the
risks counted. Remediations are manual and point to the provider's budget console, or for
enforcement to the provider's guide on capping spend.

Not judged: whether the code behind an action really stops spend (segurata sees the topic, the
action or the action group, not what it does), and recipients the provider does not return (AWS
subscriber kinds need one call per notification and are not read).

## Secrets

- The config never holds a secret value, only a reference (`env:NAME`, `keychain:service`,
  `op://vault/item/field`); the core resolves it and passes the value in the request, in memory.
  A connector declares what it reads in `needs` (`secret:NAME`) and reads it from `secrets`.
- A secret that is missing is a `missing_credentials` status whose `detail` says where to create a
  read-only credential and how to store it in the Keychain, never an error and never a guess.
- One owner per problem. A reference the core cannot resolve (an unset variable, a Keychain item
  that is gone) is the core's: it emits one `missing_credentials` status naming the key and, for a
  secret listed in `needs`, does not call `inventory` at all, so the connector never reports it a
  second time. A built-in connector supplies the steps for that status by implementing
  `connector.SetupHinter` (`SetupHint(secret) string`); they are appended to the core's detail. A
  secret with no reference in the config reaches the connector as absent, and reporting it stays
  the connector's job.
- Ask for the narrowest credential that can read what you need. Read-only keys first.
- Never write a secret to stdout, stderr, a file or a log, not even in debug output. Never put one
  in a URL query when the API accepts a header.
- Never log a request or a response verbatim: responses may echo the key or hold tokens. Decode
  into typed fields and drop what you do not use.
- Tests use synthetic values that look fake (`sk-TEST-not-a-real-key`) and assert they do not
  appear in the output.

## External connector protocol

An external connector is a `segurata-<name>` executable on `PATH`. The core runs it with one
subcommand and, except for `describe`, one JSON request on stdin. The core speaks protocol 1 and
protocol 2; a connector declares the one it speaks in `describe`, and every request carries that
number.

### `describe` (v1, v2)

Prints one JSON object:

```json
{"name": "example", "version": "0.1.0", "protocol": 2,
 "summary": "What it inventories", "needs": ["cdp", "cli:gcloud", "secret:EXAMPLE_API_KEY"],
 "remediates": ["example.token.revoke"]}
```

- `needs`: `cdp` (drives the browser over the DevTools protocol), `cli:<tool>`, `secret:<NAME>`.
  `segurata schedule` leaves out connectors that need `cdp` unless asked for them.
- `remediates` (protocol 2 only): the remediation actions this connector plans and applies. A
  finding whose `remediation.action` is not in this list cannot be remediated through it. An action
  the core owns (`file.chmod600`) is always handled by the core.
- A description that speaks another protocol, or declares `remediates` on protocol 1, is ignored
  with a message on stderr.

### `inventory` (v1, v2)

Reads one request:

```json
{"protocol": 2, "cdp_url": "http://127.0.0.1:9222", "config": {"…": "…"},
 "secrets": {"EXAMPLE_API_KEY": "value already resolved by the core"}}
```

and writes JSON Lines to stdout: `finding`, `status`, `scope` and `log` records as described
above.

- Exit 0 when it finished, even if some accounts reported error statuses. Non-zero only when the
  connector could not start at all.
- stderr is for human diagnostics; the core shows it with `--verbose`.
- The core takes the connector name from `describe`, never from the records, and computes ids.
- Unparseable lines are ignored with a log line.

### `plan` (v2)

Reads one request with the finding to remediate, as it appears in the latest run:

```json
{"protocol": 2, "cdp_url": "http://127.0.0.1:9222", "config": {"…": "…"},
 "secrets": {"EXAMPLE_API_KEY": "…"},
 "finding": {"type": "finding", "id": "9f2c…", "connector": "example", "account": "me@example.com",
             "resource": {"type": "token", "id": "tok_123", "name": "ci"}, "kind": "credential",
             "severity": "high", "title": "Token ci never expires", "evidence": {"created": "2021-01-04"},
             "remediation": {"summary": "Revoke the token", "action": "example.token.revoke", "automatable": true},
             "observed_at": "2026-11-24T08:00:00Z"}}
```

and prints one JSON object, the plan, with the fields of `connector.Plan`, changing nothing:

```json
{"action": "example.token.revoke",
 "summary": "Revoke the token ci (tok_123) of me@example.com.",
 "commands": [{"argv": ["example-cli", "tokens", "revoke", "tok_123"]}],
 "side_effects": ["Anything still using the token ci stops working."],
 "undo": [{"argv": ["example-cli", "tokens", "create", "--name", "ci"]}]}
```

- `action` must equal the finding's `remediation.action`; `summary` is required.
- `commands` are the exact command lines `apply` will run, shown to the owner as they are. A
  connector that calls an API instead lists nothing there and says in `summary` which request it
  makes. `undo` is how to go back, shown, never run.
- `files` (path, `mode`, `was`; modes as decimal numbers) lists permission changes the connector
  will make itself.
- No sudo: a plan with a `"sudo": true` step or `"needs_sudo": true` is refused. The core runs a
  root command only when it is on a hand-written allowlist of exact argument lists compiled into
  segurata, with the owner's terminal attached so sudo asks for the password itself. A plugin's
  command line arrives at run time and was never reviewed, so the core cannot vet it, and running
  it as root would give the plugin root on the strength of one "y". A fix that needs root stays a
  manual one in the finding's `summary`, or becomes a built-in action.
- The reply is decoded strictly: an unknown field or a second JSON value is an error.
- Exit non-zero, with the reason on stderr, when there is nothing to do or the finding no longer
  matches what exists.

### `apply` (v2)

Reads the same request plus the plan the owner confirmed:

```json
{"protocol": 2, "config": {"…": "…"}, "secrets": {"…": "…"},
 "finding": {"…": "…"},
 "plan": {"action": "example.token.revoke", "summary": "…", "commands": [{"argv": ["…"]}]}}
```

runs it, writes `{"type": "log", "msg": "…"}` lines to stdout as it goes (the core prints them),
and exits 0 on success, non-zero on failure. stderr goes to the owner's terminal.

What the core does around it, the same as for a built-in remediation:

1. `segurata remediate <id>` asks `plan`, checks it (action, summary, no sudo, no empty command)
   and prints it. Without `--apply` it stops there.
2. With `--apply`, it asks `Apply? [y/N]` on the terminal (or takes `--yes`), then asks `plan`
   again and refuses to go on if the new plan differs in any field from the one shown.
3. It runs `apply` with the shown plan, then runs that connector's `inventory` twice, 5 seconds
   apart, and reports whether the finding is gone.

`apply` should still check before acting that the plan matches what exists (the token is still
there, the name is unchanged) and refuse otherwise: the core can compare plans, but only the
connector knows the provider. It runs as the owner, with the owner's permissions; installing an
external connector on `PATH` is trusting it with them.

### Versions

| Protocol | Adds | Core |
|---|---|---|
| 1 | `describe`, `inventory` | Speaks it |
| 2 | `remediates` in `describe`, `plan`, `apply`; `inventory` unchanged | Speaks it |

A version 1 connector keeps working unchanged and can never be asked to remediate. To move to
version 2, change `protocol` to 2 and accept `2` in the requests; add `remediates`, `plan` and
`apply` only when there is something to remediate.

## Testing

- Coverage: test that each partial failure (a rate limit, a timeout, a denied project, a cap)
  produces the status or `Scope` declaration that covers the findings it hides
  (`httpxtest.Recorder.Scopes` records the declarations).
- Built-in: test `Inventory` with a recording emitter (`httpxtest.Recorder`) and fake inputs:
  `httpxtest.NewServer` for HTTP APIs (it checks the credential and refuses anything but GET),
  testdata files for CLI output, a temp `HOME` for files. Inject the clock (`Now`) so ages and
  recency are deterministic.
- External: test the program on its own, with a fake HTTP server on `127.0.0.1` and the base URL
  in the config or an environment variable. No real network in tests.
- Protocol: `internal/connector/connectortest` builds fake external connectors from shell scripts,
  as the core's own tests do (`internal/remediate/external_test.go`).
- Every connector test asserts that the synthetic secret is absent from everything emitted, and
  that ids stay the same across two runs over the same input.
- By hand: `segurata connectors` shows whether `describe` loaded; `segurata inventory
  --verbose <name>` runs it and prints its logs and stderr; `echo '{"protocol":2}' |
  segurata-<name> inventory` runs it without the core.
- Before a connector counts as done, run it once against a real account and compare the findings
  with the provider's own pages.

`examples/hibp/` is a complete external connector in Python, with tests. `plugins/prowler/` wraps a
third-party scanner: it runs Prowler per project and turns its OCSF output into findings.
