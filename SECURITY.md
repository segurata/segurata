# Security policy

## Supported versions

Only the latest release gets security fixes. Fixes ship as a new patch release; there are no
backports to older lines.

## Reporting a vulnerability

Report privately. Do not open a public issue, discussion or pull request for a vulnerability.

- **GitHub private vulnerability reporting** (preferred): on the repository's Security tab,
  "Report a vulnerability".
- **Email**: `security@<domain>`.
  **TODO (owner):** replace with a real, monitored address before publishing.

Include the segurata version (`segurata version`), the OS, the connector or command involved, and
steps to reproduce. Never send real secret values, tokens or inventories (`out/`): describe them,
or reproduce with fake values.

## What to expect

- Acknowledgement within 3 business days.
- A first assessment (accepted or not, severity, planned fix) within 10 business days.
- Coordinated disclosure: a fixed release first, then a GitHub security advisory crediting the
  reporter unless they ask otherwise. The target is 90 days from the report, sooner for issues
  under active exploitation.

## Scope

In scope:

- The `segurata` binary and everything under `cmd/`, `internal/` and `connectors/`.
- The built-in connectors: how they call provider CLIs and APIs, parse their output and store
  results.
- The external connector protocol (`segurata-<name>` executables, [docs/connectors.md](docs/connectors.md)):
  how the core discovers, runs and trusts plugins, and validates their output and remediation
  plans.
- The example connector in `examples/hibp`.
- Release artifacts: archives, checksums, signatures and the Homebrew cask.

Out of scope:

- Vulnerabilities in the provider CLIs segurata calls (`gh`, `gcloud`, `aws`, `az`, `rg`,
  `gitleaks`...) or in the services they reach; report those upstream.
- Third-party external connectors not in this repository.
- Findings segurata reports about your own accounts: that is the tool working.
- Attacks that require an attacker who already runs code as your user or controls your `PATH`
  (they can replace the binary itself).

## Security principles

These are the properties segurata promises. Breaking one is a vulnerability.

- **Inventory is read-only.** Connectors list and read; they never change an account, a file or a
  setting.
- **No secret values in output.** Findings, statuses, reports, logs and the tracker carry
  fingerprints and locations, never the secret. Secrets in the config are references (`keychain:`,
  `env:`, `op://`) resolved at run time and never printed.
- **Changes are explicit.** `segurata remediate`, `redact`, `rotations replace` and `schedule`
  show the exact plan and change nothing without `--apply`, then ask for confirmation (refusing
  without a terminal unless `--yes`). `remediate` handles one plan at a time, which can cover several
  findings, and re-checks them afterwards.
- **Allowlisted commands.** Built-in remediations run only exact argument lists from a
  hand-written allowlist, never through a shell. Plugin plans run as the user; a plugin plan that
  needs sudo is refused.
- **Private files.** Inventories and state files are written with mode 0600.
- **Standard library only.** No third-party Go modules, so no transitive dependency supply chain.
  Release binaries are built with `CGO_ENABLED=0 -trimpath`, and their checksums file is signed
  with Sigstore cosign ([docs/releasing.md](docs/releasing.md#verifying-a-release)).
