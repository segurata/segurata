---
name: segurata-audit
description: Get started with Segurata, check prerequisites, inventory a selected connector, and interpret the local tracker or reports. Use segurata-remediate to plan or apply a fix.
---

# Audit with Segurata

## First run

1. Run `segurata version` to identify the binary. If working from a clone, follow the [installation instructions](../../../README.md#install).
2. For results already on disk, start with `segurata report --format text`. If there is no inventory, say that the scope has yet to be inspected. Use `segurata status` for the tracker briefing or `segurata track show <item-id>` for one item. Commands that discover connectors, including `status`, can run the `describe` command of plugins on `PATH`. Use trusted plugins. Leave `--write` and `--mark-seen` off when the user wants only to see the tracker.
3. For a fresh check, select the connector or instance that covers the user's request. Use `segurata connectors` to discover selectors and `segurata doctor --connector <selector>` to check prerequisites.
4. Run `segurata inventory <selector>`, then `segurata status`. An inventory contacts the providers its connector uses and writes local results and tracker updates. With no selector, the CLI runs every connector. For a credential-free first scan, use `browser-extensions` with a Brave or Chrome profile in a standard location.

Treat skipped or failed scopes as uninspected. Summarize findings with IDs, priorities and next actions. State what the run covered and keep credentials and full inventory records out of chat.

## Read when needed

Use the corresponding command's `--help` for flag syntax if the source documentation is unavailable.

- For connector selection, see [inventory](../../../docs/inventory.md). For sign-in or data sent off the machine, see the [user guide](../../../docs/user-guide.md). To install on Windows without Go, see [release binaries](../../../docs/releasing.md#release-binaries).
- Before running `local-secrets`, read [its configuration and liveness options](../../../docs/inventory.md#plaintext-secrets-on-disk-local-secrets). Check which network checks the selected instance has enabled. Run those checks only for accounts or machines the user controls and has authorized for this run. Keep credential checks disabled if ownership is unknown.
- For incomplete inventories, read [run completeness](../../../docs/architecture.md#run-completeness).
- For report formats and output paths, read [reports](../../../docs/user-guide.md#report).
- For a plan or a change, use [segurata-remediate](../segurata-remediate/SKILL.md).
