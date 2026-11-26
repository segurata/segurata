---
name: segurata-remediate
description: Preview, apply, and verify a specific Segurata remediation, credential rotation, or trail redaction. Use after identifying the finding, rotation item, or file scope.
---

# Preview and apply a Segurata fix

1. Locate the target in the latest relevant inventory or tracker. Use `segurata remediate --list` for automatable finding IDs and `segurata rotations show <id>` for one rotation item.
2. Preview the exact action without `--apply`. Use `segurata remediate <finding-id>` for an automatable finding. For trail redaction, `segurata redact --path "<exact file>"` restricts the plan to one file. Add `--item <rotation-id>` to restrict it to one credential. On its own, `--item` searches all configured trails. The preview still scans the configured trail roots and requires `rg`, the existing fingerprint key and the Unix open-file check. On Windows, report that this preview is unavailable.
3. Check the affected scope, write credentials, side effects and any backup or undo instructions. Confirm that the user authorized the action and scope before adding `--apply`. If the command recalculates the plan on apply, compare the current plan at the interactive prompt. Use `--yes` only when the authorized action and scope are fixed. If the current scope cannot be checked, stop at preview.
4. Check the post-apply result. A skipped or failed follow-up run leaves the fix unverified. For changes Segurata cannot check automatically, run the relevant connector inventory and report which scope it verified.

## Read when needed

- For provider writes, grouped plans and rechecks, read [remediation](../../../docs/architecture.md#remediation).
- For credential rotation, read [the rotation ledger](../../../docs/architecture.md#rotation-ledger) and the [secret handling guide](../../../docs/secrets.md). Check platform support before offering `rotations replace`. The user enters the new value locally. Keep it out of chat, arguments, environment assignments and tool logs. A replacement preview reads the new value and records a tracker note.
- For backups and trail edits, read [redaction](../../../docs/architecture.md#redaction). Old backups can contain plaintext.
- For a deliberate exception or a tracker change, read [accepted risks](../../../docs/architecture.md#accepted-risks) or [tracker and status](../../../docs/user-guide.md#tracker-and-status). Apply these only if the user requests the corresponding disposition.
