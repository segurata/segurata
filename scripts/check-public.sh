#!/usr/bin/env bash
# Leak gate for what this repository publishes: gitleaks over the tracked files of the working tree,
# and the owner's private identifiers (client names, internal hosts, project ids...) over their
# content and paths. The identifiers file lives outside the repository, because it would leak what
# it lists; its format is in scripts/identifiers.py. Reports name locations only, never a secret
# value or an identifier. CI runs it without identifiers; locally it runs as a pre-push hook
# (CONTRIBUTING.md).
#
# Usage: scripts/check-public.sh [--identifiers FILE] [--require-identifiers] [--history]
#   --identifiers FILE     default: $SEGURATA_PUBLIC_GATE, else ~/.config/segurata/public-gate.txt
#   --require-identifiers  fail when the identifiers file is missing, instead of warning
#   --history              also scan every commit reachable from any ref
#
# Exit status: 0 clean, 1 something found, 2 usage or tool error.
set -euo pipefail

usage() { sed -n '/^# Usage:/,/^# Exit/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

identifiers="${SEGURATA_PUBLIC_GATE:-$HOME/.config/segurata/public-gate.txt}"
require_identifiers=false
history=false
while [ $# -gt 0 ]; do
  case "$1" in
    --identifiers) [ $# -ge 2 ] || usage; identifiers="$2"; shift 2 ;;
    --require-identifiers) require_identifiers=true; shift ;;
    --history) history=true; shift ;;
    *) usage ;;
  esac
done

repo="$(git rev-parse --show-toplevel)"
here="$(cd "$(dirname "$0")" && pwd)"
command -v gitleaks >/dev/null || { echo "check-public: gitleaks is not on PATH" >&2; exit 2; }
if [ -f "$identifiers" ]; then
  python3 "$here/identifiers.py" check "$identifiers" "$repo" || exit 2
elif $require_identifiers; then
  echo "check-public: no identifiers file at $identifiers (--identifiers or SEGURATA_PUBLIC_GATE)" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
status=0
# Runs a scanner: exit 1 marks the gate failed and goes on; any other failure stops it.
scan() { local rc=0; "$@" || rc=$?; case $rc in 0) ;; 1) status=1 ;; *) exit 2 ;; esac; }

# The tracked files as they are in the working tree, without ignored output (out/, dist/).
(cd "$repo" && git ls-files -z | while IFS= read -r -d '' f; do
  if [ -e "$f" ] || [ -L "$f" ]; then printf '%s\0' "$f"; fi
done) >"$tmp/files"
mkdir "$tmp/tree"
(cd "$repo" && tar --null -T "$tmp/files" -cf -) | (cd "$tmp/tree" && tar -xf -)

echo "== gitleaks: tracked files"
scan gitleaks dir --no-banner --no-color --redact --log-level warn -c "$repo/.gitleaks.toml" "$tmp/tree"

if $history; then
  echo "== gitleaks: history ($(git -C "$repo" rev-list --all | wc -l | tr -d ' ') commits)"
  scan gitleaks git --no-banner --no-color --redact --log-level warn --log-opts=--all -c "$repo/.gitleaks.toml" "$repo"
fi

if [ -f "$identifiers" ]; then
  echo "== private identifiers: tracked files"
  scan python3 "$here/identifiers.py" scan-tree "$repo" "$identifiers"
  if $history; then
    echo "== private identifiers: history"
    scan python3 "$here/identifiers.py" scan-history "$repo" "$identifiers"
  fi
else
  echo "== private identifiers: skipped, no file at $identifiers"
fi

if [ "$status" -eq 0 ]; then echo "check-public: clean"; else echo "check-public: FAILED" >&2; fi
exit "$status"
