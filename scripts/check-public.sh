#!/usr/bin/env bash
# Leak gate for what this repository publishes: gitleaks and the owner's private identifiers (client
# names, internal hosts, project ids...) over the content and paths of what is about to go out. By
# default that is the tracked files of the working tree only, not the commits; --history adds every
# commit, and --pre-push checks exactly the commits a push sends. The identifiers file lives outside
# the repository, because it would leak what it lists; its format is in scripts/identifiers.py.
# Reports name locations only, never a secret value or an identifier: with an identifiers file,
# every line this script and its tools print goes through identifiers.py's mask. CI runs it without
# identifiers; locally it runs as a pre-push hook (CONTRIBUTING.md).
#
# Usage: scripts/check-public.sh [--identifiers FILE] [--require-identifiers] [--history|--pre-push]
#   --identifiers FILE     default: $SEGURATA_PUBLIC_GATE, else ~/.config/segurata/public-gate.txt
#   --require-identifiers  fail when the identifiers file is missing, instead of warning
#   --history              also scan every commit reachable from any ref
#   --pre-push             as a pre-push hook: scan only what the push sends, read from stdin
#                          ("<local ref> <local sha> <remote ref> <remote sha>" per ref): the
#                          commits the remote ref lacks (for a new ref, those in no remote-tracking
#                          ref), every file version they add, and the remote ref names. Deletions
#                          send nothing. The working tree is not scanned.
#
# Exit status: 0 clean, 1 something found, 2 usage or tool error.
set -euo pipefail

usage() { sed -n '/^# Usage:/,/^# Exit/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

identifiers="${SEGURATA_PUBLIC_GATE:-$HOME/.config/segurata/public-gate.txt}"
require_identifiers=false
history=false
pre_push=false
self=("$0" "$@")
while [ $# -gt 0 ]; do
  case "$1" in
    --identifiers) [ $# -ge 2 ] || usage; identifiers="$2"; shift 2 ;;
    --require-identifiers) require_identifiers=true; shift ;;
    --history) history=true; shift ;;
    --pre-push) pre_push=true; shift ;;
    *) usage ;;
  esac
done
if $history && $pre_push; then usage; fi

repo="$(git rev-parse --show-toplevel)"
here="$(cd "$(dirname "$0")" && pwd)"
command -v gitleaks >/dev/null || { echo "check-public: gitleaks is not on PATH" >&2; exit 2; }
if [ -f "$identifiers" ]; then
  python3 "$here/identifiers.py" check "$identifiers" "$repo" || exit 2
  # From here on everything printed goes through the mask: this script runs again under it.
  if [ -z "${SEGURATA_GATE_MASKED:-}" ]; then
    SEGURATA_GATE_MASKED=1 exec python3 "$here/identifiers.py" run-masked "$identifiers" "$BASH" "${self[@]}"
  fi
elif $require_identifiers; then
  echo "check-public: no identifiers file at $identifiers (--identifiers or SEGURATA_PUBLIC_GATE)" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
status=0
# Runs a scanner: exit 1 marks the gate failed and goes on; any other failure stops it.
scan() { local rc=0; "$@" || rc=$?; case $rc in 0) ;; 1) status=1 ;; *) exit 2 ;; esac; }

gitleaks_flags=(--no-banner --no-color --redact --log-level warn -c "$repo/.gitleaks.toml")

if $pre_push; then
  cat >"$tmp/push"
  revs="$(python3 "$here/identifiers.py" push-revs "$repo" <"$tmp/push")" || exit 2
  # Object ids and git options only, so splitting on spaces is safe.
  read -r -a rev_args <<<"$revs"
  if [ -n "$revs" ]; then
    echo "== gitleaks: pushed commits ($(git -C "$repo" rev-list --count "${rev_args[@]}"))"
    scan gitleaks git "${gitleaks_flags[@]}" --log-opts="$revs" "$repo"
  else
    echo "== gitleaks: nothing pushed but deletions"
  fi
else
  # The tracked files as they are in the working tree, without ignored output (out/, dist/).
  (cd "$repo" && git ls-files -z | while IFS= read -r -d '' f; do
    if [ -e "$f" ] || [ -L "$f" ]; then printf '%s\0' "$f"; fi
  done) >"$tmp/files"
  mkdir "$tmp/tree"
  (cd "$repo" && tar --null -T "$tmp/files" -cf -) | (cd "$tmp/tree" && tar -xf -)
  echo "== gitleaks: tracked files"
  scan gitleaks dir "${gitleaks_flags[@]}" "$tmp/tree"
fi

if $history; then
  echo "== gitleaks: history ($(git -C "$repo" rev-list --all | wc -l | tr -d ' ') commits)"
  scan gitleaks git "${gitleaks_flags[@]}" --log-opts=--all "$repo"
fi

if [ -f "$identifiers" ] && $pre_push; then
  echo "== private identifiers: pushed commits and ref names"
  scan python3 "$here/identifiers.py" scan-push "$repo" "$identifiers" <"$tmp/push"
elif [ -f "$identifiers" ]; then
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
