#!/usr/bin/env bash
# Installs the leak gate (check-public.sh --pre-push) as this clone's pre-push hook without taking
# any hook away: .git/hooks-segurata becomes this clone's core.hooksPath, links every hook of the
# directory git used before (which may be a global one), and chains the gate to its pre-push.
# Writing the gate into that directory would replace its pre-push and, for a global one, gate every
# other repository with a script they lack. Run it again to pick up hooks added there since.
#
# Usage: scripts/install-hooks.sh [--identifiers FILE] [--allow-author ID]... [--skip-authors]
#   --identifiers FILE   passed to the gate; default as check-public.sh's
#   --allow-author ID    passed to the gate: exact approved public Git identity (repeatable)
#   --skip-authors       passed to the gate: for a private remote (see check-public.sh)
set -euo pipefail

usage() { sed -n '/^# Usage:/,/^set /p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2; exit 2; }

gate_args=(--require-identifiers)
skip_authors=false
allow_authors=false
while [ $# -gt 0 ]; do
  case "$1" in
    --identifiers) [ $# -ge 2 ] || usage; gate_args+=(--identifiers "$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"); shift 2 ;;
    --skip-authors) skip_authors=true; gate_args+=(--skip-authors); shift ;;
    --allow-author) [ $# -ge 2 ] || usage; allow_authors=true; gate_args+=(--allow-author "$2"); shift 2 ;;
    *) usage ;;
  esac
done
if $skip_authors && $allow_authors; then usage; fi

repo="$(git rev-parse --show-toplevel)"
here="$(cd "$(dirname "$0")" && pwd)"
# The common directory: the clone's core.hooksPath holds for all its worktrees.
gitdir="$(cd "$(git rev-parse --git-common-dir)" && pwd)"
dir="$gitdir/hooks-segurata"
# Recorded on the first install: afterwards core.hooksPath points here.
prev="$(git config --local --get segurata.previousHooks || true)"
if [ -z "$prev" ]; then
  prev="$(cd "$repo" && git rev-parse --git-path hooks)"
  case "$prev" in /*) ;; *) prev="$repo/$prev" ;; esac
  [ "$prev" != "$dir" ] || { echo "install-hooks: core.hooksPath is $dir but segurata.previousHooks is unset" >&2; exit 2; }
  git config --local segurata.previousHooks "$prev"
fi

rm -rf "$dir"
mkdir -p "$dir"
for hook in "$prev"/*; do
  name="$(basename "$hook")"
  case "$name" in pre-push | *.sample) continue ;; esac
  if [ -f "$hook" ] && [ -x "$hook" ]; then ln -s "$hook" "$dir/$name"; fi
done

quoted() { printf '%q ' "$@"; }
cat >"$dir/pre-push" <<EOF
#!/usr/bin/env bash
# Written by scripts/install-hooks.sh: the leak gate, then the pre-push hook of $prev.
set -euo pipefail
input="\$(cat)"
printf '%s\n' "\$input" | $(quoted "$here/check-public.sh" "${gate_args[@]}") --pre-push "\$@"
if [ -x $(quoted "$prev/pre-push") ]; then
  printf '%s\n' "\$input" | exec $(quoted "$prev/pre-push")"\$@"
fi
EOF
chmod +x "$dir/pre-push"
git config --local core.hooksPath "$dir"
echo "install-hooks: pre-push gate installed in $dir, chained to $prev"
