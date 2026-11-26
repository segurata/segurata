#!/usr/bin/env bash
# Installs the leak gate (check-public.sh --pre-push) as this clone's pre-push hook without taking
# any hook away. Git runs one hooks directory: core.hooksPath when set (often a global one shared by
# every repository), else .git/hooks. Writing the gate there would replace the pre-push hook already
# in it and, for a global directory, gate every other repository with a script they lack. So the
# gate gets a directory of this clone's own, .git/hooks-segurata, set as core.hooksPath in this
# clone's config only: it links every other hook of the directory git used before, and its pre-push
# runs the gate of the checkout this script is in, then that directory's pre-push with the same
# input. Running it again refreshes the links (a hook added to the previous directory since needs
# that).
#
# Usage: scripts/install-hooks.sh [--identifiers FILE] [--skip-authors]
#   --identifiers FILE   passed to the gate; default as check-public.sh's
#   --skip-authors       passed to the gate: for a private remote (see check-public.sh)
set -euo pipefail

usage() { sed -n '/^# Usage:/,/^set /p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2; exit 2; }

gate_args=(--require-identifiers)
while [ $# -gt 0 ]; do
  case "$1" in
    --identifiers) [ $# -ge 2 ] || usage; gate_args+=(--identifiers "$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"); shift 2 ;;
    --skip-authors) gate_args+=(--skip-authors); shift ;;
    *) usage ;;
  esac
done

repo="$(git rev-parse --show-toplevel)"
here="$(cd "$(dirname "$0")" && pwd)"
# The common directory: core.hooksPath in the clone's config holds for all its worktrees.
gitdir="$(cd "$(git rev-parse --git-common-dir)" && pwd)"
dir="$gitdir/hooks-segurata"
# The directory git ran hooks from before: recorded on the first install, as core.hooksPath points
# here afterwards.
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
