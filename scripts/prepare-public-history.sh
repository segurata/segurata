#!/usr/bin/env bash
# Builds the history to publish, in a fresh bare clone in a new folder: one branch and the tags in
# its history, rewritten with git filter-repo so the owner's private identifiers (scripts/identifiers.py
# describes the file) are replaced in file contents and commit and tag messages. Then it gates the
# result (identifiers, gitleaks, the branch tip unchanged, only that branch and tags) and writes a
# report. Everything it prints, the report included, goes through identifiers.py's mask, so no
# identifier is ever shown. The source repository is only cloned from, never changed. This script
# never pushes: what the owner runs afterwards is in docs/releasing.md, "Going public".
#
# Usage: scripts/prepare-public-history.sh [options]
#   --source URL|PATH      repository to copy; default: this repository's origin
#   --branch NAME          the branch to publish; default: main
#   --identifiers FILE     default: $SEGURATA_PUBLIC_GATE, else ~/.config/segurata/public-gate.txt
#   --drop-path-glob GLOB  remove matching files from every commit, e.g. '*.pyc'; repeatable
#   --mailmap FILE         rewrite author and committer names and emails (git-filter-repo --mailmap)
#   --workdir DIR          where to build; must not exist yet; default: a new temporary folder
#
# Exit status: 0 every gate passed, 1 a gate failed (the result stays for inspection), 2 usage or
# tool error.
set -euo pipefail

usage() { sed -n '/^# Usage:/,/^# tool error/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
die() { echo "prepare-public-history: $*" >&2; exit 2; }

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
source=""
branch=main
identifiers="${SEGURATA_PUBLIC_GATE:-$HOME/.config/segurata/public-gate.txt}"
mailmap=""
workdir=""
drop=()
self=("$0" "$@")
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --source) source="$2" ;;
    --branch) branch="$2" ;;
    --identifiers) identifiers="$2" ;;
    --drop-path-glob) drop+=(--path-glob "$2") ;;
    --mailmap) mailmap="$2" ;;
    --workdir) workdir="$2" ;;
    *) usage ;;
  esac
  shift 2
done

for tool in git-filter-repo gitleaks python3; do
  command -v "$tool" >/dev/null || die "$tool is not on PATH"
done
[ -n "$source" ] || source="$(git -C "$repo" remote get-url origin)" || die "no origin; pass --source"
[ -f "$identifiers" ] || die "no identifiers file at $identifiers (--identifiers or SEGURATA_PUBLIC_GATE)"
python3 "$here/identifiers.py" check "$identifiers" "$repo" || exit 2
if [ -d "$source" ]; then python3 "$here/identifiers.py" check "$identifiers" "$source" || exit 2; fi
# From here on everything printed goes through the mask: this script runs again under it.
if [ -z "${SEGURATA_GATE_MASKED:-}" ]; then
  SEGURATA_GATE_MASKED=1 exec python3 "$here/identifiers.py" run-masked "$identifiers" "$BASH" "${self[@]}"
fi
[ -z "$mailmap" ] || [ -f "$mailmap" ] || die "no mailmap at $mailmap"
if [ -n "$workdir" ]; then
  [ ! -e "$workdir" ] || die "$workdir already exists; pick a new folder"
  mkdir -p "$workdir"
else
  workdir="$(mktemp -d "${TMPDIR:-/tmp}/segurata-public.XXXXXX")"
fi
workdir="$(cd "$workdir" && pwd -P)"
public="$workdir/public.git"
report="$workdir/report.txt"

# The expressions name the identifiers: private, outside the work folder, deleted on exit.
secret_dir="$(mktemp -d)"
trap 'rm -rf "$secret_dir"' EXIT
python3 "$here/identifiers.py" replace-file "$identifiers" "$secret_dir/expressions"

echo "== cloning $branch into $public"
git clone --quiet --bare --single-branch --branch "$branch" "$source" "$public"
# No remote at all from here on: nothing in this folder can push by accident.
git -C "$public" remote remove origin
before_commits="$(git -C "$public" rev-list --count "$branch")"
before_tree="$(git -C "$public" rev-parse "$branch^{tree}")"

echo "== rewriting history"
filter=(--replace-text "$secret_dir/expressions" --replace-message "$secret_dir/expressions"
  --replace-refs delete-no-add --quiet)
if [ ${#drop[@]} -gt 0 ]; then filter+=("${drop[@]}" --invert-paths); fi
if [ -n "$mailmap" ]; then filter+=(--mailmap "$mailmap"); fi
# filter-repo also expires the reflogs and repacks, so the old objects are gone.
(cd "$public" && git filter-repo "${filter[@]}")

after_commits="$(git -C "$public" rev-list --count "$branch")"
after_tree="$(git -C "$public" rev-parse "$branch^{tree}")"
status=0
fail() { status=1; echo "FAIL: $*"; }

gates() {
  echo "segurata public history report, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "source: $source"
  echo "branch: $branch"
  echo "result: $public"
  echo "commits: $before_commits before, $after_commits after"
  echo "tags: $(git -C "$public" tag | wc -l | tr -d ' ')"
  echo

  echo "== refs"
  unexpected="$(git -C "$public" for-each-ref --format='%(refname)' |
    grep -v -x -e "refs/heads/$branch" -e 'refs/tags/.*' || true)"
  if [ -n "$unexpected" ]; then fail "refs other than refs/heads/$branch and tags:"; echo "$unexpected"; else echo "ok"; fi
  if [ -n "$(git -C "$public" remote)" ]; then fail "a remote is configured"; fi

  echo "== branch tip"
  # The published tip must be the code that was tested: fix identifiers on the branch first
  # (scripts/check-public.sh), and only history gets rewritten here.
  if [ "$before_tree" = "$after_tree" ]; then echo "ok: tree $after_tree unchanged"; else
    fail "the tip's files changed ($before_tree -> $after_tree); clean the branch itself first"
  fi

  echo "== private identifiers"
  local rc=0 hits
  hits="$(python3 "$here/identifiers.py" scan-history "$public" "$identifiers")" || rc=$?
  case $rc in
    0) echo "ok: none" ;;
    1) fail "identifiers left (filter-repo does not rewrite file names or authors: use --drop-path-glob or --mailmap)"
       echo "$hits" ;;
    *) fail "the identifier scan did not run" ;;
  esac

  echo "== gitleaks"
  config="$secret_dir/gitleaks.toml"
  # The rules of the published tip; gitleaks' defaults when it has none (an empty file has no rules).
  git -C "$public" show "$branch:.gitleaks.toml" >"$config" 2>/dev/null ||
    printf '[extend]\nuseDefault = true\n' >"$config"
  if gitleaks git --no-banner --no-color --redact --log-level warn --log-opts=--all -c "$config" "$public"; then
    echo "ok: no leaks"
  else
    fail "gitleaks found leaks; rerun it on $public with --verbose (values redacted) to see where"
  fi

  echo
  if [ "$status" -eq 0 ]; then
    echo "ALL GATES PASSED. Nothing was pushed. Next: docs/releasing.md, \"Going public\"."
  else
    echo "GATES FAILED. Nothing was pushed. Fix the source or the identifiers file and run again."
  fi
}

gates >"$secret_dir/report" 2>&1
python3 "$here/identifiers.py" mask "$identifiers" <"$secret_dir/report" >"$report"
cat "$report"
exit "$status"
