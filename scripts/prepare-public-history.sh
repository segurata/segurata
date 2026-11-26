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
#   --source URL|PATH      repository to copy; default: this local repository
#   --branch NAME          the branch to publish; default: main
#   --identifiers FILE     default: $SEGURATA_PUBLIC_GATE, else ~/.config/segurata/public-gate.txt
#   --drop-path-glob GLOB  remove matching files from every commit, e.g. '*.pyc'; repeatable
#   --mailmap FILE         rewrite author, committer and tagger names and emails (git-filter-repo
#                          --mailmap)
#   --allow-author ID      accept an exact public identity "Name <email>" in Git headers.
#                          May be repeated. File, ref and message text still gets scanned.
#   --keep-authors         publish the authors, committers and taggers as they are; without this or
#                          --mailmap the authors gate fails. The report lists them either way
#   --workdir DIR          where to build; must not exist yet; default: a new temporary folder
#
# Exit status: 0 every gate passed, 1 a gate failed (the result stays for inspection), 2 usage or
# tool error.
set -euo pipefail
umask 077

usage() { sed -n '/^# Usage:/,/^# tool error/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
die() { echo "prepare-public-history: $*" >&2; exit 2; }
absolute_file() { printf '%s/%s\n' "$(cd "$(dirname "$1")" && pwd -P)" "$(basename "$1")"; }

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd -P)"
source=""
branch=main
identifiers="${SEGURATA_PUBLIC_GATE:-$HOME/.config/segurata/public-gate.txt}"
mailmap=""
keep_authors=false
workdir=""
drop=()
allow_authors=()
self=("$0" "$@")
while [ $# -gt 0 ]; do
  if [ "$1" = --keep-authors ]; then keep_authors=true; shift; continue; fi
  [ $# -ge 2 ] || usage
  case "$1" in
    --source) source="$2" ;;
    --branch) branch="$2" ;;
    --identifiers) identifiers="$2" ;;
    --drop-path-glob) drop+=(--path-glob "$2") ;;
    --mailmap) mailmap="$2" ;;
    --allow-author) allow_authors+=(--allow-author "$2") ;;
    --workdir) workdir="$2" ;;
    *) usage ;;
  esac
  shift 2
done

if [ -n "$mailmap" ] && $keep_authors; then die "--mailmap and --keep-authors exclude each other"; fi
for tool in git-filter-repo gitleaks python3; do
  command -v "$tool" >/dev/null || die "$tool is not on PATH"
done
[ -n "$source" ] || source="$repo"
case "$source" in
  http://*|https://*)
    authority="${source#*://}"
    case "${authority%%/*}" in *@*) die "use a credential helper instead of credentials in the source URL" ;; esac
    ;;
esac
[ -f "$identifiers" ] || die "no identifiers file at $identifiers (--identifiers or SEGURATA_PUBLIC_GATE)"
python3 "$here/identifiers.py" check "$identifiers" "$repo" || exit 2
if [ -d "$source" ]; then python3 "$here/identifiers.py" check "$identifiers" "$source" || exit 2; fi
# From here on everything printed goes through the mask: this script runs again under it.
if [ -z "${SEGURATA_GATE_MASKED:-}" ]; then
  SEGURATA_GATE_MASKED=1 exec python3 "$here/identifiers.py" run-masked "$identifiers" "$BASH" "${self[@]}"
fi
[ -z "$mailmap" ] || [ -f "$mailmap" ] || die "no mailmap at $mailmap"
identifiers="$(absolute_file "$identifiers")"
if [ -n "$mailmap" ]; then mailmap="$(absolute_file "$mailmap")"; fi
if [ -n "$workdir" ]; then
  [ ! -e "$workdir" ] || die "$workdir already exists; pick a new folder"
  mkdir -p "$(dirname "$workdir")"
  mkdir "$workdir"
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
git clone --quiet --bare --no-local --single-branch --branch "$branch" -- "$source" "$public"
branch_ref="refs/heads/$branch"
before_commits="$(git -C "$public" rev-list --count "$branch_ref")"
before_tree="$(git -C "$public" rev-parse "$branch_ref^{tree}")"

echo "== rewriting history"
filter=(--replace-text "$secret_dir/expressions" --replace-message "$secret_dir/expressions"
  --replace-refs delete-no-add --quiet)
if [ ${#drop[@]} -gt 0 ]; then filter+=("${drop[@]}" --invert-paths); fi
if [ -n "$mailmap" ]; then filter+=(--mailmap "$mailmap"); fi
# filter-repo removes origin, expires reflogs and repacks the rewritten objects.
(cd "$public" && git filter-repo "${filter[@]}")

after_commits="$(git -C "$public" rev-list --count "$branch_ref")"
after_tree="$(git -C "$public" rev-parse "$branch_ref^{tree}")"
status=0
fail() { status=1; echo "FAIL: $*"; }

gates() {
  echo "segurata public history report, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "branch: $branch"
  echo "result: $public"
  echo "commits: $before_commits before, $after_commits after"
  echo "tags: $(git -C "$public" tag | wc -l | tr -d ' ')"
  echo

  echo "== refs"
  unexpected="$(git -C "$public" for-each-ref --format='%(refname)' |
    grep -v -x -e "$branch_ref" -e 'refs/tags/.*' || true)"
  if [ -n "$unexpected" ]; then fail "refs other than $branch_ref and tags:"; echo "$unexpected"; else echo "ok"; fi
  if [ -n "$(git -C "$public" remote)" ]; then fail "a remote is configured"; fi

  echo "== authors"
  { git -C "$public" log --all --format='%an <%ae>%n%cn <%ce>'
    git -C "$public" for-each-ref refs/tags --format='%(if)%(taggername)%(then)%(taggername) %(taggeremail)%(end)'
  } | sed '/^$/d' | sort -u
  if [ -n "$mailmap" ]; then echo "ok: rewritten with --mailmap"
  elif $keep_authors; then echo "ok: published as listed (--keep-authors)"
  else fail "authors unchanged: rewrite them with --mailmap FILE, or publish them as listed with --keep-authors"
  fi

  echo "== branch tip"
  # The published tip must be the code that was tested: fix identifiers on the branch first
  # (scripts/check-public.sh), and only history gets rewritten here.
  if [ "$before_tree" = "$after_tree" ]; then echo "ok: tree $after_tree unchanged"; else
    fail "the tip's files changed ($before_tree -> $after_tree); clean the branch itself first"
  fi

  echo "== leak gate"
  (cd "$public" && "$here/check-public.sh" --history --require-identifiers --identifiers "$identifiers" ${allow_authors[@]+"${allow_authors[@]}"}) ||
    fail "history did not pass the leak gate"

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
