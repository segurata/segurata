#!/usr/bin/env bash
# Leak gate for what this repository publishes: gitleaks and the owner's private identifiers (client
# names, internal hosts, project ids...) over the content and paths of what is about to go out. By
# default that is the tracked files of the working tree only, not the commits; --history adds every
# commit, and --pre-push (as git's hook) or --unpushed (by hand) checks the history a push may
# publish. The identifiers file lives outside the repository, because it would leak what it lists; its
# format is in scripts/identifiers.py.
# Gitleaks reports counts. Identifier hits name masked locations. With an identifiers file,
# diagnostic output also goes through identifiers.py's mask. CI runs without
# identifiers; locally it runs as a pre-push hook (scripts/install-hooks.sh).
#
# Usage: scripts/check-public.sh [--identifiers FILE] [--require-identifiers] [--skip-authors]
#                                [--history | --unpushed | --pre-push REMOTE URL]
#   --identifiers FILE     default: $SEGURATA_PUBLIC_GATE, else ~/.config/segurata/public-gate.txt
#   --require-identifiers  fail when the identifiers file is missing, instead of warning
#   --allow-author ID      allow an exact public Git identity "Name <email>" in author,
#                          committer and tagger headers only. May be repeated.
#   --skip-authors         with --unpushed or --pre-push, leave commits' author and committer
#                          lines out of the identifiers scan (messages are still scanned): for a
#                          private remote, where the owner's name is expected until
#                          prepare-public-history.sh decides the authors of the public history
#   --history              also scan every commit reachable from any ref; works on bare clones
#   --pre-push REMOTE URL  as git's pre-push hook, which passes the remote and its URL: scan only
#                          what the push sends, read from stdin ("<local ref> <local sha> <remote
#                          ref> <remote sha>" per ref): the pushed tips, excluding only known tips
#                          Git reports at that destination. The destination ref names are scanned.
#                          Deletions send nothing. The working tree is not
#                          scanned. Run by hand, stdin is not a push, so it refuses to run
#                          without the two arguments git gives it.
#   --unpushed             approximate the same check against the local tracking ref.
#
# Exit status: 0 clean, 1 something found, 2 usage or tool error.
set -euo pipefail
umask 077

usage() { sed -n '/^# Usage:/,/^# Exit/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

identifiers="${SEGURATA_PUBLIC_GATE:-$HOME/.config/segurata/public-gate.txt}"
require_identifiers=false
history=false
pre_push=false
unpushed=false
skip_authors=()
allow_authors=()
self=("$0" "$@")
while [ $# -gt 0 ]; do
  case "$1" in
    --identifiers) [ $# -ge 2 ] || usage; identifiers="$2"; shift 2 ;;
    --require-identifiers) require_identifiers=true; shift ;;
    --allow-author) [ $# -ge 2 ] || usage; allow_authors+=(--allow-author "$2"); shift 2 ;;
    --history) history=true; shift ;;
    --pre-push) pre_push=true; shift; break ;;
    --unpushed) unpushed=true; shift ;;
    --skip-authors) skip_authors=(--skip-authors); shift ;;
    *) usage ;;
  esac
done
# --pre-push comes last: git appends the remote and its URL to the hook's command.
if $pre_push && [ $# -ne 2 ]; then
  echo "check-public: --pre-push runs as git's pre-push hook, which passes the remote and its URL; by hand, use --unpushed" >&2
  exit 2
fi
[ $# -eq 0 ] || $pre_push || usage
if [ ${#skip_authors[@]} -gt 0 ] && ! $pre_push && ! $unpushed; then usage; fi
if [ ${#allow_authors[@]} -gt 0 ]; then
  [ ${#skip_authors[@]} -eq 0 ] || usage
  $history || $pre_push || $unpushed || usage
  require_identifiers=true
fi
modes=0
for m in $history $pre_push $unpushed; do if $m; then modes=$((modes + 1)); fi; done
[ "$modes" -le 1 ] || usage

bare="$(git rev-parse --is-bare-repository)"
if [ "$bare" = true ]; then
  $history || usage
  repo="$(git rev-parse --absolute-git-dir)"
else
  repo="$(git rev-parse --show-toplevel)"
fi
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

config="$tmp/gitleaks.toml"
if [ "$bare" = true ]; then
  git -C "$repo" show HEAD:.gitleaks.toml >"$config" 2>/dev/null ||
    printf '[extend]\nuseDefault = true\n' >"$config"
else
  config="$repo/.gitleaks.toml"
fi
gitleaks_flags=(--no-banner --no-color --redact --ignore-gitleaks-allow --log-level warn -c "$config")

scan_git() {
  local oid kind record
  scan gitleaks git "${gitleaks_flags[@]}" \
    --log-opts="--no-textconv --no-ext-diff --no-show-signature --diff-merges=separate $*" "$repo"
  mkdir "$tmp/metadata"
  # Give the detector each commit's prose separately. Git's generated object IDs are not
  # credentials, and a keyword in one message should not make it flag a hash in another.
  git -C "$repo" log --no-patch --no-show-signature -z --format='%H%n%an%n%ae%n%cn%n%ce%n%B' "$@" |
    while IFS= read -r -d '' record; do
      oid="${record%%$'\n'*}"
      printf '%s\n' "${record#*$'\n'}" >"$tmp/metadata/commit-$oid.txt"
    done
  git -C "$repo" rev-list --objects --no-object-names "$@" |
    git -C "$repo" cat-file --batch-check='%(objectname) %(objecttype)' |
    while read -r oid kind; do
      if [ "$kind" = tag ]; then
        git -C "$repo" cat-file tag "$oid" | sed '1{/^object /d;}' >"$tmp/metadata/tag-$oid.txt"
      fi
    done
  echo "== gitleaks: Git metadata"
  scan gitleaks dir "${gitleaks_flags[@]}" "$tmp/metadata"
}

if $unpushed; then
  # The line git would give the hook for `git push` of the current branch.
  branch="$(git -C "$repo" symbolic-ref -q HEAD)" || { echo "check-public: --unpushed needs a branch checked out" >&2; exit 2; }
  remote_ref="$(git -C "$repo" for-each-ref --format='%(push:remoteref)' "$branch")"
  remote_sha="$(git -C "$repo" rev-parse -q --verify "${branch#refs/heads/}@{push}" 2>/dev/null)" || remote_sha="$(printf '0%.0s' {1..40})"
  printf '%s %s %s %s\n' "$branch" "$(git -C "$repo" rev-parse HEAD)" "${remote_ref:-$branch}" "$remote_sha" >"$tmp/push"
  pre_push=true
elif $pre_push; then
  cat >"$tmp/push"
fi
if $pre_push; then
  revs="$(python3 "$here/identifiers.py" push-revs "$repo" <"$tmp/push")" || exit 2
  # Object ids and git options only, so splitting on spaces is safe.
  read -r -a rev_args <<<"$revs"
  if [ -n "$revs" ]; then
    echo "== gitleaks: pushed commits ($(git -C "$repo" rev-list --count "${rev_args[@]}"))"
    scan_git "${rev_args[@]}"
  else
    echo "== gitleaks: no commits to push (up to date, or only deletions)"
  fi
elif [ "$bare" = false ]; then
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
  scan_git --all
fi

if [ -f "$identifiers" ] && $pre_push; then
  echo "== private identifiers: pushed commits and ref names"
  scan python3 "$here/identifiers.py" scan-push "$repo" "$identifiers" ${skip_authors[@]+"${skip_authors[@]}"} ${allow_authors[@]+"${allow_authors[@]}"} <"$tmp/push"
elif [ -f "$identifiers" ]; then
  if [ "$bare" = false ]; then
    echo "== private identifiers: tracked files"
    scan python3 "$here/identifiers.py" scan-tree "$repo" "$identifiers"
  fi
  if $history; then
    echo "== private identifiers: history"
    scan python3 "$here/identifiers.py" scan-history "$repo" "$identifiers" ${allow_authors[@]+"${allow_authors[@]}"}
  fi
else
  echo "== private identifiers: skipped, no file at $identifiers"
fi

if [ "$status" -eq 0 ]; then echo "check-public: clean"; else echo "check-public: FAILED" >&2; fi
exit "$status"
