#!/usr/bin/env python3
"""Private identifiers gate, shared by check-public.sh and prepare-public-history.sh.

The identifiers file lives outside the repository (it would leak what it lists). Format, one entry
per line; blank lines and lines starting with # are ignored:

    acme-internal-project
    Jane Client==>a client

The text before "==>" is the identifier, matched as a literal, case-insensitively (ASCII case).
The text after it is what prepare-public-history.sh writes in its place; REDACTED when omitted.

Reports name an identifier by its line number in the file, never by its text, so a report can be
pasted anywhere.

Commands:
    identifiers.py check FILE REPO            validate the file, and that it is outside REPO
    identifiers.py replace-file FILE OUT      write git filter-repo --replace-text expressions
    identifiers.py scan-tree REPO FILE        tracked files of the working tree: content and paths
    identifiers.py scan-history REPO FILE     every object reachable from any ref, and ref names

scan-* exit 1 when an identifier is found, 2 on a usage or input error.
"""

import os
import re
import subprocess
import sys

DEFAULT_REPLACEMENT = "REDACTED"
MIN_LENGTH = 4


class InputError(Exception):
    pass


def load(path):
    """Returns [(line number, identifier bytes, replacement bytes)]."""
    try:
        with open(path, "rb") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise InputError(f"identifiers file: {e.strerror}: {path}")
    entries = []
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith(b"#"):
            continue
        ident, sep, replacement = line.partition(b"==>")
        ident = ident.strip()
        replacement = replacement.strip() if sep else DEFAULT_REPLACEMENT.encode()
        if ident.startswith((b"regex:", b"glob:")):
            raise InputError(f"line {number}: only literal identifiers are supported")
        if len(ident) < MIN_LENGTH:
            raise InputError(f"line {number}: an identifier needs at least {MIN_LENGTH} characters")
        if ident.lower() in replacement.lower():
            raise InputError(f"line {number}: the replacement contains the identifier")
        entries.append((number, ident, replacement))
    if not entries:
        raise InputError(f"no identifiers in {path}")
    return entries


def check_outside(path, repo):
    """The list must not live in the repository it guards: one commit would publish it."""
    real, top = os.path.realpath(path), os.path.realpath(repo)
    if os.path.commonpath([real, top]) == top:
        raise InputError(f"keep the identifiers file outside the repository: {path}")


def matcher(entries):
    """Returns a function bytes -> sorted line numbers of the identifiers found in it."""
    lowered = [(number, ident.lower()) for number, ident, _ in entries]

    def find(data):
        data = data.lower()
        return [number for number, ident in lowered if ident in data]

    return find


def line_of(data, ident):
    return data.lower()[: data.lower().index(ident.lower())].count(b"\n") + 1


def git(repo, *args, stdin=None):
    return subprocess.run(
        ["git", "-C", repo, *args], input=stdin, stdout=subprocess.PIPE, check=True
    ).stdout


def replace_file(entries, out):
    """filter-repo expressions: a case-insensitive regex per identifier, matching the gate."""
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        for _, ident, replacement in entries:
            pattern = re.escape(ident.decode("utf-8", "surrogateescape"))
            f.write(b"regex:(?i)" + pattern.encode("utf-8", "surrogateescape") + b"==>" + replacement + b"\n")


def scan_tree(repo, entries):
    find = matcher(entries)
    by_number = {number: ident for number, ident, _ in entries}
    hits = []
    for path in git(repo, "ls-files", "-z").split(b"\0"):
        if not path:
            continue
        shown = path.decode("utf-8", "replace")
        for number in find(path):
            hits.append(f"identifier on line {number}: in the path {shown}")
        full = os.path.join(repo, os.fsdecode(path))
        if os.path.islink(full) or not os.path.isfile(full):
            continue  # a symlink target is checked as its own path; a deleted file has no content
        with open(full, "rb") as f:
            data = f.read()
        for number in find(data):
            hits.append(f"identifier on line {number}: {shown}:{line_of(data, by_number[number])}")
    return hits


def scan_history(repo, entries):
    find = matcher(entries)
    by_number = {number: ident for number, ident, _ in entries}
    hits = []
    for ref in git(repo, "for-each-ref", "--format=%(refname)").splitlines():
        for number in find(ref):
            hits.append(f"identifier on line {number}: ref {ref.decode('utf-8', 'replace')}")
    # Every reachable commit, tree, blob and annotated tag, with the path rev-list found it at.
    paths = {}
    for row in git(repo, "rev-list", "--objects", "--all").splitlines():
        oid, _, path = row.partition(b" ")
        paths.setdefault(oid, path.decode("utf-8", "replace"))
    tags = git(repo, "for-each-ref", "--format=%(objectname) %(objecttype)", "refs/tags").splitlines()
    for row in tags:
        oid, kind = row.split(b" ")
        if kind == b"tag":
            paths.setdefault(oid, "")
    batch = git(repo, "cat-file", "--batch", stdin=b"\n".join(paths) + b"\n")
    pos = 0
    while pos < len(batch):
        header_end = batch.index(b"\n", pos)
        oid, kind, size = batch[pos:header_end].split(b" ")
        start = header_end + 1
        data = batch[start : start + int(size)]
        pos = start + int(size) + 1
        where = paths.get(oid, "")
        for number in find(data):
            if kind == b"blob":
                line = line_of(data, by_number[number])
                hits.append(f"identifier on line {number}: blob {oid.decode()} {where}:{line}")
            elif kind == b"tree":
                hits.append(f"identifier on line {number}: a file or folder name in /{where}")
            elif kind == b"commit":
                hits.append(f"identifier on line {number}: commit {oid.decode()} (message, author or committer)")
            else:
                hits.append(f"identifier on line {number}: annotated tag {oid.decode()}")
    return hits


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    command = argv[1]
    try:
        if command == "check" and len(argv) == 4:
            check_outside(argv[2], argv[3])
            load(argv[2])
            return 0
        if command == "replace-file" and len(argv) == 4:
            replace_file(load(argv[2]), argv[3])
            return 0
        if command in ("scan-tree", "scan-history") and len(argv) == 4:
            entries = load(argv[3])
            scan = scan_tree if command == "scan-tree" else scan_history
            hits = scan(argv[2], entries)
            for hit in hits:
                print(hit)
            return 1 if hits else 0
    except InputError as e:
        print(f"identifiers.py: {e}", file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
