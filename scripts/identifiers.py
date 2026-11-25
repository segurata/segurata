#!/usr/bin/env python3
"""Private identifiers gate, shared by check-public.sh and prepare-public-history.sh.

The identifiers file lives outside the repository (it would leak what it lists). It is UTF-8, one
entry per line; blank lines and lines starting with # are ignored:

    acme-internal-project
    Jane Client==>a client

The text before "==>" is the identifier, matched as a literal and caselessly: both sides are
Unicode-casefolded and compatibility-normalized, so Ñ matches ñ, Á matches á, and a decomposed á
(a + combining accent) matches too. Content that is not valid UTF-8 is also read as Latin-1. The
text after "==>" is what prepare-public-history.sh writes in its place; REDACTED when omitted. Its
rewrite covers the case variants and the decomposed forms; anything it misses fails the gate that
runs after it.

No output ever contains an identifier: every line printed goes through mask(), which writes each
occurrence as <identifier N>, N being the identifier's line number in the file. A line the mask
cannot clean is withheld whole. So a report can be pasted anywhere.

Commands:
    identifiers.py check FILE REPO            validate the file, and that it is outside REPO
    identifiers.py replace-file FILE OUT      write git filter-repo --replace-text expressions
    identifiers.py scan-tree REPO FILE        tracked files of the working tree: content and paths
    identifiers.py scan-history REPO FILE     every object reachable from any ref, and ref names
    identifiers.py mask FILE                  copy stdin to stdout, masked
    identifiers.py run-masked FILE CMD...     run CMD with its stdout and stderr masked

scan-* exit 1 when an identifier is found, 2 on a usage or input error. run-masked exits with
CMD's status.
"""

import functools
import os
import re
import subprocess
import sys
import threading
import unicodedata

DEFAULT_REPLACEMENT = "REDACTED"
MIN_LENGTH = 4
WITHHELD = "<identifier {}>: line withheld"


class InputError(Exception):
    pass


def fold(text):
    """The compatibility caseless form (The Unicode Standard, section 3.13, D146): what matching
    compares."""
    nfd = unicodedata.normalize("NFD", text).casefold()
    return unicodedata.normalize("NFKD", unicodedata.normalize("NFKD", nfd).casefold())


def load(path):
    """Returns [(line number, identifier, replacement)], as text."""
    try:
        with open(path, "rb") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise InputError(f"identifiers file: {e.strerror}: {path}")
    entries = []
    for number, raw in enumerate(lines, 1):
        try:
            line = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            raise InputError(f"line {number}: not UTF-8")
        if not line or line.startswith("#"):
            continue
        ident, sep, replacement = line.partition("==>")
        ident = ident.strip()
        replacement = replacement.strip() if sep else DEFAULT_REPLACEMENT
        if ident.startswith(("regex:", "glob:")):
            raise InputError(f"line {number}: only literal identifiers are supported")
        if len(ident) < MIN_LENGTH:
            raise InputError(f"line {number}: an identifier needs at least {MIN_LENGTH} characters")
        if fold(ident) in fold(replacement):
            raise InputError(f"line {number}: the replacement contains the identifier")
        if fold(ident) in fold(WITHHELD):
            raise InputError(f"line {number}: the identifier is part of the mask's own text")
        entries.append((number, ident, replacement))
    if not entries:
        raise InputError(f"no identifiers in {path}")
    return entries


def check_outside(path, repo):
    """The list must not live in the repository it guards: one commit would publish it."""
    real, top = os.path.realpath(path), os.path.realpath(repo)
    if os.path.commonpath([real, top]) == top:
        raise InputError(f"keep the identifiers file outside the repository: {path}")


def views(data):
    """The texts bytes are read as: UTF-8, and Latin-1 too when they are not valid UTF-8."""
    try:
        return [data.decode("utf-8")]
    except UnicodeDecodeError:
        return [data.decode("utf-8", "surrogateescape"), data.decode("latin-1")]


def matches(data, entries):
    """Returns [(identifier line number, line in data)] for each identifier found in bytes."""
    found = {}
    for text in views(data):
        folded = fold(text)
        for number, ident, _ in entries:
            at = folded.find(fold(ident))
            if at != -1 and number not in found:
                found[number] = folded.count("\n", 0, at) + 1
    return sorted(found.items())


def mask(data, entries):
    """bytes -> printable text where each identifier reads <identifier N>.

    Folding can change a text's length, so each folded character keeps the index of the character
    it came from. Should an identifier survive anyway (an invalid UTF-8 line, normalization across
    characters), the line is withheld whole."""
    text = data.decode("utf-8", "surrogateescape")
    if not matches(data, entries):
        return printable(text)
    folded, origin = [], []
    for i, char in enumerate(text):
        piece = fold(char)
        folded.append(piece)
        origin.extend([i] * len(piece))
    folded = "".join(folded)
    spans = []
    for number, ident, _ in entries:
        key = fold(ident)
        at = folded.find(key)
        while at != -1:
            spans.append((origin[at], origin[at + len(key) - 1] + 1, number))
            at = folded.find(key, at + 1)
    out, pos = [], 0
    for start, end, number in sorted(spans):
        if start < pos:  # overlaps the previous one: already covered, extend it
            if end > pos:
                pos = end
            continue
        out.append(text[pos:start])
        out.append(f"<identifier {number}>")
        pos = end
    out.append(text[pos:])
    masked = "".join(out)
    shown = printable(masked)
    left = matches(shown.encode("utf-8"), entries) or matches(masked.encode("utf-8", "surrogateescape"), entries)
    return WITHHELD.format(left[0][0]) if left else shown


def printable(text):
    """Bytes that were not UTF-8 shown as \\xNN escapes."""
    return text.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")


def git(repo, *args, stdin=None):
    return subprocess.run(
        ["git", "-C", repo, *args], input=stdin, stdout=subprocess.PIPE, check=True
    ).stdout


@functools.cache
def case_classes():
    """casefolded text -> every single character that casefolds to it."""
    classes = {}
    for cp in range(sys.maxunicode + 1):
        char = chr(cp)
        classes.setdefault(char.casefold(), set()).add(char)
    return classes


def pattern(ident):
    """A bytes regex for filter-repo, case-insensitive like the gate: ASCII case through (?i),
    every other case variant, the decomposed forms and multi-character folds (ß, ss) as explicit
    alternatives."""
    pieces = []
    for char in ident:
        forms = case_classes().get(char.casefold(), set()) | {char}
        forms |= {unicodedata.normalize("NFD", form) for form in forms}
        if len(char.casefold()) > 1:
            forms.add(char.casefold())
        if all(len(form) == 1 and form.isascii() for form in forms):
            pieces.append(re.escape(char))
        else:
            pieces.append("(?:" + "|".join(sorted(re.escape(form) for form in forms)) + ")")
    return "(?i)" + "".join(pieces)


def replace_file(entries, out):
    """filter-repo expressions, one case-insensitive regex per identifier."""
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        for _, ident, replacement in entries:
            f.write(f"regex:{pattern(ident)}==>{replacement}\n".encode("utf-8"))


def hits_in(entries, data, where):
    """One masked report line per identifier found in data; where(line) describes the place."""
    return [mask(f"identifier on line {number}: ".encode() + where(line), entries) for number, line in matches(data, entries)]


def scan_tree(repo, entries):
    hits = []
    for path in git(repo, "ls-files", "-z").split(b"\0"):
        if not path:
            continue
        hits += hits_in(entries, path, lambda _: b"in the path " + path)
        full = os.path.join(repo, os.fsdecode(path))
        if os.path.islink(full) or not os.path.isfile(full):
            continue  # a symlink target is checked as its own path; a deleted file has no content
        with open(full, "rb") as f:
            data = f.read()
        hits += hits_in(entries, data, lambda line: path + b":%d" % line)
    return hits


def scan_objects(repo, entries, refs, objects):
    """Ref names and objects: {object id: the path rev-list found it at}."""
    hits = []
    for ref in refs:
        hits += hits_in(entries, ref, lambda _: b"ref " + ref)
    if not objects:
        return hits
    batch = git(repo, "cat-file", "--batch", stdin=b"\n".join(objects) + b"\n")
    pos = 0
    while pos < len(batch):
        header_end = batch.index(b"\n", pos)
        oid, kind, size = batch[pos:header_end].split(b" ")
        start = header_end + 1
        data = batch[start : start + int(size)]
        pos = start + int(size) + 1
        where = objects.get(oid, b"")
        if kind == b"blob":
            hits += hits_in(entries, data, lambda line: b"blob %s %s:%d" % (oid, where, line))
        elif kind == b"tree":
            hits += hits_in(entries, data, lambda _: b"a file or folder name in /" + where)
        elif kind == b"commit":
            hits += hits_in(entries, data, lambda _: b"commit %s (message, author or committer)" % oid)
        else:
            hits += hits_in(entries, data, lambda _: b"annotated tag " + oid)
    return hits


def rev_list_objects(repo, *revs):
    """Every commit, tree, blob and annotated tag rev-list reaches, with the path it found it at."""
    objects = {}
    for row in git(repo, "rev-list", "--objects", *revs).splitlines():
        oid, _, path = row.partition(b" ")
        objects.setdefault(oid, path)
    return objects


def scan_history(repo, entries):
    refs = git(repo, "for-each-ref", "--format=%(refname)").splitlines()
    objects = rev_list_objects(repo, "--all")
    for row in git(repo, "for-each-ref", "--format=%(objectname) %(objecttype)", "refs/tags").splitlines():
        oid, kind = row.split(b" ")
        if kind == b"tag":
            objects.setdefault(oid, b"")
    return scan_objects(repo, entries, refs, objects)


def run_masked(entries, cmd):
    """Runs cmd, stdin inherited, copying its stdout and stderr masked, line by line."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def copy(src, dst):
        for line in src:
            dst.write(mask(line.rstrip(b"\n"), entries) + "\n")
            dst.flush()

    threads = [threading.Thread(target=copy, args=pair) for pair in ((proc.stdout, sys.stdout), (proc.stderr, sys.stderr))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    code = proc.wait()
    return 128 - code if code < 0 else code


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
        if command == "mask" and len(argv) == 3:
            entries = load(argv[2])
            for line in sys.stdin.buffer:
                print(mask(line.rstrip(b"\n"), entries))
            return 0
        if command == "run-masked" and len(argv) >= 4:
            return run_masked(load(argv[2]), argv[3:])
        if command in ("scan-tree", "scan-history") and len(argv) == 4:
            repo, entries = argv[2], load(argv[3])
            hits = scan_tree(repo, entries) if command == "scan-tree" else scan_history(repo, entries)
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
