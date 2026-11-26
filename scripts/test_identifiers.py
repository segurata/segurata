import contextlib
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import identifiers  # noqa: E402

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Test Author",
    "GIT_AUTHOR_EMAIL": "author@example.com",
    "GIT_COMMITTER_NAME": "Test Author",
    "GIT_COMMITTER_EMAIL": "author@example.com",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


class Repo:
    def __init__(self, path):
        self.path = path
        self.git("init", "-q", "-b", "main")

    def git(self, *args):
        subprocess.run(["git", "-C", self.path, *args], env=GIT_ENV, check=True, capture_output=True)

    def write(self, name, text):
        full = os.path.join(self.path, name)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(text)

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def ids(self, text):
        path = os.path.join(self.tmp.name, "ids.txt")
        with open(path, "wb") as f:
            f.write(text if isinstance(text, bytes) else text.encode("utf-8"))
        return path

    def assertNoIdentifier(self, output, *idents):
        """Not one identifier, in any case or Unicode form, in output (text or a list of lines)."""
        text = output if isinstance(output, str) else "\n".join(output)
        for ident in idents:
            self.assertNotIn(identifiers.fold(ident), identifiers.fold(text))
            self.assertNotIn(ident.lower(), text.lower())

    def repo(self):
        path = os.path.join(self.tmp.name, "repo")
        os.mkdir(path)
        return Repo(path)


class LoadTest(Base):
    def test_entries(self):
        entries = identifiers.load(self.ids("# a comment\n\n  acme-corp  \nJane Client==>a client\n"))
        self.assertEqual(entries, [(3, "acme-corp", "REDACTED"), (4, "Jane Client", "a client")])

    def test_rejects(self):
        cases = {
            "abc\n": "at least 4",
            "regex:acme.*\n": "only literal",
            "glob:*acme*\n": "only literal",
            "acme-corp==>the ACME-CORP team\n": "replacement contains",
            "Ñandú-corp==>the ñANDÚ-CORP team\n": "replacement contains",
            "# nothing\n": "no identifiers",
            b"acme-corp\n\xd1and\xfa-corp\n": "line 2: not UTF-8",
            "Withheld\n": "the mask's own text",
        }
        for text, message in cases.items():
            with self.subTest(text=text):
                with self.assertRaisesRegex(identifiers.InputError, message):
                    identifiers.load(self.ids(text))

    def test_missing_file(self):
        with self.assertRaisesRegex(identifiers.InputError, "identifiers file"):
            identifiers.load(os.path.join(self.tmp.name, "absent.txt"))


class CheckOutsideTest(Base):
    def test_inside_the_repository(self):
        repo = self.repo()
        inside = os.path.join(repo.path, "sub", "ids.txt")
        with self.assertRaisesRegex(identifiers.InputError, "outside the repository"):
            identifiers.check_outside(inside, repo.path)
        link = os.path.join(self.tmp.name, "link")
        os.symlink(repo.path, link)
        with self.assertRaisesRegex(identifiers.InputError, "outside the repository"):
            identifiers.check_outside(os.path.join(link, "ids.txt"), repo.path)

    def test_outside(self):
        repo = self.repo()
        identifiers.check_outside(self.ids("acme-corp\n"), repo.path)


class ReplaceFileTest(Base):
    def test_case_insensitive_literal_regexes(self):
        out = os.path.join(self.tmp.name, "expressions.txt")
        identifiers.replace_file(identifiers.load(self.ids("acme.corp\nJane==>a client\n")), out)
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)
        with open(out, "rb") as f:
            lines = f.read().splitlines()
        self.assertEqual(lines, [rb"regex:(?i)acme\.corp==>REDACTED", rb"regex:(?i)Jane==>a client"])
        pattern = re.compile(lines[0][len(b"regex:") : lines[0].index(b"==>")])
        self.assertTrue(pattern.search(b"see ACME.Corp here"))
        self.assertFalse(pattern.search(b"acmeXcorp"))  # the dot is literal

    def test_unicode_case_and_forms(self):
        """filter-repo applies the expressions to bytes, where (?i) is ASCII only: every other case
        variant and the decomposed forms are spelled out, so the rewrite matches what the gate does."""
        out = os.path.join(self.tmp.name, "expressions.txt")
        identifiers.replace_file(identifiers.load(self.ids("Ñandú-Ácme\nStraße-corp\n")), out)
        with open(out, "rb") as f:
            lines = f.read().splitlines()
        nandu, strasse = (re.compile(line[len(b"regex:") : line.index(b"==>")]) for line in lines)
        for text in ("Ñandú-Ácme", "ñandú-ácme", "ÑANDÚ-ÁCME", "ñANDÚ-áCME", "N\u0303andu\u0301-A\u0301cme"):
            with self.subTest(text=text):
                self.assertTrue(nandu.search(f"x {text} y".encode()))
        self.assertFalse(nandu.search("nandu-acme".encode()))
        for text in ("Straße-corp", "STRASSE-CORP", "strasse-corp", "STRAẞE-CORP"):
            with self.subTest(text=text):
                self.assertTrue(strasse.search(text.encode()))


class MaskTest(Base):
    def test_every_occurrence_in_any_case_or_form(self):
        entries = identifiers.load(self.ids("# private\nacme-corp\nÑandú-Ácme\n"))
        cases = {
            b"in /src/ACME-corp/a and acme-CORP": "in /src/<identifier 2>/a and <identifier 2>",
            "ñANDÚ-áCME.txt".encode(): "<identifier 3>.txt",
            "N\u0303andu\u0301-A\u0301cme!".encode(): "<identifier 3>!",
            b"clean line": "clean line",
            b"bad \xff byte": "bad \\xff byte",
        }
        for data, shown in cases.items():
            with self.subTest(data=data):
                self.assertEqual(identifiers.mask(data, entries), shown)

    def test_overlapping_identifiers_are_one_mask(self):
        entries = identifiers.load(self.ids("acme-corp\ncorp-team\n"))
        self.assertEqual(identifiers.mask(b"x acme-corp-team y", entries), "x <identifier 1> y")

    def test_a_line_it_cannot_clean_is_withheld(self):
        entries = identifiers.load(self.ids("Ñandú-corp\n"))
        latin1 = "the Ñandú-corp file \xff".encode("latin-1")  # not UTF-8, so the mask cannot place it
        self.assertEqual(identifiers.mask(latin1, entries), "<identifier 1>: line withheld")


class ScanTreeTest(Base):
    def test_content_and_paths_without_the_identifier(self):
        repo = self.repo()
        repo.write("a.txt", "one\ntwo Acme-Corp\n")
        repo.write("acme-corp/b.txt", "clean\n")
        repo.write("gone.txt", "acme-corp\n")
        os.symlink("/home/ACME-corp/notes.txt", os.path.join(repo.path, "link"))
        os.symlink("a.txt", os.path.join(repo.path, "clean-link"))
        repo.commit("init")
        os.remove(os.path.join(repo.path, "gone.txt"))  # deleted in the working tree: not published
        repo.write("untracked.txt", "acme-corp\n")
        hits = identifiers.scan_tree(repo.path, identifiers.load(self.ids("acme-corp\n")))
        self.assertEqual(hits, ["identifier on line 1: a.txt:2", "identifier on line 1: in the path <identifier 1>/b.txt",
                                "identifier on line 1: link:1"])
        self.assertNoIdentifier(hits, "acme-corp")

    def test_unicode_variants(self):
        repo = self.repo()
        repo.write("ñANDÚ-áCME/a.txt", "one\nN\u0303andu\u0301-A\u0301cme\n")
        repo.write("b.txt", "ÑANDÚ-ácme")
        with open(os.path.join(repo.path, "latin1.txt"), "wb") as f:
            f.write("x\n\xd1AND\xda-\xe1cme \xff\n".encode("latin-1"))
        repo.commit("init")
        hits = identifiers.scan_tree(repo.path, identifiers.load(self.ids("Ñandú-Ácme\n")))
        self.assertEqual(
            sorted(hits),
            [
                "identifier on line 1: <identifier 1>/a.txt:2",
                "identifier on line 1: b.txt:1",
                "identifier on line 1: in the path <identifier 1>/a.txt",
                "identifier on line 1: latin1.txt:2",
            ],
        )
        self.assertNoIdentifier(hits, "Ñandú-Ácme")

    def test_clean(self):
        repo = self.repo()
        repo.write("a.txt", "nothing here\n")
        repo.commit("init")
        self.assertEqual(identifiers.scan_tree(repo.path, identifiers.load(self.ids("acme-corp\n"))), [])


class ScanHistoryTest(Base):
    def test_every_kind_of_object_and_ref(self):
        repo = self.repo()
        repo.write("keep.txt", "clean\n")
        repo.commit("init")
        repo.write("old.txt", "x\nacme-corp\n")
        repo.commit("add a file")
        repo.git("rm", "-q", "old.txt")
        repo.commit("for ACME-CORP")
        repo.git("tag", "-a", "v1", "-m", "release for acme-corp")
        repo.git("branch", "acme-corp-branch")
        hits = identifiers.scan_history(repo.path, identifiers.load(self.ids("acme-corp\n")))
        joined = "\n".join(hits)
        self.assertNoIdentifier(joined, "acme-corp")
        self.assertIn("ref refs/heads/<identifier 1>-branch", joined)
        self.assertRegex(joined, r"blob [0-9a-f]{40} old\.txt:2")
        self.assertRegex(joined, r"commit [0-9a-f]{40} \(message, author or committer\)")
        self.assertRegex(joined, r"annotated tag [0-9a-f]{40}")
        self.assertEqual(len(hits), 4)

    def test_path_names(self):
        repo = self.repo()
        repo.write("acme-corp/a.txt", "clean\n")
        repo.commit("init")
        hits = identifiers.scan_history(repo.path, identifiers.load(self.ids("acme-corp\n")))
        self.assertEqual(hits, ["identifier on line 1: a file or folder name in /"])

    def test_paths_in_hits_are_masked(self):
        repo = self.repo()
        repo.write("ACME-corp/acme-CORP.txt", "acme-corp\n")
        repo.commit("init")
        hits = identifiers.scan_history(repo.path, identifiers.load(self.ids("acme-corp\n")))
        self.assertNoIdentifier(hits, "acme-corp")
        self.assertEqual(
            sorted(re.sub("[0-9a-f]{40}", "OID", hit) for hit in hits),
            [
                "identifier on line 1: a file or folder name in /",
                "identifier on line 1: a file or folder name in /<identifier 1>",
                "identifier on line 1: blob OID <identifier 1>/<identifier 1>.txt:1",
            ],
        )

    def test_clean(self):
        repo = self.repo()
        repo.write("a.txt", "clean\n")
        repo.commit("init")
        self.assertEqual(identifiers.scan_history(repo.path, identifiers.load(self.ids("acme-corp\n"))), [])


class PushTest(Base):
    ZERO = "0" * 40

    def setUp(self):
        super().setUp()
        self.repo_ = self.repo()
        self.repo_.write("a.txt", "clean\n")
        self.repo_.commit("published")
        self.published = self.head()
        self.repo_.write("old.txt", "x\nÑANDÚ-ácme\n")
        self.repo_.commit("add")
        self.repo_.git("rm", "-q", "old.txt")
        self.repo_.commit("delete")  # the tip is clean again: only the pushed commits show it
        self.tip = self.head()

    def head(self):
        return subprocess.run(["git", "-C", self.repo_.path, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()

    def stdin(self, *rows):
        return [" ".join(row).encode() for row in rows]

    def test_revs(self):
        unknown = "1" * 40
        cases = {
            "update": ((("refs/heads/main", self.tip, "refs/heads/main", self.published),),
                       [self.tip, "^" + self.published]),
            "new ref": ((("refs/heads/main", self.tip, "refs/heads/new", self.ZERO),), [self.tip]),
            "remote commit not here": ((("refs/heads/main", self.tip, "refs/heads/main", unknown),),
                                       [self.tip]),
            "deletion": ((("(delete)", self.ZERO, "refs/heads/gone", self.published),), []),
        }
        for name, (rows, revs) in cases.items():
            with self.subTest(name):
                self.assertEqual(identifiers.push_revs(self.repo_.path, self.stdin(*rows))[0], revs)

    def test_rejects_malformed_input(self):
        for line in (b"refs/heads/main", b"refs/heads/main --all refs/heads/main " + self.ZERO.encode()):
            with self.subTest(line=line):
                with self.assertRaisesRegex(identifiers.InputError, "pre-push input"):
                    identifiers.push_revs(self.repo_.path, [line])

    def test_added_then_deleted_is_caught(self):
        entries = identifiers.load(self.ids("Ñandú-Ácme\n"))
        self.assertEqual(identifiers.scan_tree(self.repo_.path, entries), [])  # what the old hook saw
        rows = (("refs/heads/main", self.tip, "refs/heads/main", self.published),)
        hits = identifiers.scan_push(self.repo_.path, entries, self.stdin(*rows))
        self.assertEqual([re.sub("[0-9a-f]{40}", "OID", hit) for hit in hits], ["identifier on line 1: blob OID old.txt:2"])

    def test_published_commits_and_deletions_are_not_rescanned(self):
        entries = identifiers.load(self.ids("published\n"))  # only in the first commit's message
        rows = (("refs/heads/main", self.tip, "refs/heads/main", self.published),)
        self.assertEqual(identifiers.scan_push(self.repo_.path, entries, self.stdin(*rows)), [])
        rows = (("(delete)", self.ZERO, "refs/heads/published-branch", self.published),)
        self.assertEqual(identifiers.scan_push(self.repo_.path, entries, self.stdin(*rows)), [])

    def test_remote_ref_names(self):
        entries = identifiers.load(self.ids("Ñandú-Ácme\n"))
        rows = (("refs/heads/main", self.published, "refs/heads/ñandú-ácme-fix", self.ZERO),)
        hits = identifiers.scan_push(self.repo_.path, entries, self.stdin(*rows))
        self.assertIn("identifier on line 1: ref refs/heads/<identifier 1>-fix", hits)
        self.assertNoIdentifier(hits, "Ñandú-Ácme")


class MainTest(Base):
    def test_exit_codes(self):
        repo = self.repo()
        repo.write("a.txt", "acme-corp\n")
        repo.commit("init")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(identifiers.main(["x", "scan-tree", repo.path, self.ids("acme-corp\n")]), 1)
            self.assertEqual(identifiers.main(["x", "scan-tree", repo.path, self.ids("other-name\n")]), 0)
            self.assertEqual(identifiers.main(["x", "scan-tree", repo.path, self.ids("ab\n")]), 2)
            self.assertEqual(identifiers.main(["x", "unknown", "y"]), 2)
            self.assertEqual(identifiers.main(["x", "check", self.ids("acme-corp\n"), repo.path]), 0)
            self.assertEqual(identifiers.main(["x", "check", os.path.join(repo.path, "a.txt"), repo.path]), 2)
        self.assertEqual(out.getvalue(), "identifier on line 1: a.txt:1\n")
        self.assertNotIn("acme-corp", out.getvalue() + err.getvalue())

    def run_script(self, *args, stdin=b""):
        return subprocess.run([sys.executable, identifiers.__file__, *args], input=stdin, capture_output=True)

    def test_mask(self):
        done = self.run_script("mask", self.ids("acme-corp\n"), stdin=b"a ACME-corp b\nclean\n")
        self.assertEqual((done.returncode, done.stdout), (0, b"a <identifier 1> b\nclean\n"))

    def test_run_masked(self):
        program = "import sys; print('out ACME-corp'); print('err acme-CORP', file=sys.stderr); sys.exit(3)"
        done = self.run_script("run-masked", self.ids("acme-corp\n"), sys.executable, "-c", program)
        self.assertEqual(done.returncode, 3)
        self.assertEqual(done.stdout, b"out <identifier 1>\n")
        self.assertEqual(done.stderr, b"err <identifier 1>\n")
        killed = self.run_script("run-masked", self.ids("acme-corp\n"), sys.executable, "-c",
                                 "import os, signal; os.kill(os.getpid(), signal.SIGTERM)")
        self.assertEqual(killed.returncode, 128 + 15, "a signal exits like a shell reports it")

    def test_author_options(self):
        identity = "Public Name <public@example.com>"
        self.assertEqual(identifiers.author_options("scan-push", ["--skip-authors"]), (True, ()))
        self.assertEqual(identifiers.author_options("scan-history", ["--allow-author", identity]),
                         (False, {identity.encode()}))
        for command, args in (("scan-history", ["--skip-authors"]), ("scan-push", ["--allow-author"]),
                              ("scan-push", ["--allow-author", "no email"]), ("scan-push", ["--allow-author", "a <b>\nc"]),
                              ("scan-history", ["--other", identity])):
            with self.subTest(command=command, args=args):
                with self.assertRaises(identifiers.InputError):
                    identifiers.author_options(command, args)


if __name__ == "__main__":
    unittest.main()
