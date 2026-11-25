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
        subprocess.run(["git", "-C", self.path, *args], env=GIT_ENV, check=True, stdout=subprocess.DEVNULL)

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
        with open(path, "w") as f:
            f.write(text)
        return path

    def repo(self):
        path = os.path.join(self.tmp.name, "repo")
        os.mkdir(path)
        return Repo(path)


class LoadTest(Base):
    def test_entries(self):
        entries = identifiers.load(self.ids("# a comment\n\n  acme-corp  \nJane Client==>a client\n"))
        self.assertEqual(entries, [(3, b"acme-corp", b"REDACTED"), (4, b"Jane Client", b"a client")])

    def test_rejects(self):
        cases = {
            "abc\n": "at least 4",
            "regex:acme.*\n": "only literal",
            "glob:*acme*\n": "only literal",
            "acme-corp==>the ACME-CORP team\n": "replacement contains",
            "# nothing\n": "no identifiers",
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


class ScanTreeTest(Base):
    def test_content_and_paths_without_the_identifier(self):
        repo = self.repo()
        repo.write("a.txt", "one\ntwo Acme-Corp\n")
        repo.write("acme-corp/b.txt", "clean\n")
        repo.write("gone.txt", "acme-corp\n")
        repo.commit("init")
        os.remove(os.path.join(repo.path, "gone.txt"))  # deleted in the working tree: not published
        repo.write("untracked.txt", "acme-corp\n")
        hits = identifiers.scan_tree(repo.path, identifiers.load(self.ids("acme-corp\n")))
        self.assertEqual(hits, ["identifier on line 1: a.txt:2", "identifier on line 1: in the path acme-corp/b.txt"])

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
        self.assertIn("ref refs/heads/acme-corp-branch", joined)
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

    def test_clean(self):
        repo = self.repo()
        repo.write("a.txt", "clean\n")
        repo.commit("init")
        self.assertEqual(identifiers.scan_history(repo.path, identifiers.load(self.ids("acme-corp\n"))), [])


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


if __name__ == "__main__":
    unittest.main()
