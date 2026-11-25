"""The shell gates end to end, on throwaway repositories with made-up identifiers."""

import os
import secrets
import shutil
import string
import subprocess
import unittest

from test_identifiers import GIT_ENV, Base

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
GITLEAKS_CONFIG = os.path.join(SCRIPTS, "..", ".gitleaks.toml")
ENV = {k: v for k, v in GIT_ENV.items() if k not in ("SEGURATA_GATE_MASKED", "SEGURATA_PUBLIC_GATE")}


class GateBase(Base):
    IDENT = "Ñandú-Ácme"

    def setUp(self):
        super().setUp()
        self.repo_ = self.repo()
        shutil.copy(GITLEAKS_CONFIG, os.path.join(self.repo_.path, ".gitleaks.toml"))
        self.ids_file = self.ids(f"# made up\n{self.IDENT}\n")

    def gate(self, *args, stdin=b""):
        done = subprocess.run(
            [os.path.join(SCRIPTS, "check-public.sh"), "--identifiers", self.ids_file, *args],
            cwd=self.repo_.path, env=ENV, input=stdin, capture_output=True,
        )
        output = (done.stdout + done.stderr).decode("utf-8", "replace")
        self.assertNoIdentifier(output, self.IDENT)
        return done.returncode, output


@unittest.skipUnless(shutil.which("gitleaks"), "needs gitleaks")
class CheckPublicTest(GateBase):
    def test_tracked_files_are_reported_masked(self):
        self.repo_.write("ñANDÚ-áCME/notes.txt", "about ÑANDÚ-ácme\n")
        self.repo_.commit("init")
        code, output = self.gate("--require-identifiers")
        self.assertEqual(code, 1, output)
        self.assertIn("identifier on line 2: in the path <identifier 2>/notes.txt", output)
        self.assertIn("identifier on line 2: <identifier 2>/notes.txt:1", output)
        self.assertIn("check-public: FAILED", output)

    def test_clean(self):
        self.repo_.write("a.txt", "nothing\n")
        self.repo_.commit("init")
        code, output = self.gate("--require-identifiers", "--history")
        self.assertEqual(code, 0, output)
        self.assertIn("check-public: clean", output)


@unittest.skipUnless(shutil.which("gitleaks"), "needs gitleaks")
class PrePushTest(GateBase):
    """A real git push through the hook CONTRIBUTING.md installs, into a throwaway bare remote."""

    def setUp(self):
        super().setUp()
        remote = os.path.join(self.tmp.name, "remote.git")
        subprocess.run(["git", "init", "-q", "--bare", remote], env=ENV, check=True)
        self.repo_.git("remote", "add", "origin", remote)
        hook = os.path.join(self.repo_.path, ".git", "hooks", "pre-push")
        with open(hook, "w") as f:
            f.write(f"#!/bin/sh\nexec '{SCRIPTS}/check-public.sh' --require-identifiers --identifiers '{self.ids_file}' --pre-push\n")
        os.chmod(hook, 0o755)
        # Made up at run time, in the shape gitleaks' github-pat rule catches.
        self.token = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
        self.repo_.write("a.txt", "clean\n")
        self.repo_.commit("init")
        code, output = self.push("main")
        self.assertEqual(code, 0, output)

    def push(self, *args):
        done = subprocess.run(["git", "-C", self.repo_.path, "push", "-q", "origin", *args], env=ENV, capture_output=True)
        output = (done.stdout + done.stderr).decode("utf-8", "replace")
        self.assertNoIdentifier(output, self.IDENT)
        self.assertNotIn(self.token, output)
        return done.returncode, output

    def add_then_delete(self):
        self.repo_.write("config.txt", f"token = {self.token}\nowner: ñANDÚ-áCME\n")
        self.repo_.commit("add a config")
        self.repo_.git("rm", "-q", "config.txt")
        self.repo_.commit("remove it")

    def test_added_then_deleted_is_caught(self):
        self.add_then_delete()
        code, output = self.gate("--require-identifiers")
        self.assertEqual(code, 0, output)  # the working tree is clean: a tree scan passes
        code, output = self.push("main")
        self.assertNotEqual(code, 0, output)
        self.assertIn("leaks found: 1", output)
        self.assertIn("identifier on line 2: blob", output)
        self.assertIn("config.txt:2", output)
        self.assertIn("check-public: FAILED", output)

    def test_new_branch(self):
        self.add_then_delete()
        code, output = self.push("main:refs/heads/feature")
        self.assertNotEqual(code, 0, output)
        self.assertIn("leaks found: 1", output)
        self.assertIn("identifier on line 2: blob", output)

    def test_new_branch_name(self):
        code, output = self.push("main:refs/heads/ñandú-ácme-fix")
        self.assertNotEqual(code, 0, output)
        self.assertIn("ref refs/heads/<identifier 2>-fix", output)

    def test_clean_push_and_deletion(self):
        self.repo_.write("b.txt", "still clean\n")
        self.repo_.commit("more")
        self.assertEqual(self.push("main", "main:refs/heads/other")[0], 0)
        code, output = self.push("--delete", "other")
        self.assertEqual(code, 0, output)
        deletion = b"(delete) " + b"0" * 40 + b" refs/heads/other " + b"1" * 40 + b"\n"
        code, output = self.gate("--require-identifiers", "--pre-push", stdin=deletion)
        self.assertEqual(code, 0, output)
        self.assertIn("nothing pushed but deletions", output)


@unittest.skipUnless(shutil.which("gitleaks") and shutil.which("git-filter-repo"), "needs gitleaks and git-filter-repo")
class PreparePublicHistoryTest(GateBase):
    def setUp(self):
        super().setUp()
        repo = self.repo_
        repo.write("a.txt", "clean\n")
        repo.commit("init")
        # Case and Unicode variants of the identifier, in content and messages, gone from the tip.
        repo.write("notes.txt", "for ÑANDÚ-ácme\nand N\u0303andu\u0301-A\u0301cme\n")
        repo.commit("work for ñandú-ÁCME")
        repo.git("rm", "-q", "notes.txt")
        repo.commit("tidy")
        repo.git("tag", "-a", "v1", "-m", "release")
        self.runs = 0

    def prepare(self, *args):
        self.runs += 1
        workdir = os.path.join(self.tmp.name, f"public{self.runs}")
        done = subprocess.run(
            [os.path.join(SCRIPTS, "prepare-public-history.sh"), "--source", self.repo_.path,
             "--identifiers", self.ids_file, "--workdir", workdir, *args],
            env=ENV, capture_output=True,
        )
        output = (done.stdout + done.stderr).decode("utf-8", "replace")
        report = ""
        if os.path.exists(os.path.join(workdir, "report.txt")):
            with open(os.path.join(workdir, "report.txt"), encoding="utf-8") as f:
                report = f.read()
        self.assertNoIdentifier(output + report, self.IDENT)
        return done.returncode, output, report

    def test_authors_gate_fails_without_a_choice(self):
        code, output, report = self.prepare()
        self.assertEqual(code, 1, output)
        self.assertIn("== authors\nTest Author <author@example.com>\nFAIL: authors unchanged", report)
        self.assertIn("GATES FAILED", report)
        self.assertIn(report, output)

    def test_keep_authors(self):
        code, output, report = self.prepare("--keep-authors")
        self.assertEqual(code, 0, output)
        self.assertIn("== authors\nTest Author <author@example.com>\nok: published as listed (--keep-authors)", report)
        self.assertIn("== private identifiers\nok: none", report)  # every variant was rewritten
        self.assertIn("ALL GATES PASSED", report)

    def test_mailmap(self):
        mailmap = os.path.join(self.tmp.name, "mailmap")
        with open(mailmap, "w") as f:
            f.write("Public Name <public@example.com> <author@example.com>\n")
        code, output, report = self.prepare("--mailmap", mailmap)
        self.assertEqual(code, 0, output)
        self.assertIn("== authors\nPublic Name <public@example.com>\nok: rewritten with --mailmap", report)
        self.assertNotIn("author@example.com", report)

    def test_mailmap_and_keep_authors_exclude_each_other(self):
        code, output, _ = self.prepare("--keep-authors", "--mailmap", self.ids_file)
        self.assertEqual(code, 2, output)

    def test_branch_name_is_masked_everywhere(self):
        self.repo_.git("branch", "ñandú-ácme-main")
        code, output, report = self.prepare("--keep-authors", "--branch", "ñandú-ácme-main")
        self.assertEqual(code, 1, output)
        self.assertIn("branch: <identifier 2>-main", report)
        self.assertIn("ref refs/heads/<identifier 2>-main", report)
        self.assertIn("== cloning <identifier 2>-main into", output)


if __name__ == "__main__":
    unittest.main()
