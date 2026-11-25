"""The shell gates end to end, on throwaway repositories with made-up identifiers."""

import os
import shutil
import subprocess
import unittest

from test_identifiers import GIT_ENV, Base

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
GITLEAKS_CONFIG = os.path.join(SCRIPTS, "..", ".gitleaks.toml")
ENV = {k: v for k, v in GIT_ENV.items() if k not in ("SEGURATA_GATE_MASKED", "SEGURATA_PUBLIC_GATE")}


@unittest.skipUnless(shutil.which("gitleaks"), "needs gitleaks")
class CheckPublicTest(Base):
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


if __name__ == "__main__":
    unittest.main()
