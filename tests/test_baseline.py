import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from helpers import write_json
from leash.audit import Finding
from leash.baseline import fingerprint
from leash.cli import main


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(list(argv))
    return code, out.getvalue()


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.cwd = os.getcwd()
        os.chdir(self.root)
        self.local = write_json(self.root / "p" / ".claude" / "settings.local.json", {"permissions": {"allow": [
            "Bash(git push:*)", "Bash(PGPASSWORD=hunter2secret psql:*)"]}})

    def tearDown(self):
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def test_fingerprint_ignores_usage_suffix(self):
        a = Finding("high", "rule", "may run x, without asking", "", "", "/p/f")
        b = Finding("high", "rule", "may run x, without asking (used 3 times in the last 30 days)", "", "", "/p/f")
        self.assertEqual(fingerprint(a), fingerprint(b))

    def test_write_then_only_new_findings_fail(self):
        code, out = run("p", "--no-user", "--no-git", "--write-baseline", "base.json")
        self.assertEqual(code, 0)
        text = (self.root / "base.json").read_text()
        self.assertNotIn("hunter2secret", text)
        self.assertEqual(len(json.loads(text)["findings"]), 3)        # secret, push rule, psql rule

        code, out = run("p", "--no-user", "--no-git", "--baseline", "base.json")
        self.assertEqual(code, 0)
        self.assertIn("3 known finding(s) hidden", out)

        data = json.loads(self.local.read_text())
        data["permissions"]["allow"].append("Bash(curl:*)")
        self.local.write_text(json.dumps(data))
        code, out = run("p", "--no-user", "--no-git", "--baseline", "base.json")
        self.assertEqual(code, 1)
        self.assertIn("`curl`", out)
        self.assertNotIn("`git push`", out)

    def test_stale_entries_are_reported(self):
        run("p", "--no-user", "--no-git", "--write-baseline", "base.json")
        self.local.write_text(json.dumps({"permissions": {"allow": ["Bash(git push:*)"]}}))
        code, out = run("p", "--no-user", "--no-git", "--baseline", "base.json")
        self.assertIn("2 baseline entries no longer match", out)

    def test_unreadable_baseline(self):
        (self.root / "bad.json").write_text("{")
        code, _ = run("p", "--no-user", "--no-git", "--baseline", "bad.json")
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
