import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from helpers import write_json
from leash.cli import main


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(list(argv))
    return code, out.getvalue()


class MinLevelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write_json(self.root / "p" / ".claude" / "settings.local.json", {"permissions": {"allow": [
            "Bash(git push:*)", "Bash(git commit:*)", "Bash(ls:*)"]}})
        self.base = [str(self.root), "--no-user", "--no-git"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_text_hides_lower_levels_and_says_so(self):
        code, out = run(*self.base, "--min-level", "high", "--all")
        self.assertIn("`git push`", out)
        self.assertNotIn("`git commit`", out)
        self.assertNotIn("`ls`", out)
        self.assertIn("2 finding(s) below high not shown", out)
        self.assertEqual(code, 1)

    def test_exit_code_still_counts_hidden_findings(self):
        code, _ = run(*self.base, "--min-level", "critical", "--fail-on", "medium")
        self.assertEqual(code, 1)

    def test_json_and_sarif_are_filtered(self):
        _, out = run(*self.base, "--min-level", "high", "--json")
        self.assertEqual({f["level"] for f in json.loads(out)["findings"]}, {"high"})
        _, out = run(*self.base, "--min-level", "high", "--sarif")
        self.assertEqual({r["level"] for r in json.loads(out)["runs"][0]["results"]}, {"error"})

    def test_bad_level_is_refused(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                main([*self.base, "--min-level", "severe"])


if __name__ == "__main__":
    unittest.main()
