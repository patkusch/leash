import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from helpers import make_repo, write_json
from leash.cli import main


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_rule_mode(self):
        code, out, _ = run("--rule", "Bash(git push:*)", "--rule", "Bash(ls:*)")
        self.assertEqual(code, 1)
        self.assertIn("HIGH", out)
        self.assertIn("LOW", out)

    def test_rule_mode_with_secret_exits_2_and_masks(self):
        code, out, _ = run("--rule", "Bash(PGPASSWORD=hunter2secret psql:*)")
        self.assertEqual(code, 2)
        self.assertIn("SECRET", out)
        self.assertNotIn("hunter2secret", out)

    def test_clean_folder(self):
        code, out, _ = run(str(self.root), "--no-user", "--no-git")
        self.assertEqual(code, 0)
        self.assertIn("No standing permissions", out)

    def test_text_report_and_exit_code(self):
        write_json(self.root / "p" / ".claude" / "settings.local.json",
                   {"permissions": {"allow": ["Bash(git push:*)", "Bash(ls:*)"]}})
        code, out, _ = run(str(self.root), "--no-user", "--no-git")
        self.assertEqual(code, 1)
        self.assertIn("HIGH", out)
        self.assertNotIn("Bash(ls:*)", out)              # low hidden by default
        code, out, _ = run(str(self.root), "--no-user", "--no-git", "--all")
        self.assertIn("Bash(ls:*)", out)

    def test_json_report(self):
        write_json(self.root / "p" / ".claude" / "settings.local.json", {"permissions": {"allow": ["Bash"]}})
        code, out, _ = run(str(self.root), "--no-user", "--no-git", "--json")
        self.assertEqual(code, 2)
        data = json.loads(out)
        self.assertEqual((data["tool"], data["format"]), ("leash", 1))
        from leash import __version__
        self.assertEqual(data["version"], __version__)
        self.assertEqual(data["summary"]["critical"], 1)
        self.assertEqual(data["findings"][0]["rule"], "Bash")

    def test_gitignore_flag_adds_the_line_and_rechecks(self):
        repo = make_repo(self.root / "r")
        write_json(repo / ".claude" / "settings.local.json", {"permissions": {"allow": ["Bash(ls:*)"]}})
        code, out, err = run(str(self.root), "--no-user", "--no-gh", "--gitignore", "--all")
        self.assertIn("added .claude/settings.local.json", err)
        self.assertEqual((repo / ".gitignore").read_text(), ".claude/settings.local.json\n")
        self.assertIn("is ignored by git", out)
        self.assertEqual(code, 0)
        # second run changes nothing
        _, _, err = run(str(self.root), "--no-user", "--no-gh", "--gitignore")
        self.assertEqual(err, "")


if __name__ == "__main__":
    unittest.main()
