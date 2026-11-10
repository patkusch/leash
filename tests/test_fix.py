import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from helpers import write_json
from leash.cli import main
from leash.fix import fix, plan
from leash.sources import scan

SECRET_RULE = "Bash(PGPASSWORD=hunter2secret psql -h db:*)"


class FixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.backups = self.root / "backups"
        os.environ["LEASH_BACKUP_DIR"] = str(self.backups)
        self.proj = self.root / "proj"

    def tearDown(self):
        os.environ.pop("LEASH_BACKUP_DIR", None)
        self.tmp.cleanup()

    def src(self):
        return next(s for s in scan([self.proj], include_user=False).sources)

    def test_removes_only_secret_rules_and_keeps_the_rest(self):
        path = write_json(self.proj / ".claude" / "settings.local.json", {
            "model": "x",
            "permissions": {"allow": ["Bash(ls:*)", SECRET_RULE], "deny": ["Bash(rm:*)"]},
        })
        self.assertEqual(len(plan(self.src())), 1)
        removed, backup = fix(self.src())
        self.assertEqual(len(removed), 1)
        self.assertNotIn("hunter2secret", removed[0][1])
        data = json.loads(path.read_text())
        self.assertEqual(data["permissions"]["allow"], ["Bash(ls:*)"])
        self.assertEqual(data["permissions"]["deny"], ["Bash(rm:*)"])
        self.assertEqual(list(data), ["model", "permissions"])          # key order kept
        self.assertIn("hunter2secret", backup.read_text())              # the backup is the original
        self.assertTrue(str(backup).startswith(str(self.backups)))      # not next to the file
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(backup.parent.stat().st_mode), 0o700)
        self.assertEqual(list((self.proj / ".claude").iterdir()), [path])   # no stray files

    def test_gemini_tools_allowed(self):
        path = write_json(self.proj / ".gemini" / "settings.json",
                          {"tools": {"allowed": ["run_shell_command(git)", "run_shell_command(sshpass -p S3cretPass ssh h)"]}})
        removed, _ = fix(self.src())
        self.assertEqual(len(removed), 1)
        self.assertEqual(json.loads(path.read_text())["tools"]["allowed"], ["run_shell_command(git)"])

    def test_clean_file_is_not_touched(self):
        path = write_json(self.proj / ".claude" / "settings.local.json", {"permissions": {"allow": ["Bash(ls:*)"]}})
        before = path.stat().st_mtime_ns
        self.assertEqual(fix(self.src()), ([], None))
        self.assertEqual(path.stat().st_mtime_ns, before)
        self.assertFalse(self.backups.exists())

    def test_mcp_secrets_are_left_alone(self):
        path = write_json(self.proj / ".mcp.json", {"mcpServers": {"s": {"env": {"T": "ghp_" + "f" * 36}}}})
        self.assertEqual(plan(self.src()), [])
        self.assertIn("ghp_", path.read_text())

    def test_cli_fix_then_clean_report(self):
        write_json(self.proj / ".claude" / "settings.local.json", {"permissions": {"allow": [SECRET_RULE]}})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([str(self.proj), "--no-user", "--no-git", "--fix"])
        self.assertIn("removed from permissions.allow", err.getvalue())
        self.assertIn("rotate", err.getvalue())
        self.assertNotIn("hunter2secret", err.getvalue() + out.getvalue())
        self.assertEqual(code, 0)
        self.assertNotIn("CRITICAL", out.getvalue())


if __name__ == "__main__":
    unittest.main()
