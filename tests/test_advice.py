import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from helpers import write_json
from leash.advice import env_files, findings, missing, suggestion
from leash.cli import main
from leash.sources import scan


class AdviceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.proj = self.root / "p"

    def tearDown(self):
        self.tmp.cleanup()

    def sources(self, home=None):
        return scan([self.root], include_user=home is not None, home=home).sources

    def test_env_files(self):
        self.proj.mkdir()
        for n in (".env", ".env.local", ".env.example", ".env.sample", "env.txt"):
            (self.proj / n).write_text("x")
        self.assertEqual(env_files(self.proj), [".env", ".env.local"])

    def test_env_without_deny_is_medium(self):
        write_json(self.proj / ".claude" / "settings.local.json", {"permissions": {"allow": ["Bash(ls:*)"]}})
        (self.proj / ".env").write_text("DB_PASSWORD=x")
        f = findings(self.sources())
        self.assertEqual([x.level for x in f], ["medium"])
        self.assertIn(".env", f[0].title)

    def test_env_with_deny_is_quiet(self):
        write_json(self.proj / ".claude" / "settings.json", {"permissions": {"deny": ["Read(./.env)", "Read(./.env.*)"]}})
        (self.proj / ".env").write_text("x")
        self.assertEqual(findings(self.sources()), [])

    def test_no_env_no_env_advice(self):
        write_json(self.proj / ".claude" / "settings.json", {"permissions": {"deny": ["Bash(git push --force:*)"]}})
        self.assertEqual(findings(self.sources()), [])

    def test_user_level_advice_and_suggestion(self):
        home = self.root / "home"
        write_json(home / ".claude" / "settings.json", {"permissions": {"deny": ["Read(~/.ssh/**)"]}})
        srcs = [s for s in self.sources(home=home) if s.kind != "claude-managed"]
        user_missing, _ = missing(srcs)
        self.assertNotIn("Read(~/.ssh/**)", user_missing)
        self.assertIn("Read(~/.aws/**)", user_missing)
        f = findings(srcs)
        self.assertEqual([x.level for x in f], ["low"])
        text = suggestion(srcs)
        self.assertIn('"Read(~/.aws/**)"', text)
        self.assertNotIn('"Read(~/.ssh/**)"', text)

    def test_cli_suggest(self):
        write_json(self.proj / ".claude" / "settings.local.json", {"permissions": {"allow": []}})
        (self.proj / ".env").write_text("x")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main([str(self.root), "--no-user", "--no-git", "--suggest"])
        self.assertIn('"Read(./.env)"', out.getvalue())
        self.assertIn("Deny rules always win", out.getvalue())


if __name__ == "__main__":
    unittest.main()
