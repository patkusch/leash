import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from helpers import write_json
from leash.cli import main
from leash.rules import grade, parse
from leash.usage import Use, count, matches, read_uses, top_commands

NOW = datetime.now(timezone.utc)


def line(tool, cmd=None, cwd="/p", when=NOW, kind="assistant"):
    inp = {"command": cmd} if cmd is not None else {"file_path": "x"}
    return json.dumps({"type": kind, "cwd": cwd, "timestamp": when.isoformat().replace("+00:00", "Z"),
                       "message": {"content": [{"type": "tool_use", "id": "t", "name": tool, "input": inp}]}})


class MatchTests(unittest.TestCase):
    def m(self, rule, cmd, tool="Bash"):
        return matches(parse(rule), Use(tool, cmd, "/p"))

    def test_prefix(self):
        self.assertTrue(self.m("Bash(git push:*)", "git push origin main"))
        self.assertTrue(self.m("Bash(git push:*)", "git push"))
        self.assertFalse(self.m("Bash(git push:*)", "git pushx"))
        self.assertFalse(self.m("Bash(git push:*)", "git status"))

    def test_new_space_star_form(self):
        self.assertTrue(parse("Bash(npm run test *)").is_prefix)
        self.assertEqual(parse("Bash(npm run test *)").command, "npm run test")
        self.assertTrue(self.m("Bash(npm run test *)", "npm run test -- --watch"))

    def test_compound_and_env_prefix(self):
        self.assertTrue(self.m("Bash(git push:*)", "git add -A && git commit -m x && git push"))
        self.assertTrue(self.m("Bash(psql:*)", "PGPASSWORD=$P psql -h db"))

    def test_exact_and_wildcard(self):
        self.assertTrue(self.m("Bash(npm test)", "npm test"))
        self.assertFalse(self.m("Bash(npm test)", "npm test -- -u"))
        self.assertTrue(self.m("Bash(ls *.py)", "ls a.py"))

    def test_bare_bash_and_tools(self):
        self.assertTrue(self.m("Bash", "anything"))
        self.assertFalse(self.m("Bash(ls:*)", None, tool="Read"))
        self.assertTrue(matches(parse("WebFetch"), Use("WebFetch", None, "/p")))
        self.assertTrue(matches(parse("mcp__slack"), Use("mcp__slack__send_message", None, "/p")))
        self.assertIsNone(matches(parse("Read(~/.ssh/**)"), Use("Read", None, "/p")))


class GradeFixTests(unittest.TestCase):
    def test_bare_program_prefix_is_high(self):
        self.assertEqual(grade("Bash(git:*)").level, "high")
        self.assertIn("git push", grade("Bash(git:*)").why)
        self.assertEqual(grade("Bash(npm:*)").level, "high")        # npm publish
        self.assertEqual(grade("Bash(ls:*)").level, "low")


class LogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.logs = Path(self.tmp.name) / "projects"
        (self.logs / "-p").mkdir(parents=True)
        lines = [
            line("Bash", "git push origin main"),
            line("Bash", "git push origin main"),
            line("Bash", "git push origin dev", cwd="/p/sub"),
            line("Bash", "git push", cwd="/elsewhere"),
            line("Bash", "git push", when=NOW - timedelta(days=90)),
            line("Bash", "git push", kind="user"),
            "not json",
            line("Read"),
        ]
        (self.logs / "-p" / "s.jsonl").write_text("\n".join(lines) + "\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_read_and_count(self):
        uses, files = read_uses(self.logs, 30)
        self.assertEqual(files, 1)
        self.assertEqual(len(uses), 5)                           # old line and user line skipped
        self.assertEqual(count("Bash(git push:*)", "/p", uses), 3)  # /elsewhere is out of scope
        self.assertEqual(count("Bash(git push:*)", None, uses), 4)
        self.assertEqual(count("Bash(rm:*)", "/p", uses), 0)
        self.assertIsNone(count("Read(src/**)", "/p", uses))
        self.assertEqual(top_commands("Bash(git push:*)", "/p", uses)[0], "git push origin main")

    def test_cli_usage(self):
        proj = Path(self.tmp.name) / "proj"
        write_json(proj / ".claude" / "settings.local.json",
                   {"permissions": {"allow": ["Bash(git push:*)", "Bash(rm:*)"]}})
        uses_line = line("Bash", "git push origin main", cwd=str(proj.resolve()))
        (self.logs / "-p" / "t.jsonl").write_text(uses_line + "\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main([str(proj), "--no-user", "--no-git", "--usage", "--logs", str(self.logs)])
        text = out.getvalue()
        self.assertIn("`git push`, without asking (used 1 time in the last 30 days)", text)
        self.assertIn("(not used in the last 30 days)", text)
        self.assertIn("removing it costs nothing", text)
        self.assertIn("`Bash(git push origin main)`", text)
        self.assertIn("counted from 2 Claude Code session(s)", text)

    def test_json_never_contains_the_unmasked_rule(self):
        proj = Path(self.tmp.name) / "proj"
        write_json(proj / ".claude" / "settings.local.json",
                   {"permissions": {"allow": ["Bash(PGPASSWORD=hunter2secret psql:*)"]}})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main([str(proj), "--no-user", "--no-git", "--json", "--usage", "--logs", str(self.logs)])
        self.assertNotIn("hunter2secret", out.getvalue())
        self.assertNotIn("source_rule", out.getvalue())


if __name__ == "__main__":
    unittest.main()
