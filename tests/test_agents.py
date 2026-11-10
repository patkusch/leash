"""Gemini CLI, Cursor and VS Code files, fix advice, --fail-on and home-folder handling."""

import tempfile
import unittest
from pathlib import Path

from helpers import write_json
from leash.audit import Finding, audit_source, exit_code, gemini_rule, rule_fix
from leash.rules import grade, parse
from leash.sources import Source, project_sources_in, scan

TOKEN = "ghp_" + "e" * 36


def src(kind, data, shared=True):
    return Source(Path("/p/x.json"), kind, "x", Path("/p"), shared, data)


class GeminiTests(unittest.TestCase):
    def test_shell_rule_is_a_prefix(self):
        r = gemini_rule("run_shell_command(git push)")
        self.assertEqual((r.tool, r.spec), ("Bash", "git push:*"))
        self.assertEqual(grade(r).level, "high")
        self.assertEqual(grade(gemini_rule("run_shell_command(npm test)")).level, "low")
        self.assertEqual(grade(gemini_rule("run_shell_command")).level, "critical")
        self.assertEqual(grade(gemini_rule("web_fetch")).level, "medium")
        self.assertEqual(grade(gemini_rule("read_file")).level, "low")

    def test_settings(self):
        f = audit_source(src("gemini", {
            "general": {"defaultApprovalMode": "auto_edit"},
            "tools": {"allowed": ["run_shell_command(git push)", "run_shell_command(PGPASSWORD=hunter2secret psql)"]},
            "security": {"autoAddToPolicyByDefault": True},
            "mcpServers": {"s": {"httpUrl": "https://x", "headers": {"Authorization": "Bearer abcdefghijkl"},
                                 "trust": True}},
        }), use_git=False)
        kinds = sorted(x.kind for x in f)
        self.assertEqual(kinds, ["gemini", "gemini", "mcp", "rule", "rule", "secret", "secret"])
        self.assertIn("tools.allowed", next(x for x in f if x.kind == "rule" and x.level == "high").fix)
        self.assertFalse(any("hunter2secret" in (x.title + (x.rule or "")) for x in f))


class CursorAndVSCodeTests(unittest.TestCase):
    def test_cursor_uses_mcpServers(self):
        f = audit_source(src("cursor-mcp", {"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": TOKEN}}}}), use_git=False)
        self.assertEqual([x.kind for x in f], ["secret"])
        self.assertIn("Cursor MCP servers", f[0].detail)

    def test_vscode_uses_servers_and_inputs_are_fine(self):
        f = audit_source(src("vscode-mcp", {"servers": {
            "gh": {"type": "stdio", "command": "x", "env": {"GITHUB_TOKEN": TOKEN}},
            "ok": {"type": "stdio", "command": "x", "env": {"GITHUB_TOKEN": "${input:gh-token}"}},
        }}), use_git=False)
        self.assertEqual(len(f), 1)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_finds_other_agents_project_files(self):
        p = self.root / "proj"
        write_json(p / ".cursor" / "mcp.json", {})
        write_json(p / ".vscode" / "mcp.json", {})
        write_json(p / ".gemini" / "settings.json", {})
        write_json(p / ".vscode" / "settings.json", {})          # not an agent file
        kinds = sorted(s.kind for s in scan([self.root], include_user=False).sources)
        self.assertEqual(kinds, ["cursor-mcp", "gemini", "vscode-mcp"])

    def test_home_folder_is_not_read_twice(self):
        home = self.root / "home"
        write_json(home / ".claude" / "settings.json", {})
        write_json(home / ".claude" / "settings.local.json", {})
        write_json(home / ".gemini" / "settings.json", {})
        kinds = sorted(s.kind for s in project_sources_in(home, home=home))
        self.assertEqual(kinds, ["claude-local"])

    def test_user_files_for_other_agents(self):
        home = self.root / "home"
        write_json(home / ".gemini" / "settings.json", {"tools": {"allowed": ["run_shell_command"]}})
        write_json(home / ".cursor" / "mcp.json", {})
        kinds = sorted(s.kind for s in scan([], include_user=True, home=home).sources if s.kind != "claude-managed")
        self.assertEqual(kinds, ["cursor-mcp", "gemini"])

    def test_leashignore(self):
        write_json(self.root / "keep" / ".mcp.json", {})
        write_json(self.root / "skip" / "deep" / ".mcp.json", {})
        (self.root / ".leashignore").write_text("# comment\nskip\n")
        found = [s.project.name for s in scan([self.root], include_user=False).sources]
        self.assertEqual(found, ["keep"])
        found = [s.project.name for s in scan([self.root / "skip" / "deep"], include_user=False).sources]
        self.assertEqual(found, ["deep"])                     # named on purpose: not skipped


class FixAdviceTests(unittest.TestCase):
    def fix(self, raw):
        r = parse(raw)
        return rule_fix(r, grade(r))

    def test_advice_fits_the_tool(self):
        self.assertEqual(self.fix("Bash(ls:*)"), "Nothing to do.")
        self.assertIn("one at a time", self.fix("Bash"))
        self.assertIn("exact command", self.fix("Bash(git push:*)"))
        self.assertIn("deny list", self.fix("Read(~/.ssh/**)"))
        self.assertIn("`Read(~/.ssh/**)`", self.fix("Read(~/.ssh/**)"))
        self.assertIn("domain:", self.fix("WebFetch"))
        self.assertIn("mcp__slack__<tool name>", self.fix("mcp__slack"))
        self.assertIn("Edit(src/**)", self.fix("Write"))


class FailOnTests(unittest.TestCase):
    def f(self, level):
        return Finding(level, "rule", "t", "d", "f", "p")

    def test_levels(self):
        self.assertEqual(exit_code([self.f("high")]), 1)
        self.assertEqual(exit_code([self.f("high")], "critical"), 0)
        self.assertEqual(exit_code([self.f("critical")], "critical"), 2)
        self.assertEqual(exit_code([self.f("critical")], "never"), 0)
        self.assertEqual(exit_code([self.f("medium")]), 0)


if __name__ == "__main__":
    unittest.main()
