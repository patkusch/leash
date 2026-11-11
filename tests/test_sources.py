import tempfile
import unittest
from pathlib import Path

from helpers import write_json
from leash.sources import discover, find_projects, user_sources


class FindProjectsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_finds_claude_folders_and_mcp_files(self):
        write_json(self.root / "a" / ".claude" / "settings.local.json", {})
        write_json(self.root / "b" / "deep" / ".mcp.json", {})
        write_json(self.root / "c" / "node_modules" / "x" / ".claude" / "settings.json", {})   # skipped
        write_json(self.root / "d" / ".git" / ".claude" / "settings.json", {})                 # skipped
        found = find_projects([self.root])
        self.assertEqual(sorted(p.name for p in found), ["a", "deep"])

    def test_discover_reads_each_file_with_its_kind(self):
        write_json(self.root / "a" / ".claude" / "settings.json", {"permissions": {"allow": ["Bash(ls:*)"]}})
        write_json(self.root / "a" / ".claude" / "settings.local.json", {"permissions": {"allow": ["Bash"]}})
        write_json(self.root / "a" / ".mcp.json", {"mcpServers": {}})
        srcs = discover([self.root], include_user=False)
        kinds = sorted(s.kind for s in srcs)
        self.assertEqual(kinds, ["claude-local", "claude-mcp", "claude-project"])
        local = next(s for s in srcs if s.kind == "claude-local")
        self.assertEqual(local.data["permissions"]["allow"], ["Bash"])
        self.assertFalse(local.shared)
        self.assertEqual(local.project, (self.root / "a").resolve())

    def test_broken_json_is_reported_not_raised(self):
        p = self.root / "a" / ".claude" / "settings.local.json"
        p.parent.mkdir(parents=True)
        p.write_text("{ not json", encoding="utf-8")
        srcs = discover([self.root], include_user=False)
        self.assertEqual(len(srcs), 1)
        self.assertIn("could not read", srcs[0].error)

    def test_user_sources_from_a_fake_home(self):
        home = self.root / "home"
        write_json(home / ".claude" / "settings.json", {"permissions": {"allow": ["WebFetch"]}})
        write_json(home / ".claude.json", {"projects": {}})
        (home / ".codex").mkdir()
        (home / ".codex" / "config.toml").write_text('approval_policy = "never"\n', encoding="utf-8")
        srcs = user_sources(home)
        kinds = sorted(s.kind for s in srcs if s.kind != "claude-managed")
        self.assertEqual(kinds, ["claude-global", "claude-user", "codex"])
        codex = next(s for s in srcs if s.kind == "codex")
        self.assertEqual(codex.data["approval_policy"], "never")


if __name__ == "__main__":
    unittest.main()


class OversizeTests(unittest.TestCase):
    def test_oversized_file_is_skipped_and_reported(self):
        from unittest import mock

        from leash import sources
        from leash.audit import audit_source
        with tempfile.TemporaryDirectory() as tmp:
            p = write_json(Path(tmp) / "p" / ".claude" / "settings.local.json",
                           {"permissions": {"allow": ["Bash"]}})
            with mock.patch.object(sources, "MAX_SETTINGS_BYTES", 10):
                src = discover([Path(tmp)], include_user=False)[0]
            self.assertTrue(src.error.startswith("skipped"))
            self.assertEqual(src.data, {})
            f = audit_source(src, use_git=False)
            self.assertEqual([x.level for x in f], ["info"])
            self.assertIn("was not checked", f[0].title)
            self.assertTrue(p.exists())
