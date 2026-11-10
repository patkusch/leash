import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from helpers import commit_all, git, make_repo, write_json
from leash.audit import audit_history
from leash.cli import main
from leash.history import historical_files, is_agent_file, secrets_in_history

TOKEN = "ghp_" + "c" * 36


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_is_agent_file(self):
        for p in (".mcp.json", "a/.mcp.json", ".claude/settings.local.json", "x/.vscode/mcp.json",
                  ".gemini/settings.json", ".cursor/mcp.json"):
            self.assertTrue(is_agent_file(p), p)
        for p in ("mcp.json", ".claude/agents/x.md", "settings.json", "a/.vscode/settings.json"):
            self.assertFalse(is_agent_file(p), p)

    def test_historical_files_include_deleted_and_nested(self):
        repo = make_repo(self.root / "r")
        write_json(repo / ".mcp.json", {})
        write_json(repo / "sub" / ".claude" / "settings.local.json", {})
        write_json(repo / "other.json", {})
        commit_all(repo)
        git(repo, "rm", "-q", "sub/.claude/settings.local.json")
        commit_all(repo, "remove")
        self.assertEqual(historical_files(repo), [".mcp.json", "sub/.claude/settings.local.json"])

    def test_secret_removed_from_file_is_still_found(self):
        repo = make_repo(self.root / "r")
        local = repo / ".claude" / "settings.local.json"
        write_json(local, {"permissions": {"allow": [f"Bash(curl -H 'Authorization: token {TOKEN}' x:*)"]}})
        commit_all(repo, "one")
        write_json(local, {"permissions": {"allow": []}})
        commit_all(repo, "two")
        old = secrets_in_history(repo, ".claude/settings.local.json")
        self.assertEqual(len(old), 1)
        self.assertEqual(old[0].versions, 1)
        f = audit_history(repo, use_gh=False)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].kind, "history")
        self.assertEqual(f[0].level, "high")          # no remote: may never have left the machine
        self.assertNotIn(TOKEN, f[0].title + f[0].detail)

    def test_remote_makes_it_critical(self):
        repo = make_repo(self.root / "r", remote="https://example.com/x.git")
        write_json(repo / ".mcp.json", {"mcpServers": {"s": {"env": {"T": TOKEN}}}})
        commit_all(repo)
        (repo / ".mcp.json").unlink()
        commit_all(repo, "gone")
        f = audit_history(repo, use_gh=False)
        self.assertEqual([x.level for x in f], ["critical"])

    def test_secret_still_in_file_is_not_reported_twice(self):
        repo = make_repo(self.root / "r")
        write_json(repo / ".mcp.json", {"mcpServers": {"s": {"env": {"T": TOKEN}}}})
        commit_all(repo)
        self.assertEqual(audit_history(repo, use_gh=False), [])

    def test_leashignore_skips_history_unless_asked_for(self):
        repo = make_repo(self.root / "r")
        write_json(repo / "docs" / "ex" / ".mcp.json", {"mcpServers": {"s": {"env": {"T": TOKEN}}}})
        (repo / ".leashignore").write_text("docs/ex\n")
        commit_all(repo)
        write_json(repo / "docs" / "ex" / ".mcp.json", {})
        commit_all(repo, "clean")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main([str(repo), "--no-user", "--no-gh"])
        self.assertEqual(code, 0, out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            code = main([str(repo / "docs" / "ex"), "--no-user", "--no-gh"])
        self.assertEqual(code, 1)                      # asked for by name: not skipped, history found

    def test_no_history_flag(self):
        repo = make_repo(self.root / "r")
        write_json(repo / ".mcp.json", {"mcpServers": {"s": {"env": {"T": TOKEN}}}})
        commit_all(repo)
        write_json(repo / ".mcp.json", {})
        commit_all(repo, "clean")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(repo), "--no-user", "--no-gh", "--no-history"]), 0)
            self.assertEqual(main([str(repo), "--no-user", "--no-gh"]), 1)


if __name__ == "__main__":
    unittest.main()
