import tempfile
import unittest
from pathlib import Path

from helpers import commit_all, git, make_repo, write_json
from leash.audit import audit_source, exit_code
from leash.sources import Source, discover, user_sources


def by_kind(findings, kind):
    return [f for f in findings if f.kind == kind]


class PermissionAuditTests(unittest.TestCase):
    def src(self, data, kind="claude-local", shared=False):
        return Source(Path("/x/.claude/settings.local.json"), kind, "Claude Code", Path("/x"), shared, data)

    def test_secret_in_allow_rule_is_critical_and_masked(self):
        f = audit_source(self.src({"permissions": {"allow": ["Bash(PGPASSWORD=hunter2secret psql -h db:*)"]}}),
                         use_git=False)
        secrets = by_kind(f, "secret")
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0].level, "critical")
        self.assertIn("don't ask again", secrets[0].title)
        for x in f:
            for text in (x.title, x.detail, x.fix, x.rule or ""):
                self.assertNotIn("hunter2secret", text)

    def test_every_allow_rule_gets_a_graded_finding(self):
        f = audit_source(self.src({"permissions": {"allow": ["Bash(git push:*)", "Bash(ls:*)", "Bash"]}}),
                         use_git=False)
        rules = by_kind(f, "rule")
        self.assertEqual(sorted(r.level for r in rules), ["critical", "high", "low"])

    def test_bypass_mode_in_local_file_is_medium(self):
        # current Claude Code ignores bypassPermissions in project and local files
        f = audit_source(self.src({"permissions": {"defaultMode": "bypassPermissions"}}), use_git=False)
        self.assertEqual([x.level for x in by_kind(f, "mode")], ["medium"])

    def test_deny_rules_are_reported_as_info(self):
        f = audit_source(self.src({"permissions": {"deny": ["Bash(rm:*)", "Read(.env)"]}}), use_git=False)
        self.assertEqual([x.level for x in by_kind(f, "rule")], ["info"])

    def test_env_block_secret(self):
        f = audit_source(self.src({"env": {"ANTHROPIC_API_KEY": "sk-ant-" + "a" * 30, "FOO": "bar"}}), use_git=False)
        s = by_kind(f, "secret")
        self.assertEqual(len(s), 1)
        self.assertIn("env", s[0].title)

    def test_mcp_env_and_header_secrets(self):
        f = audit_source(self.src({"mcpServers": {
            "gh": {"command": "x", "env": {"GITHUB_TOKEN": "ghp_" + "a" * 36}},
            "api": {"url": "https://x", "headers": {"Authorization": "Bearer abcdefghijklmnop"}},
            "ok": {"command": "x", "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
        }}, kind="claude-mcp", shared=True), use_git=False)
        s = by_kind(f, "secret")
        self.assertEqual(len(s), 2)
        self.assertTrue(all("committed and shared" in x.detail for x in s))

    def test_clean_file_has_no_findings(self):
        self.assertEqual(audit_source(self.src({"permissions": {"allow": []}}), use_git=False), [])


class GlobalAndCodexTests(unittest.TestCase):
    def test_global_allowed_tools(self):
        src = Source(Path("/h/.claude.json"), "claude-global", "Claude Code", None, False,
                     {"projects": {"/p": {"allowedTools": ["Bash(git push:*)"], "mcpServers": {
                         "s": {"env": {"TOKEN": "xoxb-" + "1" * 12}}}}}})
        f = audit_source(src, use_git=False)
        self.assertEqual([x.level for x in by_kind(f, "rule")], ["high"])
        self.assertEqual(by_kind(f, "rule")[0].project, "/p")
        self.assertEqual(len(by_kind(f, "secret")), 1)

    def test_codex(self):
        src = Source(Path("/h/.codex/config.toml"), "codex", "Codex CLI", None, False,
                     {"approval_policy": "never", "sandbox_mode": "danger-full-access"})
        f = audit_source(src, use_git=False)
        self.assertEqual([x.level for x in f], ["critical", "critical"])
        src.data = {"approval_policy": "on-request", "sandbox_mode": "workspace-write",
                    "sandbox_workspace_write": {"network_access": True}}
        f = audit_source(src, use_git=False)
        self.assertEqual([x.level for x in f], ["high"])


class GitAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def local(self, repo, data):
        return write_json(repo / ".claude" / "settings.local.json", data)

    def run_audit(self, repo):
        out = []
        for s in discover([repo], include_user=False):
            out.extend(audit_source(s, use_git=True, use_gh=False))
        return out

    def test_not_ignored_is_medium(self):
        repo = make_repo(self.root / "r")
        self.local(repo, {"permissions": {"allow": ["Bash(ls:*)"]}})
        g = by_kind(self.run_audit(repo), "git")
        self.assertEqual([x.level for x in g], ["medium"])
        self.assertIn("not ignored", g[0].title)

    def test_ignored_is_info(self):
        repo = make_repo(self.root / "r")
        (repo / ".gitignore").write_text(".claude/settings.local.json\n")
        self.local(repo, {"permissions": {"allow": ["Bash(ls:*)"]}})
        g = by_kind(self.run_audit(repo), "git")
        self.assertEqual([x.level for x in g], ["info"])

    def test_tracked_is_high_or_critical(self):
        repo = make_repo(self.root / "r", remote="https://github.com/someone/thing.git")
        self.local(repo, {"permissions": {"allow": ["Bash(ls:*)"]}})
        commit_all(repo)
        g = by_kind(self.run_audit(repo), "git")
        self.assertEqual([x.level for x in g], ["high"])
        self.assertIn("committed", g[0].title)
        # with a secret inside, it is critical even when visibility is unknown
        self.local(repo, {"permissions": {"allow": ["Bash(sshpass -p S3cretPass ssh host:*)"]}})
        commit_all(repo)
        f = self.run_audit(repo)
        self.assertEqual([x.level for x in by_kind(f, "git")], ["critical"])
        self.assertEqual(exit_code(f), 2)

    def test_deleted_but_in_history_is_high(self):
        repo = make_repo(self.root / "r")
        self.local(repo, {"permissions": {"allow": ["Bash(ls:*)"]}})
        commit_all(repo)
        git(repo, "rm", "-q", "--cached", ".claude/settings.local.json")
        (repo / ".gitignore").write_text(".claude/settings.local.json\n")
        commit_all(repo, "untrack")
        g = by_kind(self.run_audit(repo), "git")
        self.assertEqual([x.level for x in g], ["high"])
        self.assertIn("still in", g[0].title)

    def test_shared_file_with_secret_in_history_is_critical(self):
        repo = make_repo(self.root / "r")
        write_json(repo / ".mcp.json", {"mcpServers": {"s": {"env": {"TOKEN": "ghp_" + "b" * 36}}}})
        commit_all(repo)
        f = self.run_audit(repo)
        self.assertEqual([x.level for x in by_kind(f, "git")], ["critical"])

    def test_outside_git_has_no_git_findings(self):
        proj = self.root / "p"
        self.local(proj, {"permissions": {"allow": ["Bash(ls:*)"]}})
        self.assertEqual(by_kind(self.run_audit(proj), "git"), [])


if __name__ == "__main__":
    unittest.main()
