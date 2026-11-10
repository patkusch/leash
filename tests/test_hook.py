import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from helpers import git, make_repo, write_json
from leash.audit import audit_staged
from leash.cli import main
from leash.hook import MARK, HookExists, install


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class StagedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = make_repo(Path(self.tmp.name) / "r")

    def tearDown(self):
        self.tmp.cleanup()

    def test_staging_the_local_file_is_stopped(self):
        write_json(self.repo / ".claude" / "settings.local.json", {"permissions": {"allow": ["Bash(ls:*)"]}})
        git(self.repo, "add", "-A")
        findings, n = audit_staged(self.repo)
        self.assertEqual(n, 1)
        self.assertEqual([f.level for f in findings], ["critical"])
        code, out, _ = run(str(self.repo), "--staged")
        self.assertEqual(code, 2)
        self.assertIn("Commit stopped", out)

    def test_secret_in_staged_mcp_file_is_stopped(self):
        write_json(self.repo / ".mcp.json", {"mcpServers": {"s": {"env": {"T": "ghp_" + "d" * 36}}}})
        git(self.repo, "add", "-A")
        findings, _ = audit_staged(self.repo)
        self.assertEqual([f.kind for f in findings], ["secret"])

    def test_staged_version_is_checked_not_the_working_copy(self):
        write_json(self.repo / ".mcp.json", {"mcpServers": {"s": {"env": {"T": "ghp_" + "d" * 36}}}})
        git(self.repo, "add", "-A")
        write_json(self.repo / ".mcp.json", {})       # fixed on disk but not re-staged
        findings, _ = audit_staged(self.repo)
        self.assertEqual(len(findings), 1)

    def test_clean_commit_passes_quietly(self):
        write_json(self.repo / ".mcp.json", {"mcpServers": {"s": {"env": {"T": "${TOKEN}"}}}})
        (self.repo / "README.md").write_text("hi")
        git(self.repo, "add", "-A")
        code, out, _ = run(str(self.repo), "--staged")
        self.assertEqual((code, out), (0, ""))

    def test_not_a_repo(self):
        code, _, err = run(self.tmp.name, "--staged")
        self.assertEqual(code, 3)
        self.assertIn("not inside a git repo", err)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = make_repo(Path(self.tmp.name) / "r")

    def tearDown(self):
        self.tmp.cleanup()

    def test_install_writes_an_executable_hook_once(self):
        msg = install(self.repo)
        hook = self.repo / ".git" / "hooks" / "pre-commit"
        self.assertIn("installed", msg)
        self.assertIn(MARK, hook.read_text())
        self.assertTrue(os.access(hook, os.X_OK))
        self.assertIn("already", install(self.repo))

    def test_install_will_not_overwrite_another_hook(self):
        hook = self.repo / ".git" / "hooks" / "pre-commit"
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text("#!/bin/sh\nrun-other-thing\n")
        with self.assertRaises(HookExists):
            install(self.repo)
        self.assertEqual(hook.read_text(), "#!/bin/sh\nrun-other-thing\n")
        code, _, err = run(str(self.repo), "--install-hook")
        self.assertEqual(code, 3)
        self.assertIn(MARK, err)

    def test_install_respects_core_hooks_path(self):
        git(self.repo, "config", "core.hooksPath", ".githooks")
        install(self.repo)
        self.assertTrue((self.repo / ".githooks" / "pre-commit").exists())


if __name__ == "__main__":
    unittest.main()
