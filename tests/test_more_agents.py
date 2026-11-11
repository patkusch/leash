import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from helpers import write_json
from leash.audit import audit_source
from leash.sources import Source, app_support, scan

TOKEN = "ghp_" + "h" * 36


class MoreAgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def kinds(self):
        return sorted(s.kind for s in scan([], include_user=True, home=self.home).sources
                      if s.kind != "claude-managed")

    def test_finds_desktop_windsurf_cline_roo_and_vscode_user(self):
        with mock.patch.object(sys, "platform", "darwin"):
            sup = app_support(self.home)
            ext = sup / "Code" / "User" / "globalStorage"
            write_json(sup / "Claude" / "claude_desktop_config.json", {"mcpServers": {}})
            write_json(sup / "Code" / "User" / "mcp.json", {"servers": {}})
            write_json(self.home / ".codeium" / "windsurf" / "mcp_config.json", {"mcpServers": {}})
            write_json(ext / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json", {"mcpServers": {}})
            write_json(ext / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json", {"mcpServers": {}})
            self.assertEqual(self.kinds(), ["claude-desktop", "cline-mcp", "roo-mcp", "vscode-mcp", "windsurf-mcp"])

    def test_app_support_per_platform(self):
        with mock.patch.object(sys, "platform", "linux"), mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(app_support(self.home), self.home / ".config")
        with mock.patch.object(sys, "platform", "darwin"):
            self.assertEqual(app_support(self.home), self.home / "Library" / "Application Support")

    def test_desktop_token_is_found(self):
        src = Source(Path("/x"), "claude-desktop", "Claude Desktop", None, False,
                     {"mcpServers": {"gh": {"command": "npx", "env": {"GITHUB_TOKEN": TOKEN}}}})
        f = audit_source(src, use_git=False)
        self.assertEqual([x.kind for x in f], ["secret"])
        self.assertIn("Claude Desktop", f[0].detail)

    def test_auto_approve_lists(self):
        src = Source(Path("/x"), "cline-mcp", "Cline", None, False, {"mcpServers": {
            "gh": {"autoApprove": ["list_issues", "create_pull_request", "push_files"]},
            "fs": {"alwaysAllow": ["read_file", "write_file"]},
            "off": {"disabled": True, "autoApprove": ["delete_everything"]},
        }})
        f = audit_source(src, use_git=False)
        levels = {x.rule.split(": ")[1]: x.level for x in f}
        self.assertEqual(levels, {"list_issues": "low", "create_pull_request": "medium", "push_files": "medium",
                                  "read_file": "low", "write_file": "medium"})


if __name__ == "__main__":
    unittest.main()
