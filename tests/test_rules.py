import unittest

from leash.rules import grade, grade_mode, parse


class ParseTests(unittest.TestCase):
    def test_tool_only(self):
        r = parse("Bash")
        self.assertEqual((r.tool, r.spec, r.is_prefix), ("Bash", None, False))

    def test_prefix(self):
        r = parse("Bash(git push:*)")
        self.assertEqual((r.tool, r.spec, r.is_prefix, r.command), ("Bash", "git push:*", True, "git push"))

    def test_exact(self):
        r = parse("Bash(npm test)")
        self.assertEqual((r.is_prefix, r.command), (False, "npm test"))

    def test_mcp(self):
        self.assertEqual(parse("mcp__slack__send_message").tool, "mcp__slack__send_message")


class GradeTests(unittest.TestCase):
    def level(self, raw):
        return grade(raw).level

    def test_bare_bash_is_critical(self):
        for raw in ("Bash", "Bash(*)", "Bash(*:*)", "Bash(:*)"):
            self.assertEqual(self.level(raw), "critical", raw)

    def test_send_is_high(self):
        for raw in ("Bash(git push:*)", "Bash(curl:*)", "Bash(gh pr create:*)", "Bash(scp:*)", "Bash(aws s3:*)"):
            self.assertEqual(self.level(raw), "high", raw)

    def test_destroy_is_high(self):
        for raw in ("Bash(rm:*)", "Bash(rm -rf node_modules)", "Bash(sudo:*)", "Bash(git reset --hard:*)"):
            self.assertEqual(self.level(raw), "high", raw)

    def test_interpreters_are_high(self):
        for raw in ("Bash(python:*)", "Bash(node -e:*)", "Bash(bash:*)", "Bash(sshpass:*)", "Bash(xargs:*)"):
            self.assertEqual(self.level(raw), "high", raw)

    def test_force_push_is_high_with_its_own_reason(self):
        g = grade("Bash(git push --force:*)")
        self.assertEqual(g.level, "high")
        self.assertIn("forced push", g.why)

    def test_history_is_medium(self):
        for raw in ("Bash(git commit:*)", "Bash(git add:*)", "Bash(git commit -m 'x')"):
            self.assertEqual(self.level(raw), "medium", raw)

    def test_scripts_are_medium(self):
        for raw in ("Bash(npm install:*)", "Bash(npx:*)", "Bash(make:*)", "Bash(pip install:*)"):
            self.assertEqual(self.level(raw), "medium", raw)

    def test_database_is_medium(self):
        self.assertEqual(self.level("Bash(psql -h db:*)"), "medium")
        self.assertIn("database", grade("Bash(psql -h db:*)").why)

    def test_env_prefix_is_skipped_for_the_command(self):
        g = grade("Bash(PGPASSWORD=hunter2secret psql -h db:*)")
        self.assertEqual(g.level, "medium")
        self.assertTrue(g.what.startswith("run any command that starts with `psql"), g.what)
        self.assertNotIn("hunter2secret", g.what)
        self.assertNotIn("hunter2secret", g.why)

    def test_read_only_is_low(self):
        for raw in ("Bash(ls:*)", "Bash(git status)", "Bash(npm test:*)", "Bash(pytest:*)", "Bash(cat:*)",
                    "Bash(git log:*)", "Bash(git diff:*)"):
            self.assertEqual(self.level(raw), "low", raw)

    def test_prefix_does_not_match_partial_words(self):
        # "git logs-upload" is not "git log"
        self.assertNotEqual(self.level("Bash(git logs-upload:*)"), "low")
        self.assertNotEqual(self.level("Bash(lsof:*)"), "low")

    def test_wildcard_right_after_the_command_is_high(self):
        self.assertEqual(self.level("Bash(git *:*)"), "high")
        self.assertEqual(self.level("Bash(npm *)"), "high")

    def test_wildcard_later_in_the_command_keeps_the_category(self):
        g = grade('Bash(psql -c "select count(*) from t":*)')
        self.assertEqual(g.level, "medium")
        self.assertIn("database", g.why)
        self.assertIn("wildcard", g.why)
        self.assertEqual(self.level("Bash(ls *.py)"), "medium")   # low, raised one step by the wildcard

    def test_unknown_command_is_medium(self):
        self.assertEqual(self.level("Bash(frobnicate:*)"), "medium")

    def test_long_command_is_shortened_in_what(self):
        self.assertLessEqual(len(grade("Bash(" + "a" * 200 + ":*)").what), 120)

    def test_write_tools(self):
        self.assertEqual(self.level("Write"), "medium")
        self.assertEqual(self.level("Edit(src/**)"), "low")
        self.assertEqual(self.level("Edit(~/.ssh/config)"), "high")
        self.assertEqual(self.level("Write(/etc/hosts)"), "high")

    def test_read_tools(self):
        self.assertEqual(self.level("Read"), "low")
        self.assertEqual(self.level("Read(~/.aws/**)"), "high")
        self.assertEqual(self.level("Read(.env)"), "high")
        self.assertEqual(self.level("Read(/var/log/**)"), "medium")
        self.assertEqual(self.level("Glob(src/**)"), "low")

    def test_web(self):
        self.assertEqual(self.level("WebFetch"), "medium")
        self.assertEqual(self.level("WebFetch(domain:docs.python.org)"), "low")
        self.assertEqual(self.level("WebSearch"), "medium")

    def test_mcp(self):
        self.assertEqual(self.level("mcp__slack"), "medium")
        self.assertEqual(self.level("mcp__slack__list_channels"), "low")
        self.assertEqual(self.level("mcp__slack__send_message"), "medium")
        self.assertEqual(self.level("mcp__github__create_pull_request"), "medium")

    def test_housekeeping_is_low(self):
        for raw in ("TodoWrite", "AskUserQuestion", "ExitPlanMode"):
            self.assertEqual(self.level(raw), "low", raw)

    def test_unknown_tool_is_medium(self):
        self.assertEqual(self.level("Teleport"), "medium")


class ModeTests(unittest.TestCase):
    def test_modes(self):
        self.assertIsNone(grade_mode(None))
        self.assertIsNone(grade_mode("default"))
        self.assertIsNone(grade_mode("plan"))
        self.assertEqual(grade_mode("bypassPermissions").level, "critical")
        self.assertEqual(grade_mode("dontAsk").level, "high")
        self.assertEqual(grade_mode("acceptEdits").level, "medium")


if __name__ == "__main__":
    unittest.main()
