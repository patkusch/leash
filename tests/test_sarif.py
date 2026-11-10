import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from helpers import write_json
from leash.cli import main


class SarifTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.cwd = os.getcwd()
        os.chdir(self.root)

    def tearDown(self):
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def run_sarif(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["proj", "--no-user", "--no-git", "--sarif"])
        return code, json.loads(out.getvalue())

    def test_sarif_shape_lines_and_masking(self):
        write_json(self.root / "proj" / ".claude" / "settings.local.json", {"permissions": {"allow": [
            "Bash(ls:*)", "Bash(git push:*)", "Bash(PGPASSWORD=hunter2secret psql:*)"]}})
        code, d = self.run_sarif()
        self.assertEqual(code, 2)
        self.assertEqual(d["version"], "2.1.0")
        run = d["runs"][0]
        ids = sorted(r["ruleId"] for r in run["results"])
        self.assertEqual(ids, ["leash/rule/high", "leash/rule/medium", "leash/secret/critical"])   # low left out
        self.assertNotIn("hunter2secret", json.dumps(d))
        loc = run["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "proj/.claude/settings.local.json")
        lines = {r["ruleId"]: r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in run["results"]}
        self.assertEqual(lines["leash/rule/high"], 5)          # the line where Bash(git push:*) is
        sev = {r["id"]: r["properties"]["security-severity"] for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(sev["leash/secret/critical"], "9.5")

    def test_clean_project_gives_empty_results(self):
        write_json(self.root / "proj" / ".claude" / "settings.local.json", {"permissions": {"allow": ["Bash(ls:*)"]}})
        code, d = self.run_sarif()
        self.assertEqual((code, d["runs"][0]["results"]), (0, []))


if __name__ == "__main__":
    unittest.main()
