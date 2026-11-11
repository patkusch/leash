import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from helpers import write_json
from leash.audit import Finding
from leash.cli import main
from leash.report import as_markdown


class MarkdownTests(unittest.TestCase):
    def test_table_escapes_pipes_and_hides_low(self):
        f = [Finding("high", "rule", "may run `a | b`", "why\nnext", "fix it", "/x/p/f.json"),
             Finding("low", "rule", "may run `ls`", "", "Nothing to do.", "/x/p/f.json")]
        md = as_markdown(f, 1, base=Path("/x"))
        self.assertIn("| 🟠 high | may run `a \\| b`<br><sub>why next</sub> | `p/f.json` | fix it |", md)
        self.assertIn("1 low finding(s) not shown.", md)
        self.assertNotIn("`ls`", md)

    def test_clean(self):
        self.assertIn("No standing permissions", as_markdown([], 2))

    def test_cli_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_json(Path(tmp) / "p" / ".claude" / "settings.local.json", {"permissions": {"allow": ["Bash(git push:*)"]}})
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    main(["p", "--no-user", "--no-git", "--markdown"])
            finally:
                os.chdir(cwd)
        self.assertTrue(out.getvalue().startswith("## leash"))
        self.assertIn("`p/.claude/settings.local.json`", out.getvalue())


if __name__ == "__main__":
    unittest.main()
