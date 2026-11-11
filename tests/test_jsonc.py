import json
import tempfile
import unittest
from pathlib import Path

from leash.audit import audit_source
from leash.sources import scan, strip_jsonc


class JsoncTests(unittest.TestCase):
    def test_comments_and_trailing_commas(self):
        text = '''{
  // GitHub server
  "servers": {
    "gh": { "type": "stdio", "command": "npx", /* pinned later */ "args": ["a",], },
  },
}'''
        d = json.loads(strip_jsonc(text))
        self.assertEqual(d["servers"]["gh"]["args"], ["a"])

    def test_slashes_and_commas_inside_strings_are_kept(self):
        text = r'{"url": "https://x.example/a//b", "s": "a, }", "q": "say \"//hi\"",}'
        d = json.loads(strip_jsonc(text))
        self.assertEqual(d["url"], "https://x.example/a//b")
        self.assertEqual(d["s"], "a, }")
        self.assertEqual(d["q"], 'say "//hi"')

    def test_vscode_file_with_comments_is_audited(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "proj" / ".vscode" / "mcp.json"
            p.parent.mkdir(parents=True)
            p.write_text('{\n // token below\n "servers": {"gh": {"env": {"GITHUB_TOKEN": "ghp_' + "g" * 36 + '"},},},\n}')
            src = scan([Path(tmp)], include_user=False).sources[0]
            self.assertIsNone(src.error)
            self.assertEqual([f.kind for f in audit_source(src, use_git=False)], ["secret"])


if __name__ == "__main__":
    unittest.main()
