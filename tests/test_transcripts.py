import tempfile
import unittest
from pathlib import Path

from helpers import commit_all, git, make_repo
from leash.audit import audit_history, audit_source, audit_staged, sort_findings
from leash.history import is_agent_file
from leash.sources import scan

CHAT = """# Session

_**User**_
connect to the db

_**Assistant**_
```bash
PGPASSWORD=Wint3rIsComing psql -h db.internal -U app
```
and again: PGPASSWORD=Wint3rIsComing psql -h db.internal -U app
"""


class TranscriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, base, name="2026-11-10_chat.md", text=CHAT):
        p = base / ".specstory" / "history" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        (base / ".specstory" / ".what-is-this.md").write_text("SpecStory folder")
        return p

    def audit(self, roots):
        out = []
        for s in scan(roots, include_user=False).sources:
            out.extend(audit_source(s, use_git=True, use_gh=False))
        return sort_findings(out)

    def test_is_agent_file(self):
        self.assertTrue(is_agent_file(".specstory/history/a.md"))
        self.assertTrue(is_agent_file("x/.specstory/history/a.md"))
        self.assertFalse(is_agent_file(".specstory/.what-is-this.md"))
        self.assertFalse(is_agent_file("docs/specstory.md"))

    def test_secret_found_once_with_line_and_masked(self):
        self.write(self.root / "p")
        f = [x for x in self.audit([self.root]) if x.kind == "secret"]
        self.assertEqual(len(f), 1)
        self.assertIn("(line 8)", f[0].title)
        self.assertNotIn("Wint3rIsComing", f[0].title + f[0].detail)

    def test_not_ignored_note_appears_once_per_project(self):
        repo = make_repo(self.root / "r")
        self.write(repo, "a.md", "nothing secret")
        self.write(repo, "b.md", "nothing secret either")
        g = [x for x in self.audit([repo]) if x.kind == "git"]
        self.assertEqual([x.level for x in g], ["medium"])
        self.assertIn("does not ignore", g[0].title)

    def test_ignored_folder_is_quiet(self):
        repo = make_repo(self.root / "r")
        (repo / ".gitignore").write_text(".specstory/\n")
        self.write(repo, "a.md", "nothing secret")
        self.assertEqual(self.audit([repo]), [])

    def test_committed_transcript_with_secret_is_critical(self):
        repo = make_repo(self.root / "r")
        self.write(repo)
        commit_all(repo)
        g = [x for x in self.audit([repo]) if x.kind == "git"]
        self.assertEqual([x.level for x in g], ["critical"])

    def test_deleted_transcript_secret_is_found_in_history(self):
        repo = make_repo(self.root / "r", remote="https://example.com/x.git")
        self.write(repo)
        commit_all(repo)
        git(repo, "rm", "-q", "-r", ".specstory")
        commit_all(repo, "remove chats")
        h = audit_history(repo, use_gh=False)
        self.assertEqual([x.level for x in h], ["critical"])
        self.assertIn(".specstory/history/2026-11-10_chat.md", h[0].title)

    def test_staged_transcript_with_secret_is_stopped(self):
        repo = make_repo(self.root / "r")
        self.write(repo)
        git(repo, "add", "-A")
        findings, n = audit_staged(repo)
        self.assertEqual(n, 1)
        self.assertEqual([x.kind for x in findings], ["secret"])


if __name__ == "__main__":
    unittest.main()
