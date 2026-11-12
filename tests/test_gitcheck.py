import tempfile
import unittest
from pathlib import Path
from unittest import mock

from helpers import commit_all, git, make_repo
from leash import gitcheck


class GithubSlug(unittest.TestCase):
    def test_reads_owner_and_repo_from_every_remote_style(self):
        for remote in (
            "https://github.com/patkusch/leash.git",
            "https://github.com/patkusch/leash",
            "https://github.com/patkusch/leash/",
            "git@github.com:patkusch/leash.git",
            "ssh://git@github.com/patkusch/leash.git",
        ):
            self.assertEqual(gitcheck.github_slug(remote), "patkusch/leash", remote)

    def test_other_hosts_and_empty_remotes_give_nothing(self):
        self.assertIsNone(gitcheck.github_slug("https://gitlab.com/a/b.git"))
        self.assertIsNone(gitcheck.github_slug(""))
        self.assertIsNone(gitcheck.github_slug(None))


class Status(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = make_repo(Path(self._tmp.name) / "r")
        self.addCleanup(self._tmp.cleanup)

    def test_a_folder_that_is_not_a_repo_reports_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            st = gitcheck.status(Path(d) / "settings.json", use_gh=False)
        self.assertIsNone(st.repo)
        self.assertFalse(st.tracked)
        self.assertEqual(st.history_commits, 0)

    def test_committed_file_is_tracked_and_has_history(self):
        f = self.repo / "settings.json"
        f.write_text("{}")
        commit_all(self.repo)
        st = gitcheck.status(f, use_gh=False)
        self.assertEqual(st.repo.resolve(), self.repo.resolve())
        self.assertTrue(st.tracked)
        self.assertFalse(st.ignored)
        self.assertEqual(st.history_commits, 1)

    def test_deleted_file_is_not_tracked_but_history_remembers_it(self):
        f = self.repo / "settings.json"
        f.write_text("{}")
        commit_all(self.repo)
        git(self.repo, "rm", "-q", "settings.json")
        git(self.repo, "commit", "-q", "-m", "gone")
        f.write_text("{}")  # back on disk, untracked
        st = gitcheck.status(f, use_gh=False)
        self.assertFalse(st.tracked)
        self.assertEqual(st.history_commits, 2)

    def test_ignored_file_is_reported_as_ignored(self):
        (self.repo / ".gitignore").write_text("local.json\n")
        f = self.repo / "local.json"
        f.write_text("{}")
        st = gitcheck.status(f, use_gh=False)
        self.assertTrue(st.ignored)
        self.assertFalse(st.tracked)

    def test_remote_is_read_and_visibility_is_asked_only_when_allowed(self):
        repo = make_repo(Path(self._tmp.name) / "withremote", "https://github.com/patkusch/leash.git")
        f = repo / "a.json"
        f.write_text("{}")
        with mock.patch.object(gitcheck, "_gh_visibility", return_value="public") as ask:
            off = gitcheck.status(f, use_gh=False)
            self.assertEqual(off.remote, "https://github.com/patkusch/leash.git")
            self.assertIsNone(off.visibility)
            ask.assert_not_called()
            on = gitcheck.status(f, use_gh=True)
        self.assertEqual(on.visibility, "public")
        ask.assert_called_once_with("patkusch/leash")

    def test_non_github_remote_never_asks_gh(self):
        repo = make_repo(Path(self._tmp.name) / "other", "https://example.com/x/y.git")
        f = repo / "a.json"
        f.write_text("{}")
        with mock.patch.object(gitcheck, "_gh_visibility") as ask:
            st = gitcheck.status(f, use_gh=True)
        ask.assert_not_called()
        self.assertIsNone(st.visibility)


class GhVisibility(unittest.TestCase):
    def setUp(self):
        gitcheck._gh_visibility.cache_clear()
        self.addCleanup(gitcheck._gh_visibility.cache_clear)

    def test_no_gh_installed_means_unknown(self):
        with mock.patch("shutil.which", return_value=None):
            self.assertIsNone(gitcheck._gh_visibility("a/b"))

    def test_answer_is_lowercased_and_odd_answers_are_unknown(self):
        for out, want in (("PUBLIC\n", "public"), ("private\n", "private"), ("weird\n", None)):
            gitcheck._gh_visibility.cache_clear()
            done = mock.Mock(returncode=0, stdout=out)
            with mock.patch("shutil.which", return_value="/usr/bin/gh"), mock.patch("subprocess.run", return_value=done):
                self.assertEqual(gitcheck._gh_visibility("a/b"), want, out)

    def test_gh_failure_means_unknown(self):
        done = mock.Mock(returncode=1, stdout="")
        with mock.patch("shutil.which", return_value="/usr/bin/gh"), mock.patch("subprocess.run", return_value=done):
            self.assertIsNone(gitcheck._gh_visibility("a/b"))


class AddToGitignore(unittest.TestCase):
    def test_creates_the_file_and_does_not_add_twice(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            self.assertTrue(gitcheck.add_to_gitignore(repo))
            self.assertEqual((repo / ".gitignore").read_text(), ".claude/settings.local.json\n")
            self.assertFalse(gitcheck.add_to_gitignore(repo))
            self.assertEqual((repo / ".gitignore").read_text().count("settings.local.json"), 1)

    def test_keeps_existing_lines_and_adds_a_newline_when_missing(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / ".gitignore").write_text("node_modules")
            self.assertTrue(gitcheck.add_to_gitignore(repo, "secret.json"))
            self.assertEqual((repo / ".gitignore").read_text(), "node_modules\nsecret.json\n")


if __name__ == "__main__":
    unittest.main()
