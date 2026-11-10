"""Ask git where a permission file stands: tracked, ignored, in history, on a public remote."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass
class GitStatus:
    repo: Path | None = None       # repo root, or None when not in a git repo
    tracked: bool = False          # committed and still tracked
    ignored: bool = False          # matched by .gitignore
    history_commits: int = 0       # commits (any branch) that touched the file, even if since deleted
    remote: str | None = None      # origin URL
    visibility: str | None = None  # "public", "private", or None when unknown


def _git(args: list[str], cwd: Path, timeout: int = 10) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def repo_root(folder: Path) -> Path | None:
    r = _git(["rev-parse", "--show-toplevel"], folder)
    if r and r.returncode == 0:
        return Path(r.stdout.strip())
    return None


def github_slug(remote: str | None) -> str | None:
    if not remote:
        return None
    m = re.search(r"github\.com[:/]([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", remote)
    return f"{m.group(1)}/{m.group(2)}" if m else None


@lru_cache(maxsize=None)
def _gh_visibility(slug: str) -> str | None:
    if not shutil.which("gh"):
        return None
    try:
        r = subprocess.run(["gh", "repo", "view", slug, "--json", "visibility", "--jq", ".visibility"],
                           capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    v = r.stdout.strip().lower()
    return v if v in ("public", "private", "internal") else None


def status(path: Path, use_gh: bool = True) -> GitStatus:
    st = GitStatus()
    folder = path.parent if path.is_file() else path
    root = repo_root(folder)
    if root is None:
        return st
    st.repo = root
    try:
        rel = str(path.resolve().relative_to(root))
    except ValueError:
        return st
    r = _git(["ls-files", "--error-unmatch", "--", rel], root)
    st.tracked = bool(r and r.returncode == 0)
    r = _git(["check-ignore", "-q", "--", rel], root)
    st.ignored = bool(r and r.returncode == 0)
    r = _git(["log", "--all", "--format=%h", "--", rel], root)
    if r and r.returncode == 0:
        st.history_commits = len([ln for ln in r.stdout.splitlines() if ln.strip()])
    r = _git(["remote", "get-url", "origin"], root)
    if r and r.returncode == 0:
        st.remote = r.stdout.strip() or None
    if use_gh:
        slug = github_slug(st.remote)
        if slug:
            st.visibility = _gh_visibility(slug)
    return st


def add_to_gitignore(repo: Path, line: str = ".claude/settings.local.json") -> bool:
    """Append a line to the repo's .gitignore unless it is already there. Returns True if written."""
    gi = repo / ".gitignore"
    existing = gi.read_text(encoding="utf-8") if gi.exists() else ""
    if any(ln.strip() == line for ln in existing.splitlines()):
        return False
    sep = "" if (not existing or existing.endswith("\n")) else "\n"
    gi.write_text(existing + sep + line + "\n", encoding="utf-8")
    return True
