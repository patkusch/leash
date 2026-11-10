"""Install leash as a git pre-commit hook."""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

MARK = "leash --staged"
HOOK = """#!/bin/sh
# leash: stop agent permission files, and the secrets in them, from being committed.
# Remove this file to turn the check off. Skip it once with: git commit --no-verify
if command -v leash >/dev/null 2>&1; then
  exec leash --staged
fi
echo "leash is not installed, so the agent-permission check was skipped" >&2
exit 0
"""


class HookExists(Exception):
    pass


def hook_path(repo: Path) -> Path:
    r = subprocess.run(["git", "config", "core.hooksPath"], cwd=repo, capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        base = Path(r.stdout.strip()).expanduser()
        return (base if base.is_absolute() else repo / base) / "pre-commit"
    r = subprocess.run(["git", "rev-parse", "--git-path", "hooks/pre-commit"], cwd=repo, capture_output=True,
                       text=True, check=True)
    p = Path(r.stdout.strip())
    return p if p.is_absolute() else repo / p


def install(repo: Path) -> str:
    path = hook_path(repo)
    if path.exists():
        if MARK in path.read_text(encoding="utf-8", errors="replace"):
            return f"leash is already the pre-commit hook in {path}"
        raise HookExists(f"{path} already exists and is not leash's. Add this line to it instead:\n    {MARK}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(HOOK, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return f"installed the pre-commit hook: {path}"
