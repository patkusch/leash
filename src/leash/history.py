"""Look through git history for agent permission files and the secrets in their old versions.

Deleting a secret from a committed file does not remove it: every old commit still has it,
and so does every clone and fork made since. This module reads those old versions.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .secrets import find_secrets

AGENT_FILES = (".claude/settings.local.json", ".claude/settings.json", ".mcp.json", ".cursor/mcp.json",
               ".vscode/mcp.json", ".gemini/settings.json")
MAX_VERSIONS = 200


def _git(args: list[str], cwd: Path, timeout: int = 30) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, errors="replace",
                              timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def is_agent_file(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    return any(rel == n or rel.endswith("/" + n) for n in AGENT_FILES)


def is_local_file(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    return rel == ".claude/settings.local.json" or rel.endswith("/.claude/settings.local.json")


def historical_files(repo: Path) -> list[str]:
    """Every agent permission file that any commit on any branch ever touched (paths relative to repo)."""
    r = _git(["log", "--all", "--format=", "--name-only", "--", *[f":(glob)**/{n}" for n in AGENT_FILES]], repo)
    if not r or r.returncode != 0:
        return []
    return sorted({ln.strip() for ln in r.stdout.splitlines() if ln.strip() and is_agent_file(ln.strip())})


@dataclass
class OldSecret:
    kind: str
    masked: str
    first_commit: str   # oldest commit that has it
    last_commit: str    # newest commit that has it
    versions: int       # how many saved versions hold it


def secrets_in_history(repo: Path, rel: str) -> list[OldSecret]:
    r = _git(["log", "--all", "--format=%h", "--", rel], repo)
    if not r or r.returncode != 0:
        return []
    commits = [c for c in r.stdout.split() if c][:MAX_VERSIONS]   # newest first
    found: dict[tuple[str, str], OldSecret] = {}
    for c in commits:
        s = _git(["show", f"{c}:{rel}"], repo)
        if not s or s.returncode != 0:      # the commit that deleted the file
            continue
        for sec in find_secrets(s.stdout):
            key = (sec.kind, sec.masked)
            if key in found:
                found[key].first_commit = c
                found[key].versions += 1
            else:
                found[key] = OldSecret(sec.kind, sec.masked, c, c, 1)
    return list(found.values())


def staged_agent_files(repo: Path) -> list[str]:
    r = _git(["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"], repo)
    if not r or r.returncode != 0:
        return []
    return [p for p in r.stdout.split("\0") if p and is_agent_file(p)]


def staged_text(repo: Path, rel: str) -> str:
    r = _git(["show", f":{rel}"], repo)
    return r.stdout if r and r.returncode == 0 else ""
