"""How often each standing rule was actually used, from Claude Code's own session logs.

Claude Code keeps a log of every session in ~/.claude/projects/<folder>/<session>.jsonl.
Each tool call the agent made is a line there, with the folder it ran in and the time.
leash reads those lines on your machine only, and keeps nothing.

A rule that was never used costs nothing to remove. A wide rule that is used a lot is
worth replacing with the few exact commands it was actually used for.
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .rules import Rule, parse

_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")
_ENV = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)+")


@dataclass(frozen=True)
class Use:
    tool: str
    command: str | None
    cwd: str | None


def default_log_dir() -> Path:
    return Path.home() / ".claude" / "projects"


def _when(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def read_uses(log_dir: Path, days: int, now: datetime | None = None) -> tuple[list[Use], int]:
    """Every tool call in sessions from the last `days` days, and how many session files were read."""
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    uses: list[Use] = []
    files = 0
    if not log_dir.is_dir():
        return uses, 0
    for path in log_dir.rglob("*.jsonl"):
        try:
            if datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) < since:
                continue
            fh = path.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files += 1
        with fh:
            for line in fh:
                if '"tool_use"' not in line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                t = _when(d.get("timestamp"))
                if d.get("type") != "assistant" or (t is not None and t < since):
                    continue
                m = d.get("message")
                content = m.get("content") if isinstance(m, dict) else None
                for c in content if isinstance(content, list) else []:
                    if isinstance(c, dict) and c.get("type") == "tool_use" and isinstance(c.get("name"), str):
                        inp = c.get("input") if isinstance(c.get("input"), dict) else {}
                        cmd = inp.get("command") if isinstance(inp.get("command"), str) else None
                        uses.append(Use(c["name"], cmd, d.get("cwd") if isinstance(d.get("cwd"), str) else None))
    return uses, files


def _parts(command: str) -> list[str]:
    parts = [p.strip() for p in _SPLIT.split(command) if p.strip()]
    return [_ENV.sub("", p) for p in parts] + [p for p in parts if _ENV.match(p)]


def matches(rule: Rule, use: Use) -> bool | None:
    """True or False when leash can tell whether this tool call fell under the rule, None when it cannot."""
    if rule.tool == "Bash":
        if use.tool != "Bash" or not use.command:
            return False
        spec = (rule.spec or "").strip()
        if spec in ("", "*", "*:*", ":*", "**"):
            return True
        want = rule.command or ""
        for part in _parts(use.command):
            if rule.is_prefix:
                if part == want or part.startswith(want + " "):
                    return True
            elif "*" in want:
                if fnmatch.fnmatchcase(part, want):
                    return True
            elif part == want:
                return True
        return False
    if rule.tool.startswith("mcp__"):
        return use.tool == rule.tool or use.tool.startswith(rule.tool + "__")
    if rule.spec is None:
        return use.tool == rule.tool
    return None   # path and domain rules: the log has the argument, but matching it exactly is not worth guessing


def _in_scope(use: Use, project: str | None) -> bool:
    if project is None:
        return True
    if not use.cwd:
        return False
    cwd, proj = use.cwd.rstrip("/"), project.rstrip("/")
    return cwd == proj or cwd.startswith(proj + "/")


def count(raw_rule: str, project: str | None, uses: list[Use]) -> int | None:
    rule = parse(raw_rule)
    total = 0
    for u in uses:
        if not _in_scope(u, project):
            continue
        m = matches(rule, u)
        if m is None:
            return None
        total += bool(m)
    return total


def top_commands(raw_rule: str, project: str | None, uses: list[Use], n: int = 3) -> list[str]:
    """The exact commands a wide Bash rule was used for, most frequent first."""
    rule = parse(raw_rule)
    if rule.tool != "Bash":
        return []
    c: Counter[str] = Counter(u.command.strip() for u in uses
                              if u.command and _in_scope(u, project) and matches(rule, u))
    return [cmd for cmd, _ in c.most_common(n) if len(cmd) <= 80]
