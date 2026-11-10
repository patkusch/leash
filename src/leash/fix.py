"""Remove rules that have a secret in them, after saving a backup outside the project.

Only rule lists are touched: Claude Code's permissions.allow / ask / deny and Gemini CLI's
tools.allowed. Secrets in MCP server settings or hooks are left for you to move, because
taking them out would break the server or hook.

The backup holds the secret, so it goes in ~/.leash/backups (readable only by you),
never next to the file, where it could be committed.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from pathlib import Path

from .secrets import find_secrets, redact
from .sources import Source

FIXABLE = ("claude-user", "claude-project", "claude-local", "gemini")


def backup_dir() -> Path:
    return Path(os.environ.get("LEASH_BACKUP_DIR", Path.home() / ".leash" / "backups"))


def _rule_lists(kind: str, data: dict) -> list[tuple[str, list]]:
    out = []
    if kind == "gemini":
        tools = data.get("tools")
        if isinstance(tools, dict) and isinstance(tools.get("allowed"), list):
            out.append(("tools.allowed", tools["allowed"]))
    else:
        perms = data.get("permissions")
        if isinstance(perms, dict):
            for key in ("allow", "ask", "deny"):
                if isinstance(perms.get(key), list):
                    out.append((f"permissions.{key}", perms[key]))
    return out


def plan(src: Source) -> list[tuple[str, str]]:
    """[(list name, masked rule)] that fix() would remove from this file."""
    if src.kind not in FIXABLE or src.error:
        return []
    return [(name, redact(r)) for name, rules in _rule_lists(src.kind, src.data)
            for r in rules if isinstance(r, str) and find_secrets(r)]


def fix(src: Source, now: datetime | None = None) -> tuple[list[tuple[str, str]], Path | None]:
    """Remove secret-bearing rules from the file. Returns what was removed and where the backup is."""
    removed = plan(src)
    if not removed:
        return [], None
    data = json.loads(src.path.read_text(encoding="utf-8"))
    for _name, rules in _rule_lists(src.kind, data):
        rules[:] = [r for r in rules if not (isinstance(r, str) and find_secrets(r))]

    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
    dest_dir = backup_dir() / stamp
    dest_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(dest_dir.parent, 0o700)
    os.chmod(dest_dir, 0o700)
    flat = str(src.path.resolve()).strip("/").replace("/", "__")
    backup = dest_dir / flat
    shutil.copy2(src.path, backup)
    os.chmod(backup, 0o600)

    tmp = src.path.with_name(src.path.name + ".leash-tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    shutil.copymode(src.path, tmp)
    os.replace(tmp, src.path)
    return removed, backup
