"""Find the files where coding agents keep their standing permissions.

Claude Code:
    ~/.claude/settings.json                  your own rules, every project
    <project>/.claude/settings.json          shared with the team, usually committed
    <project>/.claude/settings.local.json    yours only; this is where "don't ask again" writes
    <project>/.mcp.json                      MCP servers for the project, usually committed
    ~/.claude.json                           per-project allowed tools and MCP servers
    managed-settings.json                    set by an administrator
Codex CLI:
    ~/.codex/config.toml                     approval policy and sandbox mode
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".cache", ".tox", ".mypy_cache",
              ".pytest_cache", "Library", ".Trash", "dist", "build", ".next", "target", ".idea", ".vscode"}
MAX_DEPTH = 8


@dataclass
class Source:
    path: Path
    kind: str                # see module docstring
    agent: str               # "Claude Code" or "Codex CLI"
    project: Path | None     # the project folder this file belongs to, if any
    shared: bool             # True if the file is normally committed and shared
    data: dict = field(default_factory=dict)
    error: str | None = None

    @property
    def label(self) -> str:
        return {
            "claude-user": "your Claude Code settings",
            "claude-managed": "administrator-managed Claude Code settings",
            "claude-project": "shared project settings",
            "claude-local": "local project settings (where 'don't ask again' writes)",
            "claude-mcp": "project MCP servers",
            "claude-global": "Claude Code's per-project record",
            "codex": "Codex CLI config",
        }.get(self.kind, self.kind)


def _load_json(path: Path) -> tuple[dict, str | None]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, "missing"
    except (OSError, ValueError) as e:
        return {}, f"could not read: {e}"
    return (data if isinstance(data, dict) else {}), None


def _load_toml(path: Path) -> tuple[dict, str | None]:
    if tomllib is None:
        return {}, "needs Python 3.11 or newer to read TOML"
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, "missing"
    except (OSError, ValueError) as e:
        return {}, f"could not read: {e}"
    return data, None


def managed_settings_paths() -> list[Path]:
    if sys.platform == "darwin":
        return [Path("/Library/Application Support/ClaudeCode/managed-settings.json")]
    if sys.platform.startswith("win"):
        return [Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ClaudeCode" / "managed-settings.json"]
    return [Path("/etc/claude-code/managed-settings.json")]


def user_sources(home: Path | None = None) -> list[Source]:
    """The machine-wide files: your own settings, the managed file, Codex's config."""
    home = home or Path.home()
    out: list[Source] = []
    p = home / ".claude" / "settings.json"
    if p.exists():
        data, err = _load_json(p)
        out.append(Source(p, "claude-user", "Claude Code", None, False, data, err))
    for p in managed_settings_paths():
        if p.exists():
            data, err = _load_json(p)
            out.append(Source(p, "claude-managed", "Claude Code", None, False, data, err))
    p = home / ".claude.json"
    if p.exists():
        data, err = _load_json(p)
        out.append(Source(p, "claude-global", "Claude Code", None, False, data, err))
    p = home / ".codex" / "config.toml"
    if p.exists():
        data, err = _load_toml(p)
        out.append(Source(p, "codex", "Codex CLI", None, False, data, err))
    return out


def project_sources_in(project: Path) -> list[Source]:
    """The permission files directly inside one project folder."""
    out: list[Source] = []
    claude = project / ".claude"
    for name, kind, shared in (("settings.json", "claude-project", True),
                               ("settings.local.json", "claude-local", False)):
        p = claude / name
        if p.is_file():
            data, err = _load_json(p)
            out.append(Source(p, kind, "Claude Code", project, shared, data, err))
    p = project / ".mcp.json"
    if p.is_file():
        data, err = _load_json(p)
        out.append(Source(p, "claude-mcp", "Claude Code", project, True, data, err))
    return out


def find_projects(roots: list[Path], max_depth: int = MAX_DEPTH) -> list[Path]:
    """Every folder under roots that holds a .claude/ folder or a .mcp.json file."""
    seen: set[Path] = set()
    found: list[Path] = []
    for root in roots:
        root = root.expanduser().resolve()
        if not root.is_dir():
            continue
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            depth = len(here.parts) - base_depth
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS and not (d.startswith(".") and d != ".claude"))
            if depth >= max_depth:
                dirnames[:] = []
            if (".claude" in dirnames or ".mcp.json" in filenames) and here not in seen:
                seen.add(here)
                found.append(here)
            if ".claude" in dirnames:
                dirnames.remove(".claude")   # nothing to find inside it
    return found


def discover(roots: list[Path], include_user: bool = True, home: Path | None = None) -> list[Source]:
    out: list[Source] = []
    if include_user:
        out.extend(user_sources(home))
    for project in find_projects(roots):
        out.extend(project_sources_in(project))
    return out
