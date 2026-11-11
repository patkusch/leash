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
Gemini CLI:
    ~/.gemini/settings.json, <project>/.gemini/settings.json
                                             tools.allowed, approval mode, MCP servers
Cursor:
    ~/.cursor/mcp.json, <project>/.cursor/mcp.json        MCP servers
VS Code:
    <project>/.vscode/mcp.json               MCP servers (under "servers")

A `.leashignore` file in any folder lists paths below it to skip, one per line,
such as `docs/example`. A folder you name on the command line is never skipped.
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
              ".pytest_cache", "Library", ".Trash", "dist", "build", ".next", "target", ".idea"}
MARKER_DIRS = {".claude", ".cursor", ".vscode", ".gemini"}
MAX_DEPTH = 8


@dataclass
class Source:
    path: Path
    kind: str                # see module docstring
    agent: str               # "Claude Code", "Codex CLI", "Gemini CLI", "Cursor", "VS Code"
    project: Path | None     # the project folder this file belongs to, if any
    shared: bool             # True if the file is normally committed and shared
    data: dict = field(default_factory=dict)
    error: str | None = None
    text: str = ""           # the raw file text

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
            "gemini": "Gemini CLI settings",
            "cursor-mcp": "Cursor MCP servers",
            "vscode-mcp": "VS Code MCP servers",
        }.get(self.kind, self.kind)


@dataclass
class Scan:
    sources: list[Source]
    repos: list[Path]                       # git repos found under the folders
    ignores: list[Path]                     # paths a .leashignore asked to skip
    roots: list[Path]                       # the folders asked for, resolved


def _read(path: Path) -> tuple[str, str | None]:
    try:
        return path.read_text(encoding="utf-8"), None
    except FileNotFoundError:
        return "", "missing"
    except OSError as e:
        return "", f"could not read: {e}"


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, outside strings. VS Code's mcp.json allows both."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    cleaned = "".join(out)
    # trailing commas: a comma followed only by whitespace and then } or ], outside strings
    result: list[str] = []
    in_str = False
    k = 0
    while k < len(cleaned):
        c = cleaned[k]
        if in_str:
            result.append(c)
            if c == "\\" and k + 1 < len(cleaned):
                result.append(cleaned[k + 1])
                k += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            result.append(c)
        elif c == ",":
            j = k + 1
            while j < len(cleaned) and cleaned[j] in " \t\r\n":
                j += 1
            if j < len(cleaned) and cleaned[j] in "}]":
                k += 1
                continue
            result.append(c)
        else:
            result.append(c)
        k += 1
    return "".join(result)


def _load(path: Path, fmt: str = "json") -> tuple[dict, str, str | None]:
    text, err = _read(path)
    if err:
        return {}, text, err
    try:
        if fmt == "toml":
            if tomllib is None:
                return {}, text, "needs Python 3.11 or newer to read TOML"
            data = tomllib.loads(text)
        else:
            try:
                data = json.loads(text) if text.strip() else {}
            except ValueError:
                data = json.loads(strip_jsonc(text))   # comments or trailing commas
    except ValueError as e:
        return {}, text, f"could not read: {e}"
    return (data if isinstance(data, dict) else {}), text, None


def _source(path: Path, kind: str, agent: str, project: Path | None, shared: bool, fmt: str = "json") -> Source:
    data, text, err = _load(path, fmt)
    return Source(path, kind, agent, project, shared, data, err, text)


def managed_settings_paths() -> list[Path]:
    if sys.platform == "darwin":
        return [Path("/Library/Application Support/ClaudeCode/managed-settings.json")]
    if sys.platform.startswith("win"):
        return [Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ClaudeCode" / "managed-settings.json"]
    return [Path("/etc/claude-code/managed-settings.json")]


def user_sources(home: Path | None = None) -> list[Source]:
    """The machine-wide files: your own settings, the managed file, other agents' user configs."""
    home = home or Path.home()
    wanted = [
        (home / ".claude" / "settings.json", "claude-user", "Claude Code", "json"),
        *[(p, "claude-managed", "Claude Code", "json") for p in managed_settings_paths()],
        (home / ".claude.json", "claude-global", "Claude Code", "json"),
        (home / ".codex" / "config.toml", "codex", "Codex CLI", "toml"),
        (home / ".gemini" / "settings.json", "gemini", "Gemini CLI", "json"),
        (home / ".cursor" / "mcp.json", "cursor-mcp", "Cursor", "json"),
    ]
    return [_source(p, kind, agent, None, False, fmt) for p, kind, agent, fmt in wanted if p.is_file()]


def project_sources_in(project: Path, home: Path | None = None) -> list[Source]:
    """The permission files directly inside one project folder."""
    home = (home or Path.home()).resolve()
    out: list[Source] = []
    at_home = project.resolve() == home   # these are user files, read by user_sources
    candidates = [
        (project / ".claude" / "settings.json", "claude-project", "Claude Code", True),
        (project / ".claude" / "settings.local.json", "claude-local", "Claude Code", False),
        (project / ".mcp.json", "claude-mcp", "Claude Code", True),
        (project / ".gemini" / "settings.json", "gemini", "Gemini CLI", True),
        (project / ".cursor" / "mcp.json", "cursor-mcp", "Cursor", True),
        (project / ".vscode" / "mcp.json", "vscode-mcp", "VS Code", True),
    ]
    for p, kind, agent, shared in candidates:
        if at_home and kind in ("claude-project", "gemini", "cursor-mcp"):
            continue
        if p.is_file():
            out.append(_source(p, kind, agent, project, shared))
    return out


def read_ignore(folder: Path) -> list[Path]:
    """Paths listed in folder/.leashignore, resolved against that folder."""
    p = folder / ".leashignore"
    if not p.is_file():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append((folder / line.strip("/")).resolve())
    return out


def is_ignored(path: Path, ignores: list[Path], roots: list[Path]) -> bool:
    """True if path is under an ignored path, unless a folder you asked for is itself under it."""
    path = path.resolve()
    for ig in ignores:
        if path == ig or ig in path.parents:
            if any(r == ig or ig in r.parents for r in roots if r == path or r in path.parents):
                continue
            return True
    return False


def scan(roots: list[Path], include_user: bool = True, home: Path | None = None,
         max_depth: int = MAX_DEPTH) -> Scan:
    roots = [r.expanduser().resolve() for r in roots]
    sources: list[Source] = user_sources(home) if include_user else []
    repos: list[Path] = []
    ignores: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            if here != root and is_ignored(here, ignores, roots):
                dirnames[:] = []
                continue
            ignores.extend(read_ignore(here))
            if (".git" in dirnames or ".git" in filenames) and here not in repos:
                repos.append(here)
            markers = [d for d in dirnames if d in MARKER_DIRS]
            if (markers or ".mcp.json" in filenames) and here not in seen:
                seen.add(here)
                sources.extend(project_sources_in(here, home))
            depth = len(here.parts) - base_depth
            dirnames[:] = sorted(d for d in dirnames
                                 if d not in _SKIP_DIRS and not d.startswith(".") and depth < max_depth)
    return Scan(sources, repos, ignores, roots)


def find_projects(roots: list[Path], max_depth: int = MAX_DEPTH) -> list[Path]:
    """Every folder under roots that holds agent settings."""
    found: list[Path] = []
    for s in scan(roots, include_user=False, max_depth=max_depth).sources:
        if s.project is not None and s.project not in found:
            found.append(s.project)
    return found


def discover(roots: list[Path], include_user: bool = True, home: Path | None = None) -> list[Source]:
    return scan(roots, include_user, home).sources
