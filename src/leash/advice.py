"""Protections that are missing: deny rules that keep agents away from the places secrets live.

Claude Code's settings docs show `Read(./.env)` and `Read(./.env.*)` as deny rules, and audit
guides after the November 2026 leak add the home-folder key stores. A deny rule always wins over
an allow rule. It covers Claude Code's own file tools; a shell command such as `cat .env` is
governed by Bash rules instead, which is why leash also grades those.
"""

from __future__ import annotations

import json
from pathlib import Path

from .audit import Finding
from .sources import Source

USER_DENY = ["Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(~/.gnupg/**)", "Read(~/.config/gh/**)",
             "Read(~/.netrc)", "Read(~/.docker/config.json)", "Read(~/.kube/**)"]
PROJECT_DENY = ["Read(./.env)", "Read(./.env.*)", "Bash(git push --force:*)"]
_SAFE_ENV = (".example", ".sample", ".template", ".dist", ".defaults")
CLAUDE_KINDS = ("claude-user", "claude-managed", "claude-project", "claude-local")


def _denies(src: Source) -> list[str]:
    perms = src.data.get("permissions") if isinstance(src.data.get("permissions"), dict) else {}
    return [d for d in perms.get("deny") or [] if isinstance(d, str)]


def env_files(project: Path) -> list[str]:
    out = []
    try:
        for p in project.iterdir():
            if p.is_file() and (p.name == ".env" or p.name.startswith(".env.")) and not p.name.endswith(_SAFE_ENV):
                out.append(p.name)
    except OSError:
        pass
    return sorted(out)


def _covers(denies: list[str], needle: str) -> bool:
    return any(needle in d for d in denies)


def missing(sources: list[Source]) -> tuple[list[str], dict[Path, list[str]]]:
    """(user-level deny rules missing, {project: project-level deny rules missing})."""
    user = [d for s in sources if s.kind in ("claude-user", "claude-managed") for d in _denies(s)]
    projects: dict[Path, list[str]] = {}
    for s in sources:
        if s.kind in ("claude-project", "claude-local") and s.project is not None:
            projects.setdefault(s.project, []).extend(_denies(s))
    user_missing = [r for r in USER_DENY if not _covers(user, r[5:].split("/**")[0].rstrip(")"))]
    proj_missing: dict[Path, list[str]] = {}
    for proj, denies in projects.items():
        all_denies = user + denies
        need = [r for r in PROJECT_DENY if r.startswith("Bash") and not _covers(all_denies, "push --force")]
        if env_files(proj) and not _covers(all_denies, ".env"):
            need = ["Read(./.env)", "Read(./.env.*)"] + need
        if need:
            proj_missing[proj] = need
    return user_missing, proj_missing


def findings(sources: list[Source]) -> list[Finding]:
    out: list[Finding] = []
    claude = [s for s in sources if s.kind in CLAUDE_KINDS]
    if not claude:
        return out
    user_missing, proj_missing = missing(sources)
    for proj, need in proj_missing.items():
        envs = env_files(proj)
        if envs and any(".env" in r for r in need):
            out.append(Finding("medium", "advice", f"the agent may read {', '.join(envs)} here: no deny rule covers it",
                               "That is usually where this project's passwords and keys are. What the agent reads can "
                               "end up in a command, a commit or a web request.",
                               "Add `Read(./.env)` and `Read(./.env.*)` to the deny list in `.claude/settings.json` "
                               "(`leash --suggest` prints the block).", str(proj / envs[0]), str(proj)))
    if user_missing and any(s.kind == "claude-user" for s in sources):
        user_file = next(s.path for s in sources if s.kind == "claude-user")
        out.append(Finding("low", "advice", f"{len(user_missing)} folder(s) where keys live are not on your deny list",
                           "A deny rule makes the agent ask, or refuse, before reading them in any project: "
                           + ", ".join(f"`{r}`" for r in user_missing) + ".",
                           "Add them to the deny list in `~/.claude/settings.json` (`leash --suggest` prints the block).",
                           str(user_file)))
    return out


def suggestion(sources: list[Source]) -> str:
    user_missing, proj_missing = missing(sources)
    lines = []
    if user_missing:
        lines.append("Add to ~/.claude/settings.json (every project):")
        lines.append(json.dumps({"permissions": {"deny": user_missing}}, indent=2))
    for proj, need in proj_missing.items():
        lines.append(f"\nAdd to {proj / '.claude' / 'settings.json'} (this project, shared with the team):")
        lines.append(json.dumps({"permissions": {"deny": need}}, indent=2))
    if not lines:
        return "Nothing to add: the recommended deny rules are already in place.\n"
    lines.append("\nMerge these into any deny list already in the file. Deny rules always win over allow rules.")
    return "\n".join(lines) + "\n"
