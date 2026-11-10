"""Settings that act on their own: hooks, command helpers, auto-approved MCP servers, extra folders.

None of these are allow rules, but each one lets something happen without a prompt.
"""

from __future__ import annotations

import re
from pathlib import Path

from .rules import grade, parse
from .secrets import find_secrets, redact

# Keys whose value is a shell command Claude Code runs by itself (code.claude.com/docs/en/settings-reference).
COMMAND_KEYS = ("apiKeyHelper", "awsCredentialExport", "awsAuthRefresh", "gcpAuthRefresh", "otelHeadersHelper",
                "statusLine", "subagentStatusLine", "fileSuggestion")

_PIPE_TO_SHELL = re.compile(r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b")
_SENSITIVE_DIR = re.compile(r"(?:^|/)(?:\.ssh|\.aws|\.gnupg|\.config|\.kube|\.docker|Library|Documents|Desktop|Downloads)(?:/|$)")


def _command_of(value) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("command"), str):
        return value["command"]
    return None


def hook_commands(hooks) -> list[tuple[str, str]]:
    """[(event, command)] from Claude Code's hooks block: {Event: [{matcher, hooks: [{type, command}]}]}."""
    out: list[tuple[str, str]] = []
    if not isinstance(hooks, dict):
        return out
    for event, groups in hooks.items():
        for group in groups if isinstance(groups, list) else []:
            if not isinstance(group, dict):
                continue
            for h in group.get("hooks") or []:
                cmd = _command_of(h) if isinstance(h, dict) and h.get("type", "command") == "command" else None
                if cmd:
                    out.append((str(event), cmd))
    return out


def grade_command(cmd: str) -> tuple[str, str]:
    """(level, why) for a command that runs with no prompt."""
    if _PIPE_TO_SHELL.search(cmd):
        return "high", "It downloads a script and runs it, every time. Whoever controls that address controls your machine."
    first = cmd.strip().split("&&")[0].split("|")[0].split(";")[0].strip()
    g = grade(parse(f"Bash({first}:*)")) if first else None
    if g is None:
        return "medium", "leash could not read the command."
    level = {"critical": "high"}.get(g.level, g.level)
    return level, g.why


def additional_dir_level(d: str, home: Path) -> tuple[str, str]:
    p = d.strip()
    expanded = Path(p.replace("~", str(home), 1)).expanduser() if p.startswith("~") else Path(p)
    if p in ("/", "~", "~/", "$HOME") or str(expanded).rstrip("/") in (str(home), ""):
        return "high", "That is your whole home folder (or the whole disk): every key, document and other project."
    if _SENSITIVE_DIR.search(p):
        return "high", "That is a place where keys, settings or personal files live."
    return "low", "Only that folder. Check it is one you meant."


def findings_for(data: dict, shared: bool, home: Path | None = None) -> list[dict]:
    """Plain dicts (level, kind, title, detail, fix, rule) for the caller to turn into Findings."""
    home = home or Path.home()
    out: list[dict] = []
    who = ("everyone who opens this project, because the file is shared" if shared else "you, with no prompt")

    for event, cmd in hook_commands(data.get("hooks")):
        for s in find_secrets(cmd):
            out.append(dict(level="critical", kind="secret", title=f"{s.kind} is written into a `{event}` hook: {s.masked}",
                            detail="Hook commands are saved as plain text in the settings file.",
                            fix="Read the value from the environment or a credentials file instead, and rotate it.",
                            rule=redact(cmd)))
        level, why = grade_command(cmd)
        if shared and level == "low":
            level = "medium"
        short = redact(cmd) if len(cmd) <= 80 else redact(cmd)[:77] + "..."
        out.append(dict(level=level, kind="hook", title=f"a `{event}` hook runs `{short}` on its own",
                        detail=f"It runs for {who}. {why}",
                        fix="Nothing to do." if level == "low" else
                        "Keep it only if you know what it does. A shared hook should be reviewed like code.",
                        rule=redact(cmd)))

    for key in COMMAND_KEYS:
        cmd = _command_of(data.get(key))
        if not cmd:
            continue
        for s in find_secrets(cmd):
            out.append(dict(level="critical", kind="secret", title=f"{s.kind} is written into `{key}`: {s.masked}",
                            detail="The command is saved as plain text in the settings file.",
                            fix="Read the value from the environment or a credentials file instead, and rotate it.",
                            rule=redact(cmd)))
        if shared:
            level, why = grade_command(cmd)
            out.append(dict(level=max(level, "medium", key=lambda l: {"high": 2, "medium": 1}.get(l, 0)),
                            kind="hook", title=f"the shared settings set `{key}`, a command that runs on its own",
                            detail=f"It runs for everyone who opens this project. {why}",
                            fix=f"Move `{key}` to your own settings unless the whole team needs it.",
                            rule=f"{key}: {redact(cmd)}"))

    if data.get("enableAllProjectMcpServers") is True:
        if shared:
            out.append(dict(level="high", kind="mcp", title="this project approves every MCP server in its own `.mcp.json`",
                            detail="Anyone who opens the project starts those servers with no prompt. A pull request "
                                   "that adds a server gets it started on every machine.",
                            fix="Remove `enableAllProjectMcpServers` and list trusted servers in `enabledMcpjsonServers`.",
                            rule="enableAllProjectMcpServers: true"))
        else:
            out.append(dict(level="medium", kind="mcp", title="every project's `.mcp.json` servers start without a prompt",
                            detail="That includes repos you clone from someone else.",
                            fix="Remove `enableAllProjectMcpServers` and approve servers per project.",
                            rule="enableAllProjectMcpServers: true"))

    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    for d in perms.get("additionalDirectories") or []:
        if isinstance(d, str):
            level, why = additional_dir_level(d, home)
            out.append(dict(level=level, kind="rule", title=f"may read and change files in `{d}` as well as the project",
                            detail=why, fix="Nothing to do." if level == "low" else
                            "Remove it from `additionalDirectories`, or name a smaller folder.",
                            rule=f"additionalDirectories: {d}"))
    if perms.get("disableBypassPermissionsMode") == "disable":
        out.append(dict(level="info", kind="mode", title="bypass-permissions mode is switched off here",
                        detail="Nobody can turn all prompts off in these sessions. Good.", fix="",
                        rule="disableBypassPermissionsMode: disable"))
    return out
