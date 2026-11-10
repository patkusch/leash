"""Turn permission files into findings a person can act on."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path

from . import gitcheck
from .rules import grade, grade_mode, parse
from .secrets import find_secrets, redact
from .sources import Source

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    level: str          # critical | high | medium | low | info
    kind: str           # secret | rule | mode | git | mcp | codex | error
    title: str          # one line, plain English
    detail: str         # why it matters
    fix: str            # what to do
    path: str           # the file it came from
    project: str | None = None
    rule: str | None = None   # the rule text, with any secret masked

    def to_dict(self) -> dict:
        return asdict(self)


def _secret_findings(text: str, where: str, src: Source, fix_hint: str) -> list[Finding]:
    out = []
    for s in find_secrets(text):
        out.append(Finding(
            "critical", "secret",
            f"{s.kind} is written into {where}: {s.masked}",
            f"This is in {src.label}. " + (
                "That file is normally committed and shared, so the secret travels with the project."
                if src.shared else
                "Anyone who can read this file has the secret. If the file is in git, so does everyone with the repo."),
            fix_hint + " Then rotate the secret: treat it as already seen.",
            str(src.path), str(src.project) if src.project else None, redact(text)))
    return out


def _permission_findings(src: Source) -> list[Finding]:
    out: list[Finding] = []
    perms = src.data.get("permissions") if isinstance(src.data.get("permissions"), dict) else {}
    mode = perms.get("defaultMode") or src.data.get("defaultMode")
    g = grade_mode(mode)
    if g:
        out.append(Finding(g.level, "mode", f"the agent may {g.what} (defaultMode is `{mode}`)", g.why,
                           "Remove `defaultMode` or set it to `default`.", str(src.path),
                           str(src.project) if src.project else None, f"defaultMode: {mode}"))
    for raw in perms.get("allow") or []:
        if not isinstance(raw, str):
            continue
        out.extend(_secret_findings(raw, "a 'don't ask again' rule", src,
                                    "Delete the rule from the allow list and run the command without the "
                                    "password in it next time (use a variable, a prompt or a credentials file)."))
        r = parse(raw)
        g = grade(r)
        out.append(Finding(g.level, "rule", f"may {g.what}, without asking", g.why,
                           "Remove the rule if you did not mean it. Narrow it to one exact command if you did.",
                           str(src.path), str(src.project) if src.project else None, redact(raw)))
    for raw in perms.get("deny") or []:
        if isinstance(raw, str):
            out.extend(_secret_findings(raw, "a deny rule", src, "Delete the rule."))
    for raw in perms.get("ask") or []:
        if isinstance(raw, str):
            out.extend(_secret_findings(raw, "an ask rule", src, "Delete the rule."))
    denies = [d for d in (perms.get("deny") or []) if isinstance(d, str)]
    if denies:
        out.append(Finding("info", "rule", f"{len(denies)} deny rule(s) are set: these always ask or refuse",
                           "Deny rules win over allow rules. Good.", "", str(src.path),
                           str(src.project) if src.project else None, "; ".join(redact(d) for d in denies)))
    env = src.data.get("env")
    if isinstance(env, dict):
        for k, v in env.items():
            if isinstance(v, str):
                out.extend(_secret_findings(f"{k}={v}", "the `env` block", src,
                                            "Move the value into your shell environment or a secrets manager "
                                            "and reference it there."))
    return out


def _mcp_findings(src: Source) -> list[Finding]:
    out: list[Finding] = []
    servers = src.data.get("mcpServers")
    if not isinstance(servers, dict):
        return out
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        for field_name in ("env", "headers"):
            block = cfg.get(field_name)
            if isinstance(block, dict):
                for k, v in block.items():
                    if isinstance(v, str):
                        out.extend(_secret_findings(f"{k}={v}" if field_name == "env" else f"{k}: {v}",
                                                    f"the `{name}` MCP server's {field_name}", src,
                                                    "Reference an environment variable (`${NAME}`) instead of "
                                                    "writing the value in the file."))
        for key in ("url", "command"):
            v = cfg.get(key)
            if isinstance(v, str):
                out.extend(_secret_findings(v, f"the `{name}` MCP server's {key}", src,
                                            "Take the secret out of the URL or command."))
        for a in cfg.get("args") or []:
            if isinstance(a, str):
                out.extend(_secret_findings(a, f"the `{name}` MCP server's arguments", src,
                                            "Pass the secret through the environment instead."))
    return out


def _global_findings(src: Source) -> list[Finding]:
    """~/.claude.json: per-project allowedTools and MCP servers."""
    out: list[Finding] = []
    out.extend(_mcp_findings(src))
    projects = src.data.get("projects")
    if not isinstance(projects, dict):
        return out
    for proj, cfg in projects.items():
        if not isinstance(cfg, dict):
            continue
        for raw in cfg.get("allowedTools") or []:
            if not isinstance(raw, str):
                continue
            out.extend(_secret_findings(raw, "an allowed-tool entry", src, "Delete the entry."))
            g = grade(raw)
            out.append(Finding(g.level, "rule", f"may {g.what}, without asking", g.why,
                               "Remove the entry if you did not mean it.", str(src.path), proj, redact(raw)))
        sub = Source(src.path, src.kind, src.agent, Path(proj), False, cfg, None)
        for f in _mcp_findings(sub):
            f.project = proj
            out.append(f)
    return out


def _codex_findings(src: Source) -> list[Finding]:
    out: list[Finding] = []
    d = src.data
    ap = d.get("approval_policy")
    if ap == "never":
        out.append(Finding("critical", "codex", "Codex never asks before running a command (approval_policy is `never`)",
                           "Every command runs on its own. Only the sandbox, if any, holds it back.",
                           "Set `approval_policy` to `on-request` or `untrusted`.", str(src.path), None,
                           "approval_policy = \"never\""))
    elif ap == "on-failure":
        out.append(Finding("medium", "codex", "Codex asks only after a sandboxed command fails (approval_policy is `on-failure`)",
                           "Commands run first and ask later.", "Set `approval_policy` to `on-request` if you want to "
                           "see commands before they run.", str(src.path), None, "approval_policy = \"on-failure\""))
    sm = d.get("sandbox_mode")
    if sm == "danger-full-access":
        out.append(Finding("critical", "codex", "Codex runs with no sandbox (sandbox_mode is `danger-full-access`)",
                           "The agent can read and write anywhere and use the network.",
                           "Set `sandbox_mode` to `workspace-write`.", str(src.path), None,
                           "sandbox_mode = \"danger-full-access\""))
    elif sm == "workspace-write":
        ws = d.get("sandbox_workspace_write")
        if isinstance(ws, dict) and ws.get("network_access"):
            out.append(Finding("high", "codex", "Codex's sandbox allows network access",
                               "Files in the workspace can be sent anywhere.",
                               "Set `network_access = false` under `[sandbox_workspace_write]`.", str(src.path),
                               None, "sandbox_workspace_write.network_access = true"))
    for name, cfg in (d.get("mcp_servers") or {}).items():
        if isinstance(cfg, dict):
            for k, v in (cfg.get("env") or {}).items():
                if isinstance(v, str):
                    out.extend(_secret_findings(f"{k}={v}", f"the `{name}` MCP server's env", src,
                                                "Pass the secret through your shell environment instead."))
    for name, cfg in (d.get("projects") or {}).items():
        if isinstance(cfg, dict) and cfg.get("trust_level") == "trusted":
            out.append(Finding("info", "codex", f"project `{name}` is marked trusted",
                               "Codex applies its default (less strict) behaviour there.", "", str(src.path), name,
                               "trust_level = \"trusted\""))
    return out


def _git_findings(src: Source, has_secret: bool, use_gh: bool) -> list[Finding]:
    if src.kind not in ("claude-local", "claude-project", "claude-mcp"):
        return []
    st = gitcheck.status(src.path, use_gh=use_gh)
    if st.repo is None:
        return []
    proj = str(src.project) if src.project else None
    out: list[Finding] = []
    where = {"public": "a public GitHub repo", "private": "a private repo", "internal": "an internal repo"}.get(
        st.visibility or "", "a repo (leash could not tell if it is public)")
    if src.kind == "claude-local":
        if st.tracked:
            level = "critical" if (st.visibility == "public" or has_secret) else "high"
            out.append(Finding(level, "git", f"your 'don't ask again' file is committed to {where}",
                               "Every rule in it, and any password inside a rule, is in the repo's history. "
                               "Deleting the file does not remove old commits or forks.",
                               "Run `git rm --cached .claude/settings.local.json`, add it to .gitignore "
                               "(`leash --gitignore` does that), commit, and rotate anything secret.",
                               str(src.path), proj))
        elif st.history_commits:
            level = "critical" if (st.visibility == "public" and has_secret) else "high"
            out.append(Finding(level, "git", f"your 'don't ask again' file was committed before and is still in "
                               f"{st.history_commits} commit(s) of {where}",
                               "It is not tracked now, but anyone can read the old commits.",
                               "Rotate anything secret that was ever in it. Rewriting history only helps if "
                               "no one has already fetched it.", str(src.path), proj))
        elif not st.ignored:
            out.append(Finding("medium", "git", "your 'don't ask again' file is not ignored by git",
                               "Nothing stops the next `git add -A` or `git add .` from committing it. "
                               "Claude Code tries to ignore it for you; that has not happened here.",
                               "Add `.claude/settings.local.json` to .gitignore (`leash --gitignore` does that).",
                               str(src.path), proj))
        else:
            out.append(Finding("info", "git", "your 'don't ask again' file is ignored by git", "", "",
                               str(src.path), proj))
    elif has_secret and (st.tracked or st.history_commits):
        out.append(Finding("critical", "git", f"a shared file with a secret in it is in {where}",
                           "The secret is in the repo's history.",
                           "Take it out of the file, commit, and rotate it.", str(src.path), proj))
    return out


def audit_source(src: Source, use_git: bool = True, use_gh: bool = True) -> list[Finding]:
    if src.error:
        return [Finding("info", "error", f"could not read {src.label}: {src.error}", "", "", str(src.path),
                        str(src.project) if src.project else None)]
    if src.kind == "codex":
        findings = _codex_findings(src)
    elif src.kind == "claude-global":
        findings = _global_findings(src)
    elif src.kind == "claude-mcp":
        findings = _mcp_findings(src)
    else:
        findings = _permission_findings(src) + _mcp_findings(src)
    if use_git and src.project is not None:
        has_secret = any(f.kind == "secret" for f in findings)
        findings.extend(_git_findings(src, has_secret, use_gh))
    return findings


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (ORDER.get(f.level, 9), f.path, f.title))


def exit_code(findings: list[Finding]) -> int:
    levels = {f.level for f in findings}
    if "critical" in levels:
        return 2
    if "high" in levels:
        return 1
    return 0
