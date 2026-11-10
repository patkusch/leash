"""Turn permission files into findings a person can act on."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

from . import gitcheck, history
from .rules import Grade, Rule, grade, grade_mode, parse
from .secrets import find_secrets, redact
from .sources import Source, is_ignored

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    level: str          # critical | high | medium | low | info
    kind: str           # secret | rule | mode | git | history | mcp | codex | gemini | error
    title: str          # one line, plain English
    detail: str         # why it matters
    fix: str            # what to do
    path: str           # the file it came from
    project: str | None = None
    rule: str | None = None   # the rule text, with any secret masked

    def to_dict(self) -> dict:
        return asdict(self)


def _proj(src: Source) -> str | None:
    return str(src.project) if src.project else None


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
            str(src.path), _proj(src), redact(text)))
    return out


_READ_TOOLS = ("Read", "Glob", "Grep", "LS")
_WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")


def rule_fix(rule: Rule, g: Grade, where: str = "the allow list") -> str:
    """What to do about one allow rule, in the agent's own rule syntax."""
    if g.level == "low":
        return "Nothing to do."
    t, spec = rule.tool, rule.spec
    if t == "Bash":
        if spec is None or spec.strip() in ("", "*", "*:*", ":*", "**"):
            return (f"Remove it from {where}. Allow the commands you need one at a time instead, "
                    "such as `Bash(npm test)`.")
        return (f"Remove it from {where} if you did not mean it. If you did, allow the exact command rather "
                "than everything that starts with it, and add a deny rule for the risky forms, such as "
                "`Bash(git push --force:*)`.")
    if t in _READ_TOOLS:
        return f"Remove it, and add `{rule.raw}` to the deny list so the agent always has to ask."
    if t in _WRITE_TOOLS:
        return "Limit it to the project's own folders, such as `Edit(src/**)`."
    if t in ("WebFetch", "WebSearch"):
        return "Limit it to the sites you need, such as `WebFetch(domain:docs.python.org)`."
    if t.startswith("mcp__"):
        if t.count("__") == 1:
            return f"Allow the tools you use one at a time, such as `{t}__<tool name>`, instead of the whole server."
        return "Keep it only if you are happy for that action to happen with no prompt."
    return f"Remove it from {where} if you did not mean it."


def _rule_finding(raw: str, r: Rule, src: Source, where: str = "the allow list", project: str | None = None,
                  fix: str | None = None) -> Finding:
    g = grade(r)
    return Finding(g.level, "rule", f"may {g.what}, without asking", g.why, fix or rule_fix(r, g, where),
                   str(src.path), project if project is not None else _proj(src), redact(raw))


def _permission_findings(src: Source) -> list[Finding]:
    out: list[Finding] = []
    perms = src.data.get("permissions") if isinstance(src.data.get("permissions"), dict) else {}
    mode = perms.get("defaultMode") or src.data.get("defaultMode")
    g = grade_mode(mode)
    if g:
        out.append(Finding(g.level, "mode", f"may {g.what} (defaultMode is `{mode}`)", g.why,
                           "Remove `defaultMode` or set it to `default`.", str(src.path), _proj(src),
                           f"defaultMode: {mode}"))
    for raw in perms.get("allow") or []:
        if not isinstance(raw, str):
            continue
        out.extend(_secret_findings(raw, "a 'don't ask again' rule", src,
                                    "Delete the rule from the allow list and run the command without the "
                                    "password in it next time (use a variable, a prompt or a credentials file)."))
        out.append(_rule_finding(raw, parse(raw), src))
    for key, label in (("deny", "a deny rule"), ("ask", "an ask rule")):
        for raw in perms.get(key) or []:
            if isinstance(raw, str):
                out.extend(_secret_findings(raw, label, src, "Delete the rule."))
    denies = [d for d in (perms.get("deny") or []) if isinstance(d, str)]
    if denies:
        out.append(Finding("info", "rule", f"{len(denies)} deny rule(s) are set: these always ask or refuse",
                           "Deny rules win over allow rules. Good.", "", str(src.path), _proj(src),
                           "; ".join(redact(d) for d in denies)))
    env = src.data.get("env")
    if isinstance(env, dict):
        for k, v in env.items():
            if isinstance(v, str):
                out.extend(_secret_findings(f"{k}={v}", "the `env` block", src,
                                            "Move the value into your shell environment or a secrets manager "
                                            "and reference it there."))
    return out


def _mcp_findings(src: Source, servers: object = None, project: str | None = None) -> list[Finding]:
    out: list[Finding] = []
    servers = src.data.get("mcpServers") if servers is None else servers
    if not isinstance(servers, dict):
        return out
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        found: list[Finding] = []
        for field_name in ("env", "headers"):
            block = cfg.get(field_name)
            if isinstance(block, dict):
                for k, v in block.items():
                    if isinstance(v, str):
                        found.extend(_secret_findings(f"{k}={v}" if field_name == "env" else f"{k}: {v}",
                                                      f"the `{name}` MCP server's {field_name}", src,
                                                      "Reference an environment variable instead of writing "
                                                      "the value in the file."))
        for key in ("url", "httpUrl", "command"):
            v = cfg.get(key)
            if isinstance(v, str):
                found.extend(_secret_findings(v, f"the `{name}` MCP server's {key}", src,
                                              "Take the secret out of the URL or command."))
        for a in cfg.get("args") or []:
            if isinstance(a, str):
                found.extend(_secret_findings(a, f"the `{name}` MCP server's arguments", src,
                                              "Pass the secret through the environment instead."))
        if cfg.get("trust") is True:
            found.append(Finding("medium", "mcp", f"every tool on the `{name}` MCP server runs without asking "
                                 "(trust is true)",
                                 "Gemini CLI skips all confirmations for a trusted server, including tools a "
                                 "server update adds later.",
                                 "Set `trust` to false, or list the safe tools in `includeTools`.",
                                 str(src.path), _proj(src), f"{name}.trust = true"))
        if project is not None:
            for f in found:
                f.project = project
        out.extend(found)
    return out


def _global_findings(src: Source) -> list[Finding]:
    """~/.claude.json: per-project allowed tools and MCP servers."""
    out: list[Finding] = _mcp_findings(src)
    projects = src.data.get("projects")
    if not isinstance(projects, dict):
        return out
    for proj, cfg in projects.items():
        if not isinstance(cfg, dict):
            continue
        for raw in cfg.get("allowedTools") or []:
            if not isinstance(raw, str):
                continue
            for f in _secret_findings(raw, "an allowed-tool entry", src, "Delete the entry."):
                f.project = proj
                out.append(f)
            out.append(_rule_finding(raw, parse(raw), src, "allowedTools", project=proj))
        out.extend(_mcp_findings(src, cfg.get("mcpServers"), project=proj))
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


# Gemini CLI tool names, mapped to the Claude Code tool with the same reach.
_GEMINI_TOOLS = {
    "run_shell_command": "Bash", "ShellTool": "Bash", "write_file": "Write", "replace": "Edit",
    "read_file": "Read", "read_many_files": "Read", "glob": "Glob", "search_file_content": "Grep",
    "list_directory": "LS", "web_fetch": "WebFetch", "google_web_search": "WebSearch",
}


def gemini_rule(raw: str) -> Rule:
    """Gemini's `run_shell_command(git)` allows every command starting with `git`: grade it as `Bash(git:*)`."""
    m = re.fullmatch(r"\s*([\w.-]+)\s*(?:\((.*)\))?\s*", raw, re.S)
    if not m:
        return Rule(raw, raw, None)
    name, arg = m.group(1), m.group(2)
    tool = _GEMINI_TOOLS.get(name, name)
    if tool == "Bash" and arg:
        arg = arg.strip()
        return Rule(raw, "Bash", arg if arg.endswith(":*") else arg + ":*")
    return Rule(raw, tool, arg)


def _gemini_findings(src: Source) -> list[Finding]:
    out: list[Finding] = []
    d = src.data
    general = d.get("general") if isinstance(d.get("general"), dict) else {}
    if general.get("defaultApprovalMode") == "auto_edit":
        out.append(Finding("medium", "gemini", "may change any file without asking (defaultApprovalMode is `auto_edit`)",
                           "File edits go in unread. Commands still ask.",
                           "Set `general.defaultApprovalMode` to `default`.", str(src.path), _proj(src),
                           "general.defaultApprovalMode = auto_edit"))
    tools = d.get("tools") if isinstance(d.get("tools"), dict) else {}
    for raw in tools.get("allowed") or []:
        if not isinstance(raw, str):
            continue
        out.extend(_secret_findings(raw, "a `tools.allowed` entry", src,
                                    "Delete the entry and keep the password out of the command."))
        r = gemini_rule(raw)
        g = grade(r)
        fix = "Nothing to do." if g.level == "low" else "Remove it from `tools.allowed` if you did not mean it."
        out.append(_rule_finding(raw, r, src, "`tools.allowed`", fix=fix))
    security = d.get("security") if isinstance(d.get("security"), dict) else {}
    if security.get("autoAddToPolicyByDefault") is True:
        out.append(Finding("medium", "gemini", "'allow for all future sessions' is the default answer for low-risk tools",
                           "One tap and the tool never asks again.", "Set `security.autoAddToPolicyByDefault` to false.",
                           str(src.path), _proj(src), "security.autoAddToPolicyByDefault = true"))
    out.extend(_mcp_findings(src))
    return out


def _git_findings(src: Source, has_secret: bool, use_gh: bool) -> list[Finding]:
    if src.kind not in ("claude-local", "claude-project", "claude-mcp", "gemini", "cursor-mcp", "vscode-mcp"):
        return []
    st = gitcheck.status(src.path, use_gh=use_gh)
    if st.repo is None:
        return []
    proj = _proj(src)
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
                        _proj(src))]
    if src.kind == "codex":
        findings = _codex_findings(src)
    elif src.kind == "claude-global":
        findings = _global_findings(src)
    elif src.kind == "gemini":
        findings = _gemini_findings(src)
    elif src.kind == "vscode-mcp":
        findings = _mcp_findings(src, src.data.get("servers"))
    elif src.kind in ("claude-mcp", "cursor-mcp"):
        findings = _mcp_findings(src)
    else:
        findings = _permission_findings(src) + _mcp_findings(src)
    if use_git and src.project is not None:
        has_secret = any(f.kind == "secret" for f in findings)
        findings.extend(_git_findings(src, has_secret, use_gh))
    return findings


def audit_history(repo: Path, ignores: list[Path] | None = None, roots: list[Path] | None = None,
                  use_gh: bool = True) -> list[Finding]:
    """Secrets that are in old commits of agent files but no longer in the file on disk."""
    ignores = ignores or []
    roots = roots or [repo]
    out: list[Finding] = []
    remote = visibility = None
    files = history.historical_files(repo)
    if files:
        st = gitcheck.status(repo, use_gh=use_gh)
        remote, visibility = st.remote, st.visibility
    for rel in files:
        path = repo / rel
        if not any(r == path or r in path.parents or r == repo or r in repo.parents for r in roots):
            continue
        if is_ignored(path, ignores, roots):
            continue
        now = ""
        if path.is_file():
            try:
                now = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                now = ""
        current = {(s.kind, s.masked) for s in find_secrets(now)}
        for old in history.secrets_in_history(repo, rel):
            if (old.kind, old.masked) in current:
                continue
            if visibility == "public":
                level, where = "critical", "a public GitHub repo"
            elif remote:
                level, where = "critical", "a repo that has a remote, so it may have been pushed"
            else:
                level, where = "high", "this repo (it has no remote, so it may never have left this machine)"
            span = old.first_commit if old.first_commit == old.last_commit else \
                f"{old.first_commit} to {old.last_commit}"
            out.append(Finding(
                level, "history",
                f"an old version of `{rel}` still holds {old.kind}: {old.masked}",
                f"It is gone from the file now, but {old.versions} saved version(s) in {where} still have it "
                f"(commit {span}). Anyone with a copy of the history can read it.",
                "Rotate the secret. Rewriting history (for example with git filter-repo) only helps if "
                "nobody has fetched the repo since.",
                str(path), str(repo)))
    return out


def audit_staged(repo: Path) -> tuple[list[Finding], int]:
    """For a pre-commit hook: agent files and secrets about to be committed."""
    from .history import is_local_file, staged_agent_files, staged_text
    out: list[Finding] = []
    files = staged_agent_files(repo)
    for rel in files:
        if is_local_file(rel):
            out.append(Finding("critical", "git", f"you are about to commit your 'don't ask again' file: {rel}",
                               "It is meant to stay on your machine. Everything in it, including any password "
                               "inside a rule, goes into the repo's history for good.",
                               f"Run `git restore --staged {rel}` and add it to .gitignore (`leash --gitignore`).",
                               rel, str(repo)))
        for s in find_secrets(staged_text(repo, rel)):
            out.append(Finding("critical", "secret", f"{s.kind} is in a file you are about to commit: {s.masked}",
                               "Once it is committed, deleting it later does not take it out of the history.",
                               f"Take the value out of `{rel}`, use an environment variable instead, and rotate it.",
                               rel, str(repo)))
    return out, len(files)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (ORDER.get(f.level, 9), f.path, f.title))


def exit_code(findings: list[Finding], fail_on: str = "high") -> int:
    """2 when anything is critical, 1 when anything is high (unless fail_on says otherwise), else 0."""
    if fail_on == "never":
        return 0
    levels = {f.level for f in findings}
    if "critical" in levels:
        return 2
    if "high" in levels and fail_on == "high":
        return 1
    return 0
