"""Grade one permission rule: what does it let the agent do without asking?

Rule syntax (Claude Code):
    Tool                  every use of the tool
    Tool(spec)            uses matching spec
    Bash(git push:*)      any command that starts with "git push"
    Bash(npm test)        exactly this command
    Read(~/.ssh/**)       files matching a path pattern
    WebFetch(domain:x.y)  one website
    mcp__server           every tool on an MCP server
    mcp__server__tool     one tool on that server
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .secrets import redact

LEVELS = ("critical", "high", "medium", "low")


@dataclass(frozen=True)
class Grade:
    level: str   # one of LEVELS
    what: str    # plain English: what the agent may now do without asking
    why: str     # plain English: why that matters


@dataclass(frozen=True)
class Rule:
    raw: str
    tool: str
    spec: str | None

    @property
    def is_prefix(self) -> bool:
        return self.spec is not None and self.spec.endswith(":*")

    @property
    def command(self) -> str | None:
        """For Bash rules: the command text without the trailing ':*'."""
        if self.tool != "Bash" or self.spec is None:
            return None
        return self.spec[:-2] if self.is_prefix else self.spec


def parse(raw: str) -> Rule:
    raw = raw.strip()
    m = re.fullmatch(r"([A-Za-z_][\w\-]*)\((.*)\)", raw, re.S)
    if m:
        return Rule(raw, m.group(1), m.group(2))
    return Rule(raw, raw, None)


# Commands that move data off the machine or change things outside the project.
_SEND = ("git push", "gh ", "gh", "curl", "wget", "ssh", "scp", "sftp", "rsync", "npm publish", "yarn publish",
         "pnpm publish", "docker push", "aws", "gcloud", "az", "kubectl", "helm", "terraform", "pulumi", "twine",
         "cargo publish", "heroku", "vercel", "netlify", "fly", "flyctl", "wrangler", "firebase", "supabase",
         "mail", "sendmail", "slack", "nc", "ncat", "netcat", "telnet", "ftp")
# Commands that delete or overwrite.
_DESTROY = ("rm", "rmdir", "git reset", "git clean", "git checkout .", "git restore", "git branch -D", "git branch -d",
            "sudo", "chmod", "chown", "dd", "mkfs", "kill", "killall", "pkill", "shutdown", "reboot", "truncate",
            "shred", "launchctl", "systemctl", "crontab", "defaults write")
# Commands that run arbitrary programs: as broad as allowing everything.
_RUN_ANYTHING = ("bash", "sh", "zsh", "fish", "eval", "exec", "source", "python", "python3", "node", "deno", "bun",
                 "ruby", "perl", "php", "osascript", "xargs", "env", "nohup", "screen", "tmux", "docker run",
                 "docker exec", "ssh", "sshpass")
# Commands that run installers or project scripts, which can fetch and execute code.
_RUN_SCRIPTS = ("npm", "npx", "yarn", "pnpm", "make", "cargo", "go", "pip", "pip3", "uv", "uvx", "pipx", "poetry",
                "docker", "brew", "apt", "apt-get", "gem", "bundle", "mvn", "gradle", "./gradlew", "composer")
# Database clients: can read or change live data.
_DATABASE = ("psql", "mysql", "mysqldump", "mariadb", "mongo", "mongosh", "redis-cli", "sqlite3", "pg_dump", "pg_restore",
             "mongodump", "mongorestore")
# Commands that put changes into git history without anyone reading them.
_HISTORY = ("git commit", "git add", "git merge", "git rebase", "git cherry-pick", "git stash", "git tag", "git am",
            "git apply")
# Commands that only read, list or test.
_READ_ONLY = ("ls", "cat", "head", "tail", "less", "more", "wc", "grep", "rg", "ag", "find", "fd", "git status",
              "git log", "git diff", "git show", "git branch", "git remote", "git fetch", "git blame", "pwd", "echo",
              "which", "file", "stat", "tree", "du", "df", "date", "whoami", "ps", "top", "pytest", "python -m pytest",
              "npm test", "npm run test", "npm run lint", "npm run build", "npm run typecheck", "yarn test",
              "pnpm test", "cargo test", "cargo check", "cargo build", "go test", "go build", "go vet", "jest",
              "vitest", "mocha", "mvn test", "tsc", "eslint", "ruff", "black", "prettier", "mypy", "pyright", "flake8",
              "isort", "shellcheck", "diff", "sort", "uniq", "cut", "awk", "sed -n", "jq", "yq", "man", "type",
              "printenv", "sleep", "true", "false", "test")

_SENSITIVE_PATH = re.compile(r"(?:^|/)(?:\.ssh|\.aws|\.gnupg|\.netrc|\.env[^/]*|\.npmrc|\.pypirc|\.docker|\.kube|"
                             r"\.config/gh|\.git-credentials|credentials[^/]*|id_rsa|id_ed25519|.*\.pem|.*\.key|"
                             r"Keychains?|\.claude\.json|\.codex)(?:/|$)", re.I)
_WRITE_ACTION = re.compile(r"(?:^|_)(?:send|post|put|delete|remove|create|write|update|publish|push|execute|exec|"
                           r"run|deploy|merge|pay|transfer|email|message|invite|share|upload)(?:_|$)", re.I)


def _starts_with_any(command: str, prefixes: tuple[str, ...]) -> str | None:
    """The longest prefix in `prefixes` that `command` starts with, as a whole word, or None."""
    best = None
    for p in prefixes:
        p = p.strip()
        if command == p or command.startswith(p + " ") or command.startswith(p + "\t"):
            if best is None or len(p) > len(best):
                best = p
    return best


def _strip_env_prefix(command: str) -> str:
    """'PGPASSWORD=x psql -c ...' -> 'psql -c ...'."""
    words = command.split()
    while words and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0]):
        words.pop(0)
    return " ".join(words)


def _grade_bash(rule: Rule) -> Grade:
    spec = (rule.spec or "").strip()
    if spec in ("", "*", "*:*", ":*", "**"):
        return Grade("critical", "run any command at all",
                     "This is the same as turning permissions off. Anything the agent types runs, including "
                     "sending files off your machine or deleting them.")
    command = _strip_env_prefix(rule.command or "")
    head = command.split(":")[0] if not rule.is_prefix else command
    shown = redact(head)
    if len(shown) > 70:
        shown = shown[:67] + "..."
    scope = "run any command that starts with" if rule.is_prefix else "run exactly the command"
    # A wildcard right after the command name widens it: Bash(git *:*) covers git push.
    tokens = command.split()
    if len(tokens) >= 2 and tokens[1] == "*":
        return Grade("high", f"run `{tokens[0]}` followed by anything",
                     "The `*` inside the rule covers every sub-command, such as `git push` under `git *`.")
    g = _grade_bash_head(head, shown, scope)
    if "*" in command and "*" not in head.split()[0]:
        return Grade("medium" if g.level == "low" else g.level, g.what,
                     g.why + " The `*` inside the rule is a wildcard, so it matches more than this exact text.")
    return g


def _grade_bash_head(head: str, shown: str, scope: str) -> Grade:
    if head.startswith("git push") and ("--force" in head or " -f" in head):
        return Grade("high", f"{scope} `{shown}`",
                     "A forced push rewrites what is on the server. Other people's work, or a leaked secret's "
                     "removal, can be undone or redone without anyone looking.")
    if (p := _starts_with_any(head, _SEND)):
        return Grade("high", f"{scope} `{shown}`",
                     f"`{p}` can send files or data off your machine, or change things outside this project. "
                     "If a secret is in the working tree, this is how it leaves.")
    if (p := _starts_with_any(head, _DESTROY)):
        return Grade("high", f"{scope} `{shown}`",
                     f"`{p}` can delete or overwrite files and settings without a second look.")
    if (p := _starts_with_any(head, _RUN_ANYTHING)):
        return Grade("high", f"{scope} `{shown}`",
                     f"`{p}` runs whatever program or code it is given, so this is almost as broad as "
                     "allowing every command.")
    if (p := _starts_with_any(head, _DATABASE)):
        return Grade("medium", f"{scope} `{shown}`",
                     f"`{p}` talks to a database. It can read or change live data, and a password typed into "
                     "the command becomes part of this rule.")
    if (p := _starts_with_any(head, _HISTORY)):
        return Grade("medium", f"{scope} `{shown}`",
                     f"`{p}` puts changes into git history without you reading them. Paired with a push rule, "
                     "that is the path the leaked secrets took.")
    if (p := _starts_with_any(head, _READ_ONLY)):
        return Grade("low", f"{scope} `{shown}`",
                     f"`{p}` reads, lists or tests. On its own it cannot change or send anything.")
    if (p := _starts_with_any(head, _RUN_SCRIPTS)):
        return Grade("medium", f"{scope} `{shown}`",
                     f"`{p}` runs installers and project scripts, which can fetch and run code you have not read.")
    return Grade("medium", f"{scope} `{shown}`",
                 "leash does not know this command. Check what it can reach: files, the network, other machines.")


def _grade_tool(rule: Rule) -> Grade:
    tool, spec = rule.tool, rule.spec
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        if spec is None or spec.strip() in ("*", "**", "**/*"):
            return Grade("medium", "change or create any file the agent can reach",
                         "Edits go in without you seeing them. A config file or a script can be changed quietly.")
        if _SENSITIVE_PATH.search(spec) or spec.startswith(("~", "/")):
            return Grade("high", f"change files matching `{spec}`",
                         "That pattern reaches outside the project or into a place where keys and settings live.")
        return Grade("low", f"change files matching `{spec}`",
                     "Only those files. Still, nobody reads the edit before it lands.")
    if tool in ("Read", "Glob", "Grep", "LS"):
        if spec and _SENSITIVE_PATH.search(spec):
            return Grade("high", f"read files matching `{spec}`",
                         "That is where keys, tokens and passwords are kept. What the agent reads can end up "
                         "in a command, a commit or a web request.")
        if spec and spec.startswith(("~", "/")):
            return Grade("medium", f"read files matching `{spec}`",
                         "That reaches outside the project.")
        return Grade("low", "read files in the project" if not spec else f"read files matching `{spec}`",
                     "Reading inside the project is normal. Nothing leaves the machine by itself.")
    if tool in ("WebFetch", "WebSearch"):
        if spec and spec.startswith("domain:"):
            return Grade("low", f"fetch pages from `{spec[7:]}`",
                         "One site only. Text from your session can still be sent to it in the request.")
        return Grade("medium", "send a request to any website",
                     "Anything in the agent's context can go into that request. This is the shape of the "
                     "'sends your email address to websites' report.")
    if tool.startswith("mcp__"):
        parts = tool.split("__")
        server = parts[1] if len(parts) > 1 else "?"
        if len(parts) >= 3:
            name = "__".join(parts[2:])
            if _WRITE_ACTION.search(name):
                return Grade("medium", f"use the `{name}` tool on the `{server}` server",
                             "The tool's name says it sends, changes or deletes something. That happens with "
                             "no one looking.")
            return Grade("low", f"use the `{name}` tool on the `{server}` server",
                         "One tool. Check what it does if you do not recognise it.")
        return Grade("medium", f"use every tool on the `{server}` server, including ones added later",
                     "A server update can add a tool that sends or deletes, and it is already allowed.")
    if tool in ("Task", "Agent"):
        return Grade("medium", "start sub-agents",
                     "Sub-agents inherit these same rules and run out of sight.")
    if tool in ("TodoRead", "TodoWrite", "BashOutput", "KillShell", "ExitPlanMode", "AskUserQuestion",
                "EnterPlanMode", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "Skill"):
        return Grade("low", f"use `{tool}`", "Housekeeping. Nothing leaves the machine and no file changes.")
    return Grade("medium", f"use `{tool}`" + (f" with `{spec}`" if spec else ""),
                 "leash does not know this tool. Check what it can reach.")


def grade(rule: Rule | str) -> Grade:
    if isinstance(rule, str):
        rule = parse(rule)
    if rule.tool == "Bash":
        return _grade_bash(rule)
    return _grade_tool(rule)


def grade_mode(mode: str | None) -> Grade | None:
    """Grade a settings 'defaultMode' value. None when the mode is fine."""
    if mode in (None, "default", "plan"):
        return None
    if mode == "bypassPermissions":
        return Grade("critical", "do everything without asking",
                     "The permission system is off. Allow and deny lists no longer matter.")
    if mode == "dontAsk":
        return Grade("high", "run anything not on the deny list without asking",
                     "Only the deny list holds. Everything else is silent.")
    if mode == "auto":
        return Grade("low", "let an automatic reviewer decide which actions need your yes (auto mode)",
                     "Risky actions are still stopped, but by a model, not by you.")
    if mode == "acceptEdits":
        return Grade("medium", "change any file without asking",
                     "File edits go in unread. Commands still ask.")
    return Grade("medium", f"run in mode `{mode}`", "leash does not know this mode.")
