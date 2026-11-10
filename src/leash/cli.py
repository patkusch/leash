"""Command line: `leash [folders] [options]`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, gitcheck, hook, usage
from .audit import Finding, audit_history, audit_source, audit_staged, exit_code
from .report import as_json, text
from .rules import grade, parse
from .secrets import find_secrets, redact
from .sources import scan


def _grade_rules(rules: list[str]) -> int:
    worst = 0
    for raw in rules:
        g = grade(parse(raw))
        print(f"{g.level.upper():9} {redact(raw)}")
        print(f"          may: {g.what}")
        print(f"          why: {g.why}")
        for s in find_secrets(raw):
            print(f"          SECRET: {s.kind}: {s.masked}")
            worst = max(worst, 2)
        worst = max(worst, {"critical": 2, "high": 1}.get(g.level, 0))
    return worst


def _repo(folder: str) -> Path | None:
    root = gitcheck.repo_root(Path(folder).resolve())
    if root is None:
        print(f"leash: {folder} is not inside a git repo", file=sys.stderr)
    return root


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="leash",
        description="See what your coding agents may do without asking, and whether a secret slipped into that list.")
    ap.add_argument("folders", nargs="*", default=["."],
                    help="folders to search for projects (default: the current folder)")
    ap.add_argument("--rule", action="append", default=[], metavar="RULE",
                    help="grade one permission rule and exit, e.g. --rule 'Bash(git push:*)'")
    ap.add_argument("--json", action="store_true", help="print findings as JSON")
    ap.add_argument("--all", action="store_true", help="show low findings too")
    ap.add_argument("--fail-on", choices=("high", "critical", "never"), default="high",
                    help="which findings make leash exit with an error (default: high)")
    ap.add_argument("--no-user", action="store_true", help="skip the settings in your home folder")
    ap.add_argument("--no-git", action="store_true", help="do not ask git anything (also skips history)")
    ap.add_argument("--no-history", action="store_true", help="do not read old commits for secrets")
    ap.add_argument("--no-gh", action="store_true", help="do not ask GitHub whether a repo is public")
    ap.add_argument("--gitignore", action="store_true",
                    help="add .claude/settings.local.json to .gitignore in every repo where it is missing")
    ap.add_argument("--staged", action="store_true",
                    help="check only the files staged for the next commit (what the pre-commit hook runs)")
    ap.add_argument("--install-hook", action="store_true",
                    help="make leash the pre-commit hook of the repo you are in")
    ap.add_argument("--usage", nargs="?", type=int, const=30, metavar="DAYS",
                    help="count how often each rule was used in your Claude Code sessions (default: last 30 days)")
    ap.add_argument("--logs", metavar="DIR", help="where Claude Code keeps session logs (default: ~/.claude/projects)")
    ap.add_argument("--version", action="version", version=f"leash {__version__}")
    args = ap.parse_args(argv)

    if args.rule:
        return _grade_rules(args.rule)

    if args.install_hook:
        repo = _repo(args.folders[0])
        if repo is None:
            return 3
        try:
            print(hook.install(repo))
        except hook.HookExists as e:
            print(f"leash: {e}", file=sys.stderr)
            return 3
        return 0

    if args.staged:
        repo = _repo(args.folders[0])
        if repo is None:
            return 3
        findings, n = audit_staged(repo)
        if args.json:
            print(as_json(findings, n))
        elif findings:
            print(text(findings, n, show_low=True, what="staged agent file"), end="")
            print("Commit stopped by leash. Fix the above, or skip the check once with `git commit --no-verify`.")
        return exit_code(findings, args.fail_on)

    result = scan([Path(f) for f in args.folders], include_user=not args.no_user)
    if args.gitignore and not args.no_git:
        done: set[Path] = set()
        for src in result.sources:
            if src.kind == "claude-local" and src.project is not None:
                root = gitcheck.repo_root(src.project)
                if root and root not in done:
                    done.add(root)
                    if gitcheck.add_to_gitignore(root):
                        print(f"added .claude/settings.local.json to {root / '.gitignore'}", file=sys.stderr)

    findings = []
    for src in result.sources:
        findings.extend(audit_source(src, use_git=not args.no_git, use_gh=not args.no_gh))
    if not args.no_git and not args.no_history:
        repos = list(result.repos)
        for r in result.roots:
            top = gitcheck.repo_root(r) if r.is_dir() else None
            if top and top not in repos:
                repos.append(top)
        for repo in repos:
            findings.extend(audit_history(repo, result.ignores, result.roots, use_gh=not args.no_gh))

    if args.usage:
        add_usage(findings, args.usage, Path(args.logs).expanduser() if args.logs else usage.default_log_dir())

    if args.json:
        print(as_json(findings, len(result.sources)))
    else:
        print(text(findings, len(result.sources), show_low=args.all), end="")
    return exit_code(findings, args.fail_on)


def add_usage(findings: list[Finding], days: int, log_dir: Path) -> None:
    """Add 'used N times' to each rule finding, and advice for unused or wide rules."""
    uses, files = usage.read_uses(log_dir, days)
    findings.append(Finding("info", "usage", f"rule use counted from {files} Claude Code session(s) in the last {days} days",
                            "Read from the session logs on this machine. Nothing was kept or sent.", "", str(log_dir)))
    for f in findings:
        if f.kind != "rule" or not f.source_rule:
            continue
        n = usage.count(f.source_rule, f.project, uses)
        if n is None:
            continue
        if n == 0:
            f.title += f" (not used in the last {days} days)"
            if f.level in ("critical", "high", "medium"):
                f.fix = f"It was not used in the last {days} days, so removing it costs nothing. " + f.fix
        else:
            f.title += f" (used {n} time{'s' if n != 1 else ''} in the last {days} days)"
            top = usage.top_commands(f.source_rule, f.project, uses)
            if top and f.level in ("critical", "high") and len(set(top)) <= 3:
                exact = ", ".join(f"`Bash({c})`" for c in top)
                f.fix += f" It was used for: {exact}. Allowing just those would cover what you use."


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
