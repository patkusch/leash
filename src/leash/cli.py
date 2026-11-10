"""Command line: `leash [folders] [options]`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, gitcheck
from .audit import audit_source, exit_code
from .report import as_json, text
from .rules import grade, parse
from .secrets import find_secrets, redact
from .sources import discover


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
    ap.add_argument("--no-user", action="store_true", help="skip your home-folder settings (Claude Code and Codex)")
    ap.add_argument("--no-git", action="store_true", help="do not ask git whether files are committed or ignored")
    ap.add_argument("--no-gh", action="store_true", help="do not ask GitHub whether a repo is public")
    ap.add_argument("--gitignore", action="store_true",
                    help="add .claude/settings.local.json to .gitignore in every repo where it is missing")
    ap.add_argument("--version", action="version", version=f"leash {__version__}")
    args = ap.parse_args(argv)

    if args.rule:
        return _grade_rules(args.rule)

    sources = discover([Path(f) for f in args.folders], include_user=not args.no_user)
    findings = []
    for src in sources:
        findings.extend(audit_source(src, use_git=not args.no_git, use_gh=not args.no_gh))

    if args.gitignore and not args.no_git:
        done: set[Path] = set()
        for src in sources:
            if src.kind == "claude-local" and src.project is not None:
                root = gitcheck.repo_root(src.project)
                if root and root not in done:
                    done.add(root)
                    if gitcheck.add_to_gitignore(root):
                        print(f"added .claude/settings.local.json to {root / '.gitignore'}", file=sys.stderr)
        findings = []
        for src in sources:
            findings.extend(audit_source(src, use_git=True, use_gh=not args.no_gh))

    if args.json:
        print(as_json(findings, len(sources)))
    else:
        print(text(findings, len(sources), show_low=args.all), end="")
    return exit_code(findings)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
