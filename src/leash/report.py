"""Print findings for a person, or as JSON for a machine."""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

from . import __version__

from .audit import Finding, sort_findings

_HEAD = {
    "critical": "CRITICAL  fix today",
    "high": "HIGH      can send, delete, run anything, or read where keys live",
    "medium": "MEDIUM    worth a look",
    "low": "LOW       fine, listed so you know",
    "info": "INFO",
}


def text(findings: list[Finding], sources_checked: int, show_low: bool = True, what: str = "file") -> str:
    lines: list[str] = []
    findings = sort_findings(findings)
    counts = Counter(f.level for f in findings)
    lines.append(f"leash looked at {sources_checked} {what}(s).")
    if not findings:
        lines.append("No standing permissions and no secrets found.")
        return "\n".join(lines) + "\n"
    summary = ", ".join(f"{counts[l]} {l}" for l in ("critical", "high", "medium", "low", "info") if counts[l])
    lines.append(f"Found: {summary}.")
    lines.append("")
    current = None
    for f in findings:
        if f.level == "low" and not show_low:
            continue
        if f.level != current:
            current = f.level
            lines.append(_HEAD[current])
            lines.append("-" * len(_HEAD[current]))
        lines.append(f"* {f.title}")
        if f.rule:
            lines.append(f"    rule: {f.rule}")
        lines.append(f"    in:   {f.path}")
        if f.detail:
            lines.append(f"    why:  {f.detail}")
        if f.fix:
            lines.append(f"    do:   {f.fix}")
        lines.append("")
    if not show_low and counts["low"]:
        lines.append(f"({counts['low']} low findings hidden; use --all to see them)")
    return "\n".join(lines).rstrip() + "\n"


def as_json(findings: list[Finding], sources_checked: int) -> str:
    findings = sort_findings(findings)
    counts = Counter(f.level for f in findings)
    return json.dumps({
        "files_checked": sources_checked,
        "summary": {l: counts[l] for l in ("critical", "high", "medium", "low", "info")},
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning"}
_SEVERITY = {"critical": "9.5", "high": "7.5", "medium": "5.0"}
_KIND_NAME = {
    "secret": "A secret is saved in an agent settings file",
    "history": "A secret is still in an old version of an agent file",
    "rule": "An agent may do this without asking",
    "mode": "An agent's permission mode skips prompts",
    "git": "An agent permission file and git",
    "hook": "A command in agent settings runs on its own",
    "mcp": "MCP servers start or run without a prompt",
    "codex": "Codex CLI approval or sandbox setting",
    "gemini": "Gemini CLI approval setting",
}


def _line_of(path: Path, f: Finding) -> int:
    needle = f.source_rule or (f.rule if f.rule and "[" not in f.rule else None)
    if not needle:
        return 1
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 1
    for probe in (json.dumps(needle)[1:-1], needle):
        i = text.find(probe)
        if i >= 0:
            return text.count("\n", 0, i) + 1
    return 1


def _uri(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_uri()


def as_sarif(findings: list[Finding], base: Path | None = None) -> str:
    """SARIF 2.1.0, for GitHub code scanning. Only medium and worse findings are included."""
    base = base or Path(os.getcwd())
    findings = [f for f in sort_findings(findings) if f.level in _SARIF_LEVEL]
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rid = f"leash/{f.kind}/{f.level}"
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f"{f.kind}-{f.level}",
                "shortDescription": {"text": f"{_KIND_NAME.get(f.kind, f.kind)} ({f.level})"},
                "helpUri": "https://github.com/patkusch/leash#what-it-checks",
                "properties": {"security-severity": _SEVERITY[f.level], "tags": ["security", "ai-agents"]},
            }
        path = Path(f.path)
        msg = f.title + (f". {f.detail}" if f.detail else "") + (f" What to do: {f.fix}" if f.fix else "")
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL[f.level],
            "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": _uri(path, base)},
                "region": {"startLine": _line_of(path, f)},
            }}],
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "leash", "version": __version__,
                                "informationUri": "https://github.com/patkusch/leash",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }, indent=2)
