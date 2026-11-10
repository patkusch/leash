"""Print findings for a person, or as JSON for a machine."""

from __future__ import annotations

import json
from collections import Counter

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
