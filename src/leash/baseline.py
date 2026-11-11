"""A list of findings you have reviewed and accepted, so later runs report only new ones.

The same idea as detect-secrets' .secrets.baseline. The file holds a fingerprint per finding
(a hash of what it is and where), plus the masked title so a person can read it. It never
holds a secret.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import date
from pathlib import Path

from .audit import Finding

_USAGE_SUFFIX = re.compile(r"\s\((?:used \d+ times?|not used) in the last \d+ days\)$")


def _where(path: str) -> str:
    p = Path(path)
    try:
        return p.resolve().relative_to(Path(os.getcwd()).resolve()).as_posix()
    except (ValueError, OSError):
        home = str(Path.home())
        return path.replace(home, "~", 1) if path.startswith(home) else path


def fingerprint(f: Finding) -> str:
    title = _USAGE_SUFFIX.sub("", f.title)
    raw = "|".join((f.kind, f.level, title, _where(f.path), f.rule or ""))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def write(findings: list[Finding], path: Path) -> int:
    keep = [f for f in findings if f.level not in ("info",)]
    entries = sorted(({"fingerprint": fingerprint(f), "level": f.level, "title": _USAGE_SUFFIX.sub("", f.title),
                       "path": _where(f.path)} for f in keep), key=lambda e: (e["path"], e["title"]))
    unique = list({e["fingerprint"]: e for e in entries}.values())
    path.write_text(json.dumps({"tool": "leash", "version": 1, "created": date.today().isoformat(),
                                "findings": unique}, indent=2) + "\n", encoding="utf-8")
    return len(unique)


def load(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {e["fingerprint"] for e in data.get("findings", []) if isinstance(e, dict) and "fingerprint" in e}


def apply(findings: list[Finding], known: set[str], path: Path) -> list[Finding]:
    """Drop findings in the baseline; say how many were hidden and how many baseline entries are gone."""
    kept, hidden, seen = [], 0, set()
    for f in findings:
        fp = fingerprint(f)
        if fp in known and f.level != "info":
            hidden += 1
            seen.add(fp)
        else:
            kept.append(f)
    if hidden:
        kept.append(Finding("info", "baseline", f"{hidden} known finding(s) hidden by the baseline",
                            "They were reviewed and accepted earlier. Only new findings are shown.", "", str(path)))
    stale = len(known - seen)
    if stale:
        kept.append(Finding("info", "baseline", f"{stale} baseline entr{'y' if stale == 1 else 'ies'} no longer match anything",
                            "Those findings were fixed or changed.",
                            "Run `leash --write-baseline` again to tidy the file.", str(path)))
    return kept
