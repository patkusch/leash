"""Find secret-shaped text inside a permission rule, a command, or a config value.

The point of this module is the "don't ask again" leak: Claude Code builds the
allow rule from the command the agent ran, so a password typed into that command
(PGPASSWORD=..., sshpass -p ..., mysql -p...) becomes part of the rule, and the
rule is saved to a file that often ends up in git.

Nothing here ever returns the full secret. Callers get a masked form only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Values that are clearly placeholders, not real secrets.
_PLACEHOLDER = re.compile(r"^(?:<[^>]*>|\.{3,}|\*{3,}|x{3,}|changeme|example|placeholder|redacted|your[-_][a-z_-]+)$", re.I)


@dataclass(frozen=True)
class Secret:
    kind: str      # plain-English description of what was found
    masked: str    # a safe form: first characters plus length
    start: int     # where it begins in the text
    end: int       # where it ends
    priority: int = 1   # lower wins when two matches start at the same place


def mask(value: str) -> str:
    """Return a form that identifies the secret without giving it away."""
    value = value.strip()
    if len(value) <= 4:
        return "*" * len(value)
    keep = 3 if len(value) < 12 else 4
    return f"{value[:keep]}… ({len(value)} characters)"


def _looks_real(value: str) -> bool:
    if not value or _PLACEHOLDER.match(value):
        return False
    if value.startswith(("$", "{{", "%", "<")):   # a variable, not a value
        return False
    return True


# Token shapes with a known prefix. (name, regex)
_TOKEN_SHAPES = [
    ("a GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("a GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("an Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("an OpenAI-style API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("an AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("a Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("a Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("a GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("an npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("a Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("a Stripe key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("a private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("a signed web token (JWT)", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

# Passwords and keys handed to a command. (name, regex, group holding the value)
_VALUE_IN_COMMAND = [
    ("a password or key set as an environment variable",
     re.compile(r"\b([A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)[A-Z0-9_]*)=(['\"]?)([^\s'\"$;&|]{4,})\2"), 3),
    ("a password passed to sshpass",
     re.compile(r"\bsshpass\s+-p\s*(['\"]?)([^\s'\"$]{3,})\1"), 2),
    ("a password glued to -p for mysql",
     re.compile(r"\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^|;&\n]*?\s-p(?!assword)(['\"]?)([^\s'\"$-][^\s'\"]{2,})\1"), 2),
    ("a password or token passed as a command option",
     re.compile(r"(?<![\w-])--?(?:password|passwd|pass|pw|token|api-?key|secret|access-?key|client-?secret)(?:=|\s+)(['\"]?)(?!\$)([^\s'\"$]{4,})\1", re.I), 2),
    ("a password inside a connection string",
     re.compile(r"\bpassword=(['\"]?)(?!\$)([^\s'\"&;]{3,})\1", re.I), 2),
    ("a password inside a URL",
     re.compile(r"\b[a-z][a-z0-9+.-]*://([^/\s:@]+):([^@\s/]{3,})@"), 2),
    ("a bearer or basic Authorization header",
     re.compile(r"\bAuthorization:\s*(?:Bearer|Basic|Token|token)\s+([^\s'\"$]{8,})", re.I), 1),
    ("an API key header",
     re.compile(r"\b(?:x-api-key|api-key|apikey)\s*:\s*([^\s'\"$]{8,})", re.I), 1),
    ("a user:password pair passed to curl",
     re.compile(r"(?<![\w-])-u\s+(['\"]?)([^\s:'\"$]+):([^\s'\"$]{3,})\1"), 3),
]


def find_secrets(text: str) -> list[Secret]:
    """Return every secret-shaped thing in text, masked, without overlaps."""
    if not text:
        return []
    found: list[Secret] = []
    for kind, rx in _TOKEN_SHAPES:
        for m in rx.finditer(text):
            found.append(Secret(kind, mask(m.group(0)) if "PRIVATE KEY" not in m.group(0) else "(key block)", m.start(), m.end()))
    for kind, rx, group in _VALUE_IN_COMMAND:
        for m in rx.finditer(text):
            value = m.group(group)
            if _looks_real(value):
                found.append(Secret(kind, mask(value), m.start(group), m.end(group), 0))
    # Drop overlaps: keep the earliest, then the longest.
    found.sort(key=lambda s: (s.start, s.priority, -(s.end - s.start)))
    kept: list[Secret] = []
    for s in found:
        if kept and s.start < kept[-1].end:
            continue
        kept.append(s)
    return kept


def redact(text: str) -> str:
    """The same text with every secret replaced by its masked form."""
    out = []
    last = 0
    for s in find_secrets(text):
        out.append(text[last:s.start])
        out.append("[" + s.masked + "]")
        last = s.end
    out.append(text[last:])
    return "".join(out)
