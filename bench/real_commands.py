"""How often does the secret finder go off on real commands? Reads your own Claude Code session logs.

    python bench/real_commands.py            # counts only
    python bench/real_commands.py --show     # also the flagged commands, secrets masked, cut to 120 characters

Nothing is written or sent. This measures false alarms on everyday commands, which the planted
benchmark cannot: a flagged command here is either a real secret or a false alarm, and you decide which.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from leash.secrets import find_secrets, redact  # noqa: E402
from leash.usage import default_log_dir, read_uses  # noqa: E402


def main(days: int = 90, show: bool = False) -> int:
    uses, files = read_uses(default_log_dir(), days)
    commands = [u.command for u in uses if u.tool == "Bash" and u.command]
    unique = sorted(set(commands))
    kinds: Counter[str] = Counter()
    flagged = []
    for cmd in unique:
        found = find_secrets(cmd)
        if found:
            flagged.append(cmd)
            kinds.update(s.kind for s in found)
    print(f"{files} session file(s) from the last {days} days, {len(commands)} shell commands, {len(unique)} different.")
    print(f"Flagged as holding a secret: {len(flagged)} ({100 * len(flagged) / max(len(unique), 1):.2f}% of different commands).")
    for kind, n in kinds.most_common():
        print(f"  {n:4}  {kind}")
    if show:
        for cmd in flagged[:50]:
            print("  -", redact(cmd).replace("\n", " ")[:120])
    return 0


if __name__ == "__main__":
    sys.exit(main(show="--show" in sys.argv))
