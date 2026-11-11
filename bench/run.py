"""Run leash's secret finder over the planted leaks and the lookalikes, and print what it caught.

    python bench/run.py            # table on screen
    python bench/run.py --write    # also write bench/results.md
"""

from __future__ import annotations

import random
import string
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

from cases import BENIGN, PLANTED  # noqa: E402
from leash.secrets import find_secrets  # noqa: E402

rng = random.Random(20261111)


def chars(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def fakes() -> dict[str, str]:
    up = string.ascii_uppercase + string.digits
    return {
        "pw": "Tq" + chars(10),
        "gh": "ghp_" + chars(36),
        "ant": "sk-ant-api03-" + chars(40, string.ascii_letters + string.digits + "-_"),
        "aws": "AKIA" + "".join(rng.choice(up) for _ in range(16)),
        "slack": "xoxb-" + chars(12, string.digits) + "-" + chars(24),
        "stripe": "sk_" + "test_" + chars(24),
        "whsec": "wh" + "sec_" + chars(32),
        "npm": "npm_" + chars(36),
        "hf": "hf_" + chars(34),
        "gl": "glpat-" + chars(20),
        "jwt": "eyJ" + chars(20) + "." + chars(30) + "." + chars(30),
    }


def rule(cmd: str) -> str:
    return f"Bash({cmd}:*)"


def run() -> dict:
    f = fakes()
    by_cat: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    missed = []
    for cat, tmpl in PLANTED:
        hit = bool(find_secrets(rule(tmpl.format(**f))))
        by_cat[cat][0] += hit
        by_cat[cat][1] += 1
        if not hit:
            missed.append(tmpl)
    false_alarms = [cmd for cmd in BENIGN if find_secrets(rule(cmd))]
    return {"by_cat": dict(by_cat), "missed": missed, "false_alarms": false_alarms,
            "caught": sum(v[0] for v in by_cat.values()), "planted": len(PLANTED), "benign": len(BENIGN)}


def table(r: dict) -> str:
    lines = ["| Kind of leak | Caught |", "|---|---|"]
    for cat, (hit, total) in r["by_cat"].items():
        lines.append(f"| {cat} | {hit} of {total} |")
    lines.append(f"| **all planted leaks** | **{r['caught']} of {r['planted']}** |")
    lines += ["", f"False alarms on {r['benign']} harmless lookalike commands: **{len(r['false_alarms'])}**."]
    if r["missed"]:
        lines += ["", "Missed:"] + [f"- `{m}`" for m in r["missed"]]
    if r["false_alarms"]:
        lines += ["", "False alarms:"] + [f"- `{m}`" for m in r["false_alarms"]]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    result = run()
    out = table(result)
    print(out)
    if "--write" in sys.argv:
        (HERE / "results.md").write_text(
            "# leash secret-finder benchmark\n\nMade by `python bench/run.py --write`. Every planted value is "
            "fake and built at run time.\n\n" + out +
            "\n## What this does and does not show\n\n"
            "- The first run of this benchmark caught 29 of 33. The four misses were tool flags "
            "(`redis-cli -a`, `sqlcmd -P`, `docker login -p`, `openssl -passin pass:`); the finder was then taught them.\n"
            "- The cases and the finder were written by the same person, so this shows the finder does what it "
            "claims. It is not a measure of how it does on leaks nobody has seen yet.\n"
            "- On real commands: run over the author's own Claude Code sessions (12,999 different shell commands "
            "in 90 days, by `python bench/real_commands.py`), the finder flagged 32 (0.25%). Nearly all were test "
            "files written with fake passwords on purpose, which is correct. Two were placeholder values "
            "(`dummy-...`), now ignored. One was a real-shaped Stripe webhook secret (`whsec_...`) that the finder "
            "had missed, now caught.\n"
            "- The first three kinds are the shapes that, per one write-up of the Apiiro set, got past both "
            "gitleaks and TruffleHog (215 secrets). leash was not run on that set, which is not public.\n",
            encoding="utf-8")
    sys.exit(0 if not result["missed"] and not result["false_alarms"] else 1)
