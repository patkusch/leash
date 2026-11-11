# leash secret-finder benchmark

Made by `python bench/run.py --write`. Every planted value is fake and built at run time.

| Kind of leak | Caught |
|---|---|
| env var before command | 5 of 5 |
| sshpass | 2 of 2 |
| mysql -p | 2 of 2 |
| password option | 4 of 4 |
| tool flag | 4 of 4 |
| password in URL | 3 of 3 |
| connection string | 1 of 1 |
| header | 2 of 2 |
| curl -u | 1 of 1 |
| provider token | 10 of 10 |
| **all planted leaks** | **34 of 34** |

False alarms on 34 harmless lookalike commands: **0**.

## What this does and does not show

- The first run of this benchmark caught 29 of 33. The four misses were tool flags (`redis-cli -a`, `sqlcmd -P`, `docker login -p`, `openssl -passin pass:`); the finder was then taught them.
- The cases and the finder were written by the same person, so this shows the finder does what it claims. It is not a measure of how it does on leaks nobody has seen yet.
- On real commands: run over the author's own Claude Code sessions (12,999 different shell commands in 90 days, by `python bench/real_commands.py`), the finder flagged 32 (0.25%). Nearly all were test files written with fake passwords on purpose, which is correct. Two were placeholder values (`dummy-...`), now ignored. One was a real-shaped Stripe webhook secret (`whsec_...`) that the finder had missed, now caught.
- The first three kinds are the shapes that, per one write-up of the Apiiro set, got past both gitleaks and TruffleHog (215 secrets). leash was not run on that set, which is not public.
