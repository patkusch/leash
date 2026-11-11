# Contributing

Thank you for helping. The most useful thing to add is a secret shape leash misses, with proof that it is now caught and that nothing harmless is caught with it.

## Add a secret shape

Everything leash knows about secrets is in `src/leash/secrets.py`. There are two lists.

- **`_TOKEN_SHAPES`** is for keys a provider hands out with a fixed prefix, such as `ghp_` for GitHub. Add one line: a plain-English name and a pattern.
- **`_VALUE_IN_COMMAND`** is for passwords typed into a command, such as `sshpass -p`. Add a name, a pattern, and which part of the match is the password. Only that part is masked and checked against the placeholder list.

Write the name the way a person would say it: "a password passed to sshpass", not "SSHPASS_P_FLAG". It appears in every report.

A value that is a variable (`$PASSWORD`), or a placeholder such as `<your-token>`, `changeme` or `dummy-...`, is never counted. The placeholder words are in `_PLACEHOLDER`.

## Prove it with the benchmark

`bench/cases.py` has two lists.

1. Add the leak to **`PLANTED`**, written as the command it would be. Put a placeholder in braces where the secret goes, such as `{pw}` for a made-up password.
2. Add at least one harmless lookalike to **`BENIGN`**: the same tool used without a secret, such as the same command with `$PASSWORD`. This is what stops a new pattern from crying wolf.

If the new shape needs its own fake value, add it to `fakes()` in `bench/run.py`. **Build fake tokens at run time** from a prefix and random characters, like the ones already there. Never write a whole token-shaped string into a file. GitHub may block the push, and other scanners will flag the repo.

## Check your work

```bash
make bench
make test
```

`make bench` prints what was caught and rewrites `bench/results.md`. `make test` runs every test, including one that fails if any planted leak is missed or any lookalike is flagged. Both must pass.

You can also see how the finder does on your own real commands. This reads your Claude Code session logs on your machine and prints counts only:

```bash
python bench/real_commands.py
```

Add `--show` to see the flagged commands, with secrets masked. Do not paste that output into an issue if any of it is real.

## Anything else

- Keep leash free of extra packages. It runs on the Python standard library alone.
- Every finding says what the agent may do and why it matters, in plain words. "May run any command that starts with `git push`" is right. "Prefix rule with send-class verb" is not.
- leash never prints a secret in full, never writes one anywhere, and never starts an MCP server. Changes that would break any of these will not be merged.
- Report a security problem privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.
