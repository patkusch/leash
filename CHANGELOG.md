# Changelog

## 0.4.1 (2026-11-11)

- **Tested on real commands.** `bench/real_commands.py` runs the secret finder over the shell commands in your own Claude Code sessions. On the author's 12,999 different commands it flagged 32 (0.25%), nearly all test files with fake passwords on purpose. It showed two placeholder values to ignore (`dummy-...`, `fake_...`) and one missed shape, Stripe webhook secrets (`whsec_...`), now caught. The benchmark is now 34 of 34 caught, 0 of 34 false alarms.
- **`--fail-on medium`**, for runs that should fail on anything worth a look.
- **`--min-level`** hides findings below a level in every output format; the exit code still counts all of them.
- **JSON output** now says which tool and version wrote it, and a format number.
- **`.leashignore` patterns** such as `**/fixtures` and `*.example`, matched as in `.gitignore`.
- **Oversized settings files** (over 20 MB) are skipped and reported as not checked, instead of read whole.
- **`--help`** ends with seven example commands and what each exit code means.
- **CONTRIBUTING.md** explains how to add a secret shape and prove it with the benchmark.

## 0.4.0 (2026-11-11)

Compared against gitleaks, TruffleHog, detect-secrets, mcp-scan and the OWASP MCP Security Cheat Sheet; these are the gaps that comparison showed.

- **More agents.** Claude Desktop, Windsurf, Cline and Roo Code MCP files, and VS Code's user `mcp.json`. Cline's `autoApprove` and Roo Code's `alwaysAllow` lists are graded per tool.
- **How MCP servers are started.** Unpinned `npx`/`uvx`/`pipx`/`dlx` packages, plain-http remotes, `--privileged` or root/home/socket mounts in Docker, host networking, unpinned images, pipe-to-shell starts and the old SSE transport.
- **SpecStory chat transcripts.** Secrets in `.specstory/` chats, whether git ignores the folder, committed transcripts, deleted ones in history, and staged ones in the pre-commit hook.
- **Baseline.** `--write-baseline` and `--baseline`, like detect-secrets: only new findings fail. No secret is written to the file. The Action takes a `baseline` input.
- **Missing deny rules.** A `.env` file with no deny rule covering it is medium; key folders missing from your own deny list are noted; `--suggest` prints the rules to paste.
- **Markdown report.** `--markdown`, now used for the Action's run summary.
- **Benchmark.** 33 planted leaks and 32 lookalikes; 33 caught, 0 false alarms. The first run caught 29 and showed four tool flags to add: `redis-cli -a`, `sqlcmd -P`, `docker`/`podman`/`helm login -p`, `openssl -passin pass:`.
- **JSON with comments** (and trailing commas) is read instead of reported as unreadable.
- leash's own CI pins its actions to exact commits and Dependabot proposes updates.

## 0.3.0 (2026-11-10)

- **Settings that act on their own.** Hooks, command helpers such as `apiKeyHelper` and `statusLine`, `enableAllProjectMcpServers`, and `additionalDirectories` are now checked. A hook that downloads and runs a script is high. A shared project file that approves its own MCP servers is high. Secrets in any of these commands are critical.
- **Which rules you actually use.** `--usage` reads your Claude Code session logs on this machine and adds "used 12 times" or "not used in the last 30 days" to every rule. An unused risky rule is marked as free to remove. A wide risky rule that was used for only a few exact commands gets those commands as the suggested replacement.
- **SARIF for GitHub code scanning.** `--sarif`, and a `sarif-file` input on the Action, so findings show in a repo's Security tab, each pointed at the line of the rule.
- **`--fix`** removes rules that have a password or key in them, from Claude Code and Gemini CLI settings. The old file is copied first to `~/.leash/backups`, readable only by you and never inside the project. Secrets in MCP server settings and hooks are left for you to move, because removing them would break the server or hook.
- Rules in the newer form `Bash(npm run test *)` are now read as "starts with", like `Bash(npm run test:*)`.
- `Bash(git:*)`, `Bash(npm:*)` and similar bare program names are now high, because they cover `git push`, `npm publish` and the like.
- `defaultMode: bypassPermissions` in a project or local file is now medium, not critical: current Claude Code ignores it there (older versions did not). `auto` mode is listed as low.

## 0.2.0 (2026-11-10)

- **Old versions in git.** leash now reads every saved version of every agent file in git history, including deleted ones, and reports secrets that are gone from the file but still in the history. With a remote, that is critical.
- **Pre-commit hook.** `leash --install-hook` refuses a commit that would add your "don't ask again" file, or a secret in an agent or MCP file. It checks the staged version, not the file on disk. Also works with the pre-commit tool.
- **GitHub Action.** `uses: patkusch/leash@v0.2.0`, with the report on the run's summary page.
- **More agents.** Gemini CLI settings (allowed tools, approval mode, MCP `trust`), and MCP files for Cursor and VS Code.
- **Advice that fits the rule.** The "what to do" line now names the right fix for each kind of rule, such as a deny rule for a sensitive read, or a single site for web fetches. Low findings say "Nothing to do."
- **`--fail-on`** to choose which findings fail the run, and **`.leashignore`** to skip test fixtures.
- Your home folder's own settings are no longer read twice when you scan from home.

## 0.1.0 (2026-11-10)

- First version: Claude Code and Codex permission files, rule grades, secrets in rules, git status of the "don't ask again" file.
