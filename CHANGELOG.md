# Changelog

## 0.3.0 (unreleased)

- **Settings that act on their own.** Hooks, command helpers such as `apiKeyHelper` and `statusLine`, `enableAllProjectMcpServers`, and `additionalDirectories` are now checked. A hook that downloads and runs a script is high. A shared project file that approves its own MCP servers is high. Secrets in any of these commands are critical.
- **Which rules you actually use.** `--usage` reads your Claude Code session logs on this machine and adds "used 12 times" or "not used in the last 30 days" to every rule. An unused risky rule is marked as free to remove. A wide risky rule that was used for only a few exact commands gets those commands as the suggested replacement.
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
