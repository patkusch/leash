# leash

## What it does

leash reads the files where your coding agents keep their standing permissions: the "yes, and don't ask again" answers you gave Claude Code, the approval and sandbox settings of Codex CLI, Gemini CLI's allowed tools, and the MCP server files of Claude Code, Cursor, VS Code and Gemini CLI.

It tells you four things in plain English:

1. **What the agent may now do without asking.** Each rule is graded: can it send things off your machine, delete things, run any program, or only read and test?
2. **Whether a password or key is written into one of those rules.** When you let a command through with "don't ask again", the rule is built from the command text. If the command had a password in it, the password is now in the rule.
3. **Whether that file is in git.** If it is committed, or was committed once, everything in it is in the repo's history. Deleting the file does not help.
4. **Whether an old version still holds a secret.** leash reads every saved version of every agent file in git history, including files you have since deleted, and reports any secret that is no longer in the file but is still in the history.

It can also stop the leak before it happens: as a pre-commit hook, it refuses a commit that would add your "don't ask again" file or a secret in an agent file.

It runs on your own computer. It never prints a secret in full, never writes one anywhere, and goes online only to ask GitHub whether a repo is public (and only if you have the `gh` tool; `--no-gh` turns that off).

## Why it matters

In November 2026 the security firm Apiiro [reported](https://thehackernews.com/2026/11/claude-codes-dont-ask-again-file.html) that 1,122 of the 104,185 copies of `.claude/settings.local.json` on public GitHub held real secrets, 2,539 in all. The file is where Claude Code saves "don't ask again" rules. The passwords got there through commands like `PGPASSWORD=...`, `sshpass -p ...` and `mysql -p...`. The file was committed, and then it was public.

The same week, a report that Claude Code sends your email address to websites through tool calls, and another that ChatGPT Desktop forwards your SSH agent to remote machines, made the same point from different angles: the risk is in what the agent may do quietly, not in what it does while you watch.

leash shows you that list before someone else finds it.

## Install and run

Python 3.11 or newer. No other packages.

```bash
pip install git+https://github.com/patkusch/leash
```

Then, from any folder:

```bash
leash
```

That looks at your own Claude Code and Codex settings, plus every project under the current folder. Point it at more folders if you like:

```bash
leash ~/code ~/work
```

Useful options:

| Option | What it does |
|---|---|
| `--all` | also show the low findings (rules that only read or test) |
| `--json` | print findings as JSON for a script or CI |
| `--fail-on critical` | exit with an error only for critical findings (`high` is the default, `never` always passes) |
| `--gitignore` | add `.claude/settings.local.json` to `.gitignore` in every repo where it is not ignored |
| `--rule 'Bash(git push:*)'` | grade one rule and stop, without looking at any file |
| `--install-hook` | make leash the pre-commit hook of the repo you are in |
| `--staged` | check only what is staged for the next commit (this is what the hook runs) |
| `--no-user` | skip the files in your home folder |
| `--no-history` | do not read old commits |
| `--no-git` | do not ask git anything, including history |
| `--no-gh` | do not ask GitHub whether a repo is public |

Exit code: `2` if anything is critical (a secret, a fully open agent, a committed "don't ask again" file on a public repo), `1` if anything is high, `0` otherwise.

To skip a folder, such as a test fixture with fake passwords in it, list it in a `.leashignore` file, one path per line. A folder you name on the command line is always checked, even if it is listed.

## Stop it before the commit

From inside a repo:

```bash
leash --install-hook
```

From then on, `git commit` is refused if it would add a `.claude/settings.local.json` file, or a secret in any agent or MCP file. Only the staged version is checked, so fixing the file on disk without staging it again does not get past it. If the repo already has a pre-commit hook, leash leaves it alone and prints the one line to add to it.

If you use the [pre-commit](https://pre-commit.com) tool, add this to `.pre-commit-config.yaml` instead:

```yaml
repos:
  - repo: https://github.com/patkusch/leash
    rev: v0.2.0
    hooks:
      - id: leash
```

## In GitHub Actions

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0          # full history, so old versions are checked too
- uses: patkusch/leash@v0.2.0
  with:
    path: .
    fail-on: critical       # or high, or never
```

The report is printed in the log and on the run's summary page. No other packages are installed.

## What the output looks like

This is leash on the example project in `docs/example`, which has two made-up passwords planted in it. (The repo's `.leashignore` skips that folder, so a scan of the whole repo comes back clean.)

```
leash looked at 1 file(s).
Found: 2 critical, 4 high, 3 medium, 2 low, 1 info.

CRITICAL  fix today
-------------------
* a password or key set as an environment variable is written into a 'don't ask again' rule: exam… (21 characters)
    rule: Bash(PGPASSWORD=[exam… (21 characters)] psql -h db.internal -U app -c "select count(*) from orders":*)
    in:   docs/example/.claude/settings.local.json
    why:  This is in local project settings (where 'don't ask again' writes). Anyone who can read this file has the secret.
    do:   Delete the rule from the allow list and run the command without the password in it next time.
          Then rotate the secret: treat it as already seen.

HIGH      the agent can send, delete or run anything here
---------------------------------------------------------
* may run any command that starts with `git push`, without asking
    rule: Bash(git push:*)
    why:  `git push` can send files or data off your machine, or change things outside this project.
          If a secret is in the working tree, this is how it leaves.

* may read files matching `~/.aws/**`, without asking
    rule: Read(~/.aws/**)
    why:  That is where keys, tokens and passwords are kept. What the agent reads can end up in a command,
          a commit or a web request.

MEDIUM    worth a look
----------------------
* may run any command that starts with `git commit`, without asking
    why:  `git commit` puts changes into git history without you reading them. Paired with a push rule,
          that is the path the leaked secrets took.
```

Run `make demo` to see the whole thing.

## What it checks

| File | Who writes it | What leash looks for |
|---|---|---|
| `~/.claude/settings.json` | you | allow rules, `defaultMode`, the `env` block, MCP servers |
| `<project>/.claude/settings.json` | you, shared with the team, usually committed | the same |
| `<project>/.claude/settings.local.json` | Claude Code, when you choose "don't ask again" | the same, plus: is it committed, was it ever, is it ignored |
| `<project>/.mcp.json` | you, usually committed | tokens in server `env`, `headers`, `url`, `command`, `args` |
| `~/.claude.json` | Claude Code | per-project allowed tools and MCP servers |
| managed settings | an administrator | the same as your own settings |
| `~/.codex/config.toml` | you or Codex | `approval_policy`, `sandbox_mode`, network access, MCP server env |
| `~/.gemini/settings.json`, `<project>/.gemini/settings.json` | you or Gemini CLI | `tools.allowed`, `general.defaultApprovalMode`, `security.autoAddToPolicyByDefault`, MCP servers and their `trust` switch |
| `~/.cursor/mcp.json`, `<project>/.cursor/mcp.json` | you, often committed | tokens in MCP server settings |
| `<project>/.vscode/mcp.json` | you, often committed | tokens in MCP server settings (VS Code keeps them under `servers`) |
| git history of all the project files above | git | secrets in any old version, including deleted files |

Gemini's `run_shell_command(git)` allows every command that starts with `git`, so leash grades it the way it grades Claude Code's `Bash(git:*)`.

The secret check knows the shapes of GitHub, GitLab, Anthropic, OpenAI, AWS, Google, Slack, Stripe, npm and Hugging Face keys, private key blocks and signed web tokens. It also knows how passwords are passed to commands: `NAME=value` in front of a command, `sshpass -p`, `mysql -p...`, `--password` and `--token` options, `password=` in connection strings, `user:password@` in URLs, `Authorization` and API-key headers, and `curl -u`. A value that is a variable (`$PGPASSWORD`) or a placeholder (`<your-token>`) is not counted.

The rule grades, from worst to best:

| Grade | Means |
|---|---|
| critical | a secret in a rule, `Bash` with no limit, or permissions switched off |
| high | can send data off the machine (`git push`, `curl`, `ssh`, `aws`...), delete (`rm`, `sudo`...), run any program (`python`, `bash`, `xargs`...), or read where keys live (`~/.ssh`, `.env`...) |
| medium | puts changes into git without review, runs installers and project scripts, talks to a database, changes any file, sends requests to any website, or allows a whole MCP server |
| low | reads, lists or tests |

## What it can and can't tell you

| leash says | It shows | It does not show |
|---|---|---|
| a secret is in a rule | something password-shaped is written there | that the password still works. Rotate it anyway |
| no secrets found | nothing matched the shapes leash knows | that the file is clean. A password with no tell-tale shape, in a command leash does not know, can slip past |
| the file is committed or in history | git has a copy | who has already fetched it. Assume everyone who could |
| a rule is high | the agent may run that kind of command without a prompt | that it ever did. leash reads permissions, not session logs |
| the repo is public | GitHub says so, via `gh` | anything when `gh` is missing: then leash says it could not tell |
| an old version holds a secret | a saved commit has it, on some branch | whether that commit was pushed. With a remote, leash assumes it may have been |

Two places leash does not read yet: the rules Gemini CLI saves when you choose "allow for all future sessions", and the allow list Cursor keeps inside the app itself.

leash reads settings, not sessions. For what an agent actually did, see [acta](https://github.com/patkusch/acta). For a yes-or-no gate at the moment of each call, see [airlock](https://github.com/PKusch/airlock). For what a skill can touch before you install it, see [skillgate](https://github.com/patkusch/skillgate).

## Tests

```bash
make test
```

91 tests, no network, no home-folder files. Each one builds its own throw-away project or git repo.

## Licence

MIT.
