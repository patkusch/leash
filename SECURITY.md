# Security

If you find a security problem in leash, please report it privately rather than in a public issue.

Use the **Report a vulnerability** button on the [Security tab](https://github.com/patkusch/leash/security/advisories/new). Only the maintainer can see what you send.

Include what you found, how to reproduce it, and what you think the impact is. I aim to reply within a week.

This is a personal project, so there is no bounty and no guaranteed fix time, but a real problem will be taken seriously and credited if you want.

## What leash does with secrets

leash never prints a secret it finds. It shows the first few characters and the length, nothing more. It never writes a secret anywhere, and it never goes online except to ask GitHub whether a repo is public (and only when the `gh` tool is installed; `--no-gh` turns that off).
