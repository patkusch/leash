"""How each MCP server is started or reached, checked against common supply-chain and transport advice.

Sources: the OWASP MCP Security Cheat Sheet (TLS for remote servers, containers, no auto-approve),
and write-ups of unpinned `npx -y` servers (the postmark-mcp case) recommending pinned versions.
leash never starts a server; it only reads how the file says to start one.
"""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse

from .secrets import redact
from .silent import _PIPE_TO_SHELL

_RUNNERS = {"npx": "npm", "bunx": "npm", "uvx": "PyPI", "pipx": "PyPI"}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}


def _tokens(cfg: dict) -> list[str]:
    cmd = cfg.get("command")
    args = [a for a in cfg.get("args") or [] if isinstance(a, str)]
    if not isinstance(cmd, str):
        return args
    try:
        head = shlex.split(cmd)
    except ValueError:
        head = cmd.split()
    return head + args


def _npm_pinned(spec: str) -> bool:
    name, sep, version = spec[1:].rpartition("@") if spec.startswith("@") else spec.rpartition("@")
    if not sep:
        return False
    return bool(version) and version != "latest" and bool(re.match(r"\d", version))


def _pypi_pinned(spec: str) -> bool:
    if "==" in spec:
        return True
    _, sep, version = spec.rpartition("@")
    return bool(sep) and bool(re.match(r"\d", version or ""))


def package_spec(tokens: list[str]) -> tuple[str, str] | None:
    """(registry, package) for a server started by a package runner, or None."""
    if not tokens:
        return None
    prog = tokens[0].rsplit("/", 1)[-1]
    rest = tokens[1:]
    if prog in ("pnpm", "yarn") and rest[:1] == ["dlx"]:
        prog, rest = "npx", rest[1:]
    if prog == "pipx" and rest[:1] == ["run"]:
        rest = rest[1:]
    if prog not in _RUNNERS:
        return None
    skip_next = False
    for t in rest:
        if skip_next:
            skip_next = False
            continue
        if t in ("-p", "--package", "--from", "--with", "--python"):
            skip_next = True
            continue
        if t.startswith("-"):
            continue
        return _RUNNERS[prog], t
    return None


_DOCKER_VALUE_FLAGS = {"-v", "--volume", "--mount", "-e", "--env", "--env-file", "--network", "--net", "--name", "-p",
                       "--publish", "-w", "--workdir", "--entrypoint", "-u", "--user", "--label", "-l", "--platform",
                       "--cap-add", "--cap-drop", "--add-host", "--memory", "-m", "--cpus", "--pull", "--restart"}


def docker_image(tokens: list[str]) -> str | None:
    """The image a `docker run ...` starts: the first word after `run` that is not an option or its value."""
    if "run" not in tokens:
        return None
    rest = tokens[tokens.index("run") + 1:]
    i = 0
    while i < len(rest):
        t = rest[i]
        if t in _DOCKER_VALUE_FLAGS:
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        return t
    return None


def _docker_findings(tokens: list[str]) -> list[tuple[str, str, str, str]]:
    out = []
    if not tokens or tokens[0].rsplit("/", 1)[-1] not in ("docker", "podman") or "run" not in tokens[1:3]:
        return out
    joined = " ".join(tokens)
    if "--privileged" in tokens:
        out.append(("high", "runs its container with `--privileged`",
                    "A privileged container can reach the machine it runs on, so the container is not a wall.",
                    "Remove `--privileged`."))
    for i, t in enumerate(tokens):
        mount = None
        if t in ("-v", "--volume", "--mount") and i + 1 < len(tokens):
            mount = tokens[i + 1]
        elif t.startswith(("--volume=", "--mount=")):
            mount = t.split("=", 1)[1]
        if not mount:
            continue
        src = mount.split(":")[0] if "source=" not in mount else re.sub(r".*source=([^,]+).*", r"\1", mount)
        if src in ("/", "~", "$HOME", "${HOME}") or src.endswith("docker.sock"):
            out.append(("high", f"gives its container `{src}`",
                        "That is the whole disk, your home folder or control of Docker itself.",
                        "Mount only the folder the server needs, read-only where you can (`:ro`)."))
    if re.search(r"--net(?:work)?[= ]host\b", joined):
        out.append(("medium", "shares the host's network (`--network host`)",
                    "The container can reach every service on your machine and network.",
                    "Drop `--network host` unless the server needs it."))
    image = docker_image(tokens)
    last = image.split("/")[-1] if image else ""
    if image and ("@sha256:" not in image) and (":" not in last or last.endswith(":latest")):
        out.append(("medium", f"runs image `{image}` with no fixed version",
                    "Each start can pull a different image than the one you checked.",
                    "Pin a version tag, or better, a digest (`image@sha256:...`)."))
    return out


def server_findings(name: str, cfg: dict) -> list[tuple[str, str, str, str, str]]:
    """[(level, title, detail, fix, rule)] for one MCP server's settings."""
    out = []
    tokens = _tokens(cfg)
    shown = redact(" ".join(tokens))[:100]
    spec = package_spec(tokens)
    if spec:
        registry, pkg = spec
        pinned = _npm_pinned(pkg) if registry == "npm" else _pypi_pinned(pkg)
        if not pinned:
            out.append(("medium", f"the `{name}` MCP server runs the newest `{pkg}` from {registry} every time it starts",
                        "Whoever publishes the next version runs it on your machine, with the server's access. "
                        "One such case (postmark-mcp) quietly copied every email it sent.",
                        f"Pin a version you have checked, such as `{pkg.split('@latest')[0]}@1.2.3`" +
                        ("" if registry == "npm" else " (or `==1.2.3`)") + ".", shown))
    for level, title, detail, fix in _docker_findings(tokens):
        out.append((level, f"the `{name}` MCP server {title}", detail, fix, shown))
    joined = " ".join(tokens)
    if _PIPE_TO_SHELL.search(joined):
        out.append(("high", f"the `{name}` MCP server downloads a script and runs it to start",
                    "Whoever controls that address controls your machine.", "Install the server once, from a version you checked.",
                    shown))
    for key in ("url", "httpUrl", "serverUrl"):
        url = cfg.get(key)
        if not isinstance(url, str):
            continue
        u = urlparse(url)
        host = (u.hostname or "").lower()
        if u.scheme == "http" and host not in _LOCAL_HOSTS and not host.endswith(".localhost"):
            out.append(("high", f"the `{name}` MCP server is reached over plain http",
                        "Requests, answers and any token in the headers cross the network unencrypted.",
                        "Use `https://`.", redact(url)))
        if cfg.get("type") == "sse" or cfg.get("transport") == "sse" or u.path.rstrip("/").endswith("/sse"):
            out.append(("low", f"the `{name}` MCP server uses the older SSE transport",
                        "The MCP spec replaced it with streamable HTTP.", "Switch to the server's streamable HTTP address if it has one.",
                        redact(url)))
    return out
