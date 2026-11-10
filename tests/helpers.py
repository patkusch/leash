"""Build throw-away projects and git repos for the tests."""

import json
import subprocess
from pathlib import Path

GIT_ID = ["-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"]


def git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *GIT_ID, *args], cwd=repo, capture_output=True, text=True, check=True)


def make_repo(folder: Path, remote: str | None = None) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=folder, check=True, capture_output=True)
    if remote:
        git(folder, "remote", "add", "origin", remote)
    return folder


def write_json(path: Path, data: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def commit_all(repo: Path, message: str = "x") -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
