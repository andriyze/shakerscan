#!/usr/bin/env python3
"""Reject release-only commit labels that conceal functional changes."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import PurePosixPath


FUNCTIONAL_ROOTS = {
    "api", "scanner", "ui", "db", "install", "scripts", "tests",
    "docker-compose.yml", "docker-compose.release.yml", "docker-compose.worker.yml",
    "docker-compose.broker-worker.yml", "scanner.sh",
}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def is_functional(path: str) -> bool:
    first = PurePosixPath(path).parts[0] if PurePosixPath(path).parts else path
    return first in FUNCTIONAL_ROOTS


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    failures: list[str] = []
    commits = git("rev-list", "--reverse", f"{args.base}..{args.head}").splitlines()
    for commit in commits:
        subject = git("show", "-s", "--format=%s", commit)
        if not subject.lower().startswith("release:"):
            continue
        changed = git("diff-tree", "--no-commit-id", "--name-only", "-r", commit).splitlines()
        hidden = [path for path in changed if is_functional(path)]
        if hidden:
            failures.append(
                f"{commit[:12]} {subject!r} hides functional files under release:: "
                + ", ".join(hidden[:8])
            )
    if failures:
        print("\n".join(failures))
        print("Use fix(...):, feat(...):, refactor(...):, test(...):, or split the release metadata commit.")
        return 1
    print(f"Commit policy passed for {len(commits)} commit(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
