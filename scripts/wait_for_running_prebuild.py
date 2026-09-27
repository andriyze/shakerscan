#!/usr/bin/env python3
"""Wait for one already-running exact-SHA image build without starting another."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from collections.abc import Callable


class PrebuildWaitError(RuntimeError):
    pass


def wait_for_completion(
    run_id: str,
    get_state: Callable[[str], tuple[str, str]],
    pause: Callable[[float], None],
    *,
    max_polls: int = 120,
    interval_seconds: float = 30,
) -> None:
    if max_polls < 1:
        raise ValueError("max_polls must be positive")
    for attempt in range(max_polls):
        status, conclusion = get_state(run_id)
        if status == "completed":
            if conclusion == "success":
                return
            raise PrebuildWaitError(f"build-on-main run {run_id} completed as {conclusion or 'unknown'}")
        if attempt + 1 < max_polls:
            pause(interval_seconds)
    raise PrebuildWaitError(f"build-on-main run {run_id} is still {status} after the bounded wait")


def _github_state(run_id: str) -> tuple[str, str]:
    result = subprocess.run(
        ["gh", "run", "view", run_id, "--json", "status,conclusion"],
        check=True, capture_output=True, text=True,
    )
    state = json.loads(result.stdout)
    return str(state.get("status") or ""), str(state.get("conclusion") or "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]+", args.run_id):
        parser.error("run_id must be numeric")
    print(f"Waiting for exact-SHA build-on-main run {args.run_id} instead of building twice", flush=True)
    try:
        wait_for_completion(args.run_id, _github_state, time.sleep)
    except (PrebuildWaitError, subprocess.CalledProcessError, ValueError) as exc:
        parser.exit(1, f"Exact-SHA image build unavailable: {exc}. Retry or rerun build-on-main before certifying.\n")
    print(f"build-on-main run {args.run_id} succeeded", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
