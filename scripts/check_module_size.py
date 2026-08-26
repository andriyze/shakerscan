#!/usr/bin/env python3
"""Ratchet the size of the oversized monolith modules downward.

This is a ratchet, not a style check: the limits are the frozen baseline at the
time api.py/worker.py decomposition began, and every extraction commit must
lower the relevant limit here so the module can only shrink. A change that grows
one of these files past its baseline fails CI, which stops new routes and new
features from being added to the monolith while decomposition is underway.

Run: python3 scripts/check_module_size.py
"""

from __future__ import annotations

from pathlib import Path


# Frozen decomposition baselines (line counts). Lower these — never raise them —
# as each bounded domain is extracted into api/<domain>/router.py + services.
LIMITS: dict[str, int] = {
    "api/api.py": 36310,
    "api/worker.py": 23_513,
}

_ROOT = Path(__file__).resolve().parents[1]


def check_module_sizes(limits: dict[str, int] = LIMITS) -> list[str]:
    failures: list[str] = []
    for filename, maximum_lines in limits.items():
        path = _ROOT / filename
        count = len(path.read_text(encoding="utf-8").splitlines())
        if count > maximum_lines:
            failures.append(
                f"{filename}: {count:,} lines exceeds frozen baseline "
                f"{maximum_lines:,} (+{count - maximum_lines}). Monolith growth "
                f"is frozen; extract a bounded domain and lower this baseline "
                f"instead of adding to the module."
            )
    return failures


def main() -> None:
    failures = check_module_sizes()
    if failures:
        raise SystemExit("\n".join(failures))
    print("module size ratchet: OK")


if __name__ == "__main__":
    main()
