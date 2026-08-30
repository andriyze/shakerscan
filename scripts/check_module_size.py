#!/usr/bin/env python3
"""Ratchet the *logic* in the oversized monolith modules downward.

This is a ratchet, not a style check: the limits are frozen baselines, and an extraction
commit lowers the relevant limit so the module can only shrink. What it stops is new
features being written into the monolith while decomposition is underway.

It deliberately does not count import statements or router composition. Wiring an extracted
domain back into the composition root costs a few of exactly those lines, so counting them
made the ratchet fire on the behaviour it exists to encourage: moving 200 lines of logic
into ``api/<domain>/`` still failed because the import and ``include_router`` call grew the
root by four. That produced unrelated refactors squeezed into feature commits purely to buy
back lines, which is worse for review than the growth it prevented.

Logic still counts in full. A module cannot smuggle work past this by hiding it in an
import, because an import is one line and the thing it imports has to live somewhere the
ratchet does not cover -- which is the point.

Run: python3 scripts/check_module_size.py
"""

from __future__ import annotations

from pathlib import Path
import re


# Frozen decomposition baselines, counted over logic lines only (see COMPOSITION_PATTERNS).
# Lower these -- never raise them -- as each bounded domain is extracted into
# api/<domain>/router.py plus services.
LIMITS: dict[str, int] = {
    "api/api.py": 20_897,
    "api/worker.py": 23_334,
    "scanner/risk_scoring.py": 140,
    "scanner/score_bands.py": 27,
}

# Lines that connect a module rather than implement anything in it. Extracting a domain
# adds these to the composition root by design.
COMPOSITION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*(?:from|import)\s"),
    re.compile(r"^\s*app\.include_router\("),
    re.compile(r"^\s*configure_[a-z0-9_]+\("),
)

_ROOT = Path(__file__).resolve().parents[1]


def is_composition_line(line: str) -> bool:
    return any(pattern.match(line) for pattern in COMPOSITION_PATTERNS)


def logic_line_count(text: str) -> int:
    return sum(1 for line in text.splitlines() if not is_composition_line(line))


def check_module_sizes(limits: dict[str, int] = LIMITS) -> list[str]:
    failures: list[str] = []
    for filename, maximum_lines in limits.items():
        path = _ROOT / filename
        count = logic_line_count(path.read_text(encoding="utf-8"))
        if count > maximum_lines:
            failures.append(
                f"{filename}: {count:,} logic lines exceeds frozen baseline "
                f"{maximum_lines:,} (+{count - maximum_lines}). Monolith growth is "
                f"frozen; extract a bounded domain into api/<domain>/ and lower this "
                f"baseline. Imports and router composition are already excluded, so "
                f"this is {count - maximum_lines} lines of logic that belong elsewhere."
            )
    return failures


def main() -> None:
    failures = check_module_sizes()
    if failures:
        raise SystemExit("\n".join(failures))
    print("module size ratchet: OK")


if __name__ == "__main__":
    main()
