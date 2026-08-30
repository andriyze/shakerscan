#!/usr/bin/env python3
"""Enforce the small set of documentation invariants that prevent trust drift.

This check deliberately avoids deciding whether prose is "fresh" from a date alone. It enforces
structure reviewers can rely on: the always-loaded agent guide stays compact, maintained documents
declare their lifecycle, archived material warns that it is historical, and collection indexes do
not silently omit records.

Run: python3 scripts/check_documentation_policy.py
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AGENT_GUIDE_MAX_LINES = 500
AGENT_GUIDE_MAX_BYTES = 32_000
HEADER_LINES = 20

STALE_CURRENT_PHRASES = (
    "## Four primary workflows",
    "**Status:** live user guide",
    "**Implementation state:** Planning only",
)
ARCHIVE_MARKERS = (
    "historical",
    "archived",
    "retired",
    "point-in-time",
)


def _header(path: Path) -> str:
    return "\n".join(path.read_text(encoding="utf-8").splitlines()[:HEADER_LINES])


def _check_index(index: Path, records: list[Path], root: Path) -> list[str]:
    text = index.read_text(encoding="utf-8")
    failures: list[str] = []
    for record in records:
        relative = record.relative_to(index.parent).as_posix()
        count = text.count(f"({relative})")
        if count != 1:
            failures.append(
                f"{index.relative_to(root)} must link {relative} exactly once; found {count}"
            )
    return failures


def check_documentation_policy(root: Path = ROOT) -> list[str]:
    failures: list[str] = []

    agent_guide = root / "AGENTS.md"
    agent_text = agent_guide.read_text(encoding="utf-8")
    agent_lines = len(agent_text.splitlines())
    agent_bytes = len(agent_text.encode("utf-8"))
    if agent_lines > AGENT_GUIDE_MAX_LINES:
        failures.append(
            f"AGENTS.md has {agent_lines} lines; always-loaded guide limit is "
            f"{AGENT_GUIDE_MAX_LINES}"
        )
    if agent_bytes > AGENT_GUIDE_MAX_BYTES:
        failures.append(
            f"AGENTS.md has {agent_bytes} bytes; always-loaded guide limit is "
            f"{AGENT_GUIDE_MAX_BYTES}"
        )

    docs_root = root / "docs"
    for path in sorted(docs_root.glob("*.md")):
        header = _header(path)
        if "**Status" not in header and "**Reconciled" not in header:
            failures.append(
                f"{path.relative_to(root)} must declare **Status** or **Reconciled** "
                f"within its first {HEADER_LINES} lines"
            )
        text = path.read_text(encoding="utf-8")
        for phrase in STALE_CURRENT_PHRASES:
            if phrase in text:
                failures.append(
                    f"{path.relative_to(root)} contains retired current-doc phrase: {phrase}"
                )

    archive_root = docs_root / "archive"
    for path in sorted(archive_root.glob("*.md")):
        if path.name == "README.md":
            continue
        header = _header(path).lower()
        if not any(marker in header for marker in ARCHIVE_MARKERS):
            failures.append(
                f"{path.relative_to(root)} needs a historical/archive warning within its "
                f"first {HEADER_LINES} lines"
            )

    release_records = sorted((docs_root / "releases").glob("*.md"))
    release_records = [path for path in release_records if path.name != "README.md"]
    failures.extend(
        _check_index(docs_root / "releases" / "README.md", release_records, root)
    )

    decision_records = sorted((docs_root / "decisions").glob("*.md"))
    decision_records = [path for path in decision_records if path.name != "README.md"]
    failures.extend(
        _check_index(docs_root / "decisions" / "README.md", decision_records, root)
    )

    return failures


def main() -> None:
    failures = check_documentation_policy()
    if failures:
        raise SystemExit("\n".join(failures))
    print("documentation policy: OK")


if __name__ == "__main__":
    main()
