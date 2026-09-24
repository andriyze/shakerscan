#!/usr/bin/env python3
"""Catch obsolete execution contracts in shipped methodology and core guidance.

This check does not judge vulnerability coverage from prose. It catches concrete integration
errors: dead local links, a second action-schema/approval system, and declaration/body drift.
Capability validity remains owned by the Hunt library loader.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]
RETIRED = (
    "../schemas/", "../core/", "**Allowed adapters**", "**Default budget**",
    "The strictest applicable value wins", "the strictest applicable value still wins",
    "The action adapter is allowlisted by the selected skill",
    "Every adapter invocation must include a valid policy decision reference",
    "this skill cannot be bound to a hunt yet",
    "Bind this methodology only when its required",
)


def check(root: Path = ROOT) -> list[str]:
    failures: list[str] = []
    library = root / "skills" / "web"
    paths = sorted(library.glob("*.md")) + sorted((library / "core").glob("*.md"))
    if not paths:
        return ["Hunt methodology library is absent"]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        label = path.relative_to(root).as_posix()
        for retired in RETIRED:
            if retired in text:
                failures.append(f"{label}: retired execution instruction: {retired}")
        for href in re.findall(r"\[[^\]\n]+\]\(([^)\s]+)\)", text):
            parts = urlsplit(href)
            if parts.scheme or parts.netloc or not parts.path:
                continue
            target = path.parent / unquote(parts.path)
            if not target.exists():
                failures.append(f"{label}: missing local reference: {href}")
        if "## ShakerScan execution contract" not in text:
            continue
        try:
            meta = yaml.safe_load(text.split("---", 2)[1])
            if not isinstance(meta, dict):
                raise ValueError("metadata is not an object")
        except (IndexError, ValueError, yaml.YAMLError) as exc:
            failures.append(f"{label}: malformed declaration ({type(exc).__name__})")
            continue
        section = text.split("## ShakerScan execution contract", 1)[1].split("\n## ", 1)[0]
        declared = set(meta.get("capabilities") or ()) | set(meta.get("optional_capabilities") or ())
        documented = set(re.findall(r"`([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)`", section))
        # Missing implementation identifiers may be listed, but never treated as executors.
        expected = declared | set(meta.get("missing_capabilities") or ())
        if documented != expected:
            failures.append(f"{label}: execution names differ from declaration: "
                            f"missing={sorted(expected - documented)}, extra={sorted(documented - expected)}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    failures = check(args.root)
    if failures:
        print("\n".join(failures))
        return 1
    print("Hunt methodology integration: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
