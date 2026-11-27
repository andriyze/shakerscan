#!/usr/bin/env python3
"""Reconstruct a deterministic Scan report from a private offline bundle."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import uuid


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "api"))
sys.path.insert(0, str(REPOSITORY_ROOT / "scanner"))

from scan.report_rebuild import (  # noqa: E402
    ScanReportRebuildError,
    canonical_report_json,
    rebuild_scan_report,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Rebuild a Scan report without network, API, database, Redis, or target access. "
            "The input bundle is private evidence and must be protected accordingly."
        ),
    )
    parser.add_argument("bundle", type=Path, help="private scan-report-rebuild-bundle/v1 JSON")
    parser.add_argument("--output", "-o", type=Path, help="write report JSON instead of stdout")
    parser.add_argument(
        "--force", action="store_true",
        help="replace an existing output file (never enabled implicitly)",
    )
    return parser


def _write_atomic(path: Path, value: str, *, force: bool) -> None:
    output = path.expanduser()
    if output.exists() and not force:
        raise OSError("report output already exists; use --force to replace it")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(value, encoding="utf-8")
        if force:
            temporary.replace(output)
        else:
            os.link(temporary, output)
            temporary.unlink()
    except FileExistsError as exc:
        raise OSError(
            "report output already exists; use --force to replace it"
        ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        payload = json.loads(args.bundle.read_text(encoding="utf-8"))
        report = rebuild_scan_report(payload)
        rendered = canonical_report_json(report)
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            _write_atomic(args.output, rendered, force=args.force)
    except (OSError, json.JSONDecodeError, ScanReportRebuildError, TypeError, ValueError) as exc:
        print(f"report rebuild failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
