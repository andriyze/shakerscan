#!/usr/bin/env python3
"""Read published image digests for a version from the RELEASES.md ledger.

The upgrade smoke used to hardcode the previous-stable image digests and only checked that the
baseline *tag name* matched `install/STABLE_VERSION`; advancing the channel silently left the smoke
qualifying an upgrade from the wrong images. The ledger already records every published digest, so
it is the single source the smoke reads.

    python3 scripts/release_ledger.py --version 0.8.18 --image scanner
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "RELEASES.md"
COLUMNS = {"scanner": 2, "api": 3, "ui": 4, "signer": 5, "model_intake": 6}
_REF = re.compile(r"`([^`@]+)`\s*\(`(sha256:[0-9a-f]{64})`\)")


class LedgerError(RuntimeError):
    pass


def ledger_row(version: str, text: str) -> list[str]:
    for line in text.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 6 and cells[0] == version:
            return cells
    raise LedgerError(f"RELEASES.md has no row for version {version}")


def published_image(version: str, image: str, text: str | None = None) -> str:
    """Return `repository@sha256:digest` for one published image of a version."""
    if image not in COLUMNS:
        raise LedgerError(f"unknown image {image!r}; expected one of {sorted(COLUMNS)}")
    cells = ledger_row(version, text if text is not None else LEDGER.read_text(encoding="utf-8"))
    column = COLUMNS[image]
    if column >= len(cells):
        raise LedgerError(f"RELEASES.md records no {image} image for {version}; it predates that image")
    match = _REF.search(cells[column])
    if match is None:
        raise LedgerError(f"RELEASES.md records no published digest for {image} {version}")
    repository = match.group(1).rsplit(":", 1)[0]
    return f"{repository}@{match.group(2)}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--image", required=True, choices=sorted(COLUMNS))
    args = parser.parse_args(argv)
    try:
        print(published_image(args.version, args.image))
    except (OSError, LedgerError) as exc:
        print(f"release ledger: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
