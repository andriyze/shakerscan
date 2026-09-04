#!/usr/bin/env python3
"""Record a published version's source commit and image digests in the RELEASES.md ledger.

The ledger row is what the upgrade smoke reads to find its previous-stable baseline images and
what the runtime-hardening test asserts for ``install/STABLE_VERSION``. It used to be filled by a
separate hand-written pull request; for 2.0.1 that landed after the stable channel had already
moved, which left main with a stable version whose ledger row still said "pending". The stable
promotion workflow now records the row from ``release-image-lock.env`` on the GitHub Release in
the same ``release:`` commit that moves the channel.

Fail-closed rules:

* every ledger column must be present in the lock as ``repository@sha256:<digest>``;
* a row that already records different published digests for the version is never rewritten;
* a pending row is replaced, a missing row is inserted newest-first, an identical row is left as is.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_ledger import COLUMNS  # noqa: E402

LOCK_KEYS = {"scanner": "SCANNER_IMAGE", "api": "API_IMAGE", "ui": "UI_IMAGE", "signer": "SIGNER_IMAGE", "model_intake": "MODEL_INTAKE_IMAGE"}
_IMAGE_REF = re.compile(r"^([a-z0-9][a-z0-9._/-]*)@(sha256:[0-9a-f]{64})$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class LedgerError(ValueError):
    pass


def parse_lock(text: str) -> dict[str, tuple[str, str]]:
    """Return {column: (repository, digest)} for every ledger image column in the lock."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    images: dict[str, tuple[str, str]] = {}
    for column, key in LOCK_KEYS.items():
        ref = values.get(key)
        if not ref:
            raise LedgerError(f"release-image-lock.env has no {key}")
        match = _IMAGE_REF.match(ref)
        if not match:
            raise LedgerError(f"{key} is not a repository@sha256 reference: {ref!r}")
        images[column] = (match.group(1), match.group(2))
    return images


def render_row(version: str, commit: str, images: dict[str, tuple[str, str]]) -> str:
    if not _VERSION.match(version):
        raise LedgerError(f"not a release version: {version!r}")
    if not _COMMIT.match(commit):
        raise LedgerError(f"not a 40-character commit: {commit!r}")
    cells = [version, f"`{commit}`"]
    for column in sorted(COLUMNS, key=COLUMNS.__getitem__):
        repository, digest = images[column]
        cells.append(f"`{repository}:{version}` (`{digest}`)")
    return "| " + " | ".join(cells) + " |"


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def record_row(ledger: str, version: str, commit: str, images: dict[str, tuple[str, str]]) -> tuple[str, str]:
    """Return (new ledger text, outcome) where outcome is recorded | replaced | unchanged."""
    row = render_row(version, commit, images)
    lines = ledger.splitlines(keepends=True)
    header_index = None
    for index, line in enumerate(lines):
        if line.startswith("| Version |"):
            header_index = index
            break
    if header_index is None or header_index + 1 >= len(lines) or not lines[header_index + 1].startswith("| ---"):
        raise LedgerError("RELEASES.md has no ledger table header")
    for index in range(header_index + 2, len(lines)):
        line = lines[index]
        if not line.startswith("|"):
            break
        cells = _cells(line)
        if cells[0] != version:
            continue
        if cells == _cells(row):
            return ledger, "unchanged"
        if any("sha256:" in cell for cell in cells[1:]):
            raise LedgerError(
                f"RELEASES.md already records different published digests for {version}; refusing to rewrite it"
            )
        lines[index] = row + "\n"
        return "".join(lines), "replaced"
    lines.insert(header_index + 2, row + "\n")
    return "".join(lines), "recorded"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True, help="40-character source commit of the published release")
    parser.add_argument("--lock", required=True, help="release-image-lock.env from the GitHub Release")
    parser.add_argument("--ledger", default="RELEASES.md")
    args = parser.parse_args(argv)
    ledger_path = Path(args.ledger)
    try:
        images = parse_lock(Path(args.lock).read_text(encoding="utf-8"))
        text, outcome = record_row(ledger_path.read_text(encoding="utf-8"), args.version, args.commit, images)
    except (LedgerError, OSError) as error:
        print(f"record_release_ledger: {error}", file=sys.stderr)
        return 2
    if outcome != "unchanged":
        ledger_path.write_text(text, encoding="utf-8")
    print(f"{outcome} {args.version} in {ledger_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
