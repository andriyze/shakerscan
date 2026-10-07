#!/usr/bin/env python3
"""Combine the E2E scorecards of parallel smoke shards into one scorecard.

The pull-request smoke check runs its E2E areas on several runners, each against its own stack
built from the same source. The completeness gate (scripts/summarize_e2e_debt.py) is unchanged and
must judge the union of every shard's areas, so this merge never hides a failure or a gap:

* each input must be a complete run_e2e.py scorecard;
* an area may appear in only one shard (a duplicate would let one passing copy mask another);
* every shard must have exercised the same deployment (source revision, build fingerprint and
  version), or the union would describe no single build;
* the merged gate passes only when every shard's gate passed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Sequence

SCORECARD_SCHEMA = "shakerscan-e2e-scorecard/v1"
SUBJECT_KEYS = ("source_revision", "build_fingerprint", "scanner_version")


class MergeError(ValueError):
    """The shard scorecards cannot be combined into one honest scorecard."""


def merge(cards: Sequence[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    if not cards:
        raise MergeError("no shard scorecards to merge")
    areas: list[dict[str, Any]] = []
    owners: dict[str, str] = {}
    subject: dict[str, Any] | None = None
    subject_source = ""
    passed = True
    duration = 0.0
    for source, card in cards:
        if not isinstance(card, dict) or card.get("schema_version") != SCORECARD_SCHEMA:
            raise MergeError(f"{source} is not a {SCORECARD_SCHEMA} scorecard")
        if not isinstance(card.get("areas"), list) or not card["areas"]:
            raise MergeError(f"{source} records no areas")
        for area in card["areas"]:
            name = area.get("area") if isinstance(area, dict) else None
            if not isinstance(name, str) or not name:
                raise MergeError(f"{source} has an unnamed area")
            if name in owners:
                raise MergeError(f"area {name} appears in both {owners[name]} and {source}")
            owners[name] = source
            areas.append(area)
        card_subject = card.get("subject") if isinstance(card.get("subject"), dict) else {}
        identity = {key: card_subject.get(key) for key in SUBJECT_KEYS}
        if subject is None:
            subject, subject_source = dict(card_subject), source
        elif identity != {key: subject.get(key) for key in SUBJECT_KEYS}:
            raise MergeError(
                f"{source} tested a different deployment than {subject_source}: "
                f"{identity} != { {key: subject.get(key) for key in SUBJECT_KEYS} }"
            )
        passed = passed and str(card.get("gate") or "").lower() == "pass"
        try:
            duration += float(card.get("total_duration_seconds") or 0)
        except (TypeError, ValueError):
            raise MergeError(f"{source} has a non-numeric duration") from None
    return {
        "schema_version": SCORECARD_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gate": "pass" if passed else "fail",
        "subject": subject or {},
        "areas": areas,
        "total_duration_seconds": round(duration, 3),
        "merged_from": [source for source, _ in cards],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scorecards", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        cards = [(str(path), json.loads(path.read_text(encoding="utf-8")))
                 for path in args.scorecards]
        merged = merge(cards)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Cannot merge E2E scorecards: {exc}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(merged, sort_keys=True, separators=(",", ":")) + "\n",
                           encoding="utf-8")
    names = ", ".join(area["area"] for area in merged["areas"])
    print(f"merged {len(cards)} scorecards: areas {names}; gate {merged['gate']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
