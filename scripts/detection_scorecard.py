#!/usr/bin/env python3
"""One detection scorecard from benchmark runs, and a comparison of two.

``scripts/benchmark_targets.py`` scores one run and writes it under ``results/benchmark-runs/``.
This reads those run files and prints the table a release publishes: per target, how many
expected entries were proven, how many were detected without proof, the verified and suspected
high and critical findings, and the families a Scan attempted.

With ``--baseline`` it compares the same targets in an earlier run and exits 1 when proven recall
fell on any of them, an entry the baseline proved is no longer proven (even when another took its
place), or a target the baseline scored is missing: a detection or budget change is
judged by this number, before and after, on the same targets and profile.

Usage:
  python3 scripts/detection_scorecard.py results/benchmark-runs/benchmark-juice_shop.json [...]
      [--baseline RUN.json [...]] [--json]

It reads files only: it starts no Scan and contacts nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping


def _cards(paths: Iterable[str]) -> dict[str, dict[str, Any]]:
    """The latest card per target name across the run files, in the order given."""
    cards: dict[str, dict[str, Any]] = {}
    for path in paths:
        run = json.loads(Path(path).read_text(encoding="utf-8"))
        targets = run.get("targets") if isinstance(run, Mapping) else None
        if not isinstance(targets, list):
            raise ValueError(f"{path} is not a benchmark run (no targets list)")
        for card in targets:
            if isinstance(card, Mapping) and str(card.get("target") or ""):
                cards[str(card["target"])] = dict(card)
    return cards


def summarize(card: Mapping[str, Any]) -> dict[str, Any]:
    """The published numbers of one target's card. A card that errored proves nothing."""
    found = card.get("expected_found") or []
    missed = card.get("expected_missed") or []
    unproven = card.get("expected_detected_unproven") or []
    expected = len(found) + len(missed)
    return {
        "target": str(card.get("target") or ""),
        "error": str(card["error"])[:200] if card.get("error") else None,
        "expected": expected,
        "proven": len(found),
        "detected_unproven": len(unproven),
        # Proven entries only, as the runner counts it; unknown when nothing was expected.
        "recall": round(len(found) / expected, 2) if expected else None,
        "verified_high_critical": int(card.get("verified_high_critical") or 0),
        "suspected_high_critical": int(card.get("suspected_high_critical") or 0),
        "attempted_families": sorted(str(item) for item in card.get("attempted_families") or ()),
        "missed": sorted(str(item.get("id") or "") for item in missed if isinstance(item, Mapping)),
    }


def compare(
    current: Mapping[str, Mapping[str, Any]], baseline: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    """Why ``current`` is worse than ``baseline``; empty when it is not."""
    regressions: list[str] = []
    for name, before in baseline.items():
        after = current.get(name)
        if after is None:
            regressions.append(f"{name}: scored in the baseline, missing from this run")
            continue
        if after["error"] and not before["error"]:
            regressions.append(f"{name}: the run failed ({after['error']})")
            continue
        lost = sorted(set(after["missed"]) - set(before["missed"]))
        if after["proven"] < before["proven"]:
            regressions.append(
                f"{name}: proven fell from {before['proven']} to {after['proven']} of "
                f"{after['expected']}" + (f" (now missed: {', '.join(lost)})" if lost else "")
            )
        elif lost:
            # The same count can hide a swap: an entry the baseline proved is missed now.
            regressions.append(f"{name}: no longer proven: {', '.join(lost)}")
    return regressions


def _cell(value: Any) -> str:
    return "n/a" if value is None else str(value)


def render(
    current: Mapping[str, Mapping[str, Any]],
    baseline: Mapping[str, Mapping[str, Any]] | None = None,
) -> str:
    header = ["Target", "Proven / expected", "Recall", "Detected, not proven",
              "Verified high+critical", "Suspected high+critical", "Families attempted"]
    if baseline is not None:
        header.insert(2, "Proven before")
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for name in sorted(current):
        row = current[name]
        cells = [
            name + (" (failed)" if row["error"] else ""),
            f"{row['proven']} / {row['expected']}", _cell(row["recall"]),
            str(row["detected_unproven"]), str(row["verified_high_critical"]),
            str(row["suspected_high_critical"]), ", ".join(row["attempted_families"]) or "n/a",
        ]
        if baseline is not None:
            before = baseline.get(name)
            cells.insert(2, "n/a" if before is None else str(before["proven"]))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("runs", nargs="+", help="benchmark run files to score")
    parser.add_argument("--baseline", nargs="+", default=None,
                        help="earlier run files of the same targets to compare with")
    parser.add_argument("--json", action="store_true", help="print the numbers as JSON")
    args = parser.parse_args(argv)
    try:
        current = {name: summarize(card) for name, card in _cards(args.runs).items()}
        baseline = (
            {name: summarize(card) for name, card in _cards(args.baseline).items()}
            if args.baseline else None
        )
    except (OSError, ValueError) as exc:
        print(f"detection scorecard: {exc}", file=sys.stderr)
        return 2
    regressions = compare(current, baseline) if baseline is not None else []
    if args.json:
        print(json.dumps({"targets": current, "baseline": baseline, "regressions": regressions},
                         indent=2, sort_keys=True))
    else:
        print(render(current, baseline))
        for line in regressions:
            print(f"REGRESSION {line}")
    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(main())
