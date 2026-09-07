#!/usr/bin/env python3
"""Score the PRODUCTION reachability filter against a labeled endpoint sample.

Why this exists
---------------
The Hunt frontier is polluted by discovery noise, and two attempts to score it have already been
withdrawn. The first ranked endpoints by evidence and promoted a junk sample to the top. The second
compared a low-level matcher (``_soft404_matches``) against a new classifier and reported
improvements that production already achieved on its own -- an invalid comparison.

So this evaluates the real entry point, ``filter_reachable_worklist``, by handing it worklist
entries and scoring what it keeps and drops. Production already protects fragment routes and
non-GET entries; any replacement must be measured against that, not against a raw matcher.

What it measures
----------------
Both directions, plus abstention, because phantom reduction alone is not sufficient:
  * real routes dropped         -- the harm; a demoted real route is a missed vulnerability
  * absent routes dropped       -- the benefit
  * definite verdicts on ground-truth ``unknown`` -- also an error, not a neutral outcome

Route templates and request samples are scored separately. Much of the "phantom" population is not
made of separate endpoints: it is a handful of real templates carrying thousands of junk parameter
samples, which is a grouping problem rather than a classification problem.

Usage
-----
    python3 scripts/evaluate_endpoint_reality.py --base-url http://host.docker.internal:3001

Run inside the api container, which holds the dependencies and can reach the lab target.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from asm_inventory import filter_reachable_worklist  # noqa: E402

DEFAULT_SAMPLE = Path(__file__).resolve().parents[1] / "tests/fixtures/hunt/endpoint_reality_sample.json"


def worklist_entry(entry: dict) -> str:
    """The production filter consumes 'METHOD /path' worklist entries."""
    return f"{entry.get('method', 'GET').upper()} {entry['request_sample']}"


async def evaluate(base_url: str, entries: list[dict], **kwargs) -> list[dict]:
    worklist = [worklist_entry(e) for e in entries]
    kept = set(await filter_reachable_worklist(base_url, worklist, None, **kwargs))
    return [
        {**entry, "entry": item, "production": "kept" if item in kept else "dropped"}
        for entry, item in zip(entries, worklist)
    ]


def score(results: list[dict]) -> dict:
    """A drop is correct only for an absent route. Anything else dropped is harm."""
    harm: list[dict] = []
    benefit: list[dict] = []
    unknown_decided: list[dict] = []
    for row in results:
        dropped = row["production"] == "dropped"
        route = row["route_label"]
        if dropped and route in {"real", "client_route"}:
            harm.append(row)
        elif dropped and route == "absent":
            benefit.append(row)
        elif dropped and route == "unknown":
            # A definite verdict where the ground truth is unknown is itself an error.
            unknown_decided.append(row)
    totals = Counter(row["route_label"] for row in results)
    dropped = Counter(row["route_label"] for row in results if row["production"] == "dropped")
    # Grouping view: how much of the sample is junk samples of templates that are real anyway?
    templates = Counter(row["route_template"] for row in results)
    junk = [r for r in results if r["route_label"] == "real" and r["sample_label"] == "invalid"]
    return {
        "totals_by_route_label": dict(totals),
        "dropped_by_route_label": dict(dropped),
        "real_or_client_dropped": harm,
        "absent_dropped": benefit,
        "unknown_given_definite_verdict": unknown_decided,
        "distinct_route_templates": len(templates),
        "entries": len(results),
        "junk_samples_of_real_templates": len(junk),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--sample", default=str(DEFAULT_SAMPLE))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    sample = json.loads(Path(args.sample).read_text())
    entries = sample["entries"]
    results = asyncio.run(evaluate(args.base_url, entries))
    summary = score(results)

    if args.json:
        print(json.dumps({"results": results, "summary": summary}, indent=2))
        return 0

    print(f"target: {args.base_url}   entries: {len(entries)}\n")
    print(f"{'route_label':<14}{'sample':<18}{'prod':<9}{'method':<8}path")
    for row in sorted(results, key=lambda r: (r["route_label"], r["request_sample"])):
        print(f"{row['route_label']:<14}{row['sample_label']:<18}{row['production']:<9}"
              f"{row['method']:<8}{row['request_sample']}")

    print("\n--- production filter (filter_reachable_worklist) ---")
    print(f"absent routes dropped (benefit): {len(summary['absent_dropped'])}"
          f"/{summary['totals_by_route_label'].get('absent', 0)}")
    print(f"real/client dropped (HARM)     : {len(summary['real_or_client_dropped'])}")
    for row in summary["real_or_client_dropped"]:
        print(f"  HARM: {row['route_label']} dropped -> {row['entry']}")
    print(f"definite verdict on unknown    : {len(summary['unknown_given_definite_verdict'])}")

    print("\n--- grouping view ---")
    print(f"{summary['entries']} sampled requests span {summary['distinct_route_templates']} route templates")
    print(f"{summary['junk_samples_of_real_templates']} are junk samples of templates that are REAL anyway "
          "(a grouping problem, not a classification problem)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
