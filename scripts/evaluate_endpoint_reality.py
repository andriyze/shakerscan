#!/usr/bin/env python3
"""Evaluate the EXISTING ASM decoy / soft-404 comparison against a labeled endpoint sample.

Why this exists
---------------
A Hunt ranks its endpoint frontier by `priority_score`, which demonstrably misranks discovery
phantoms above real routes. An evidence-based ranking was tried and made the frontier worse, so
before any storage or ranking change we measure whether the reality signal we already compute --
the per-prefix decoy ("soft-404") comparison in `api/asm_inventory.py` -- can actually separate
real endpoints from phantoms on an independently labeled sample.

This script does NOT reimplement the comparison. It imports and runs the real
`_learn_not_found_signatures`, `_probe_path_status`, `_soft404_matches` and `_path_prefix`, so a
result here is a statement about the shipping implementation.

What it measures
----------------
Both directions, because phantom reduction alone is not sufficient:
  * phantoms correctly identified  (the benefit)
  * REAL endpoints wrongly matched (the harm -- a demoted real route is a missed vulnerability)
  * client-side routes wrongly matched (must never be judged phantom)
  * abstention on entries whose correct answer is `unknown`

Usage
-----
    python3 scripts/evaluate_endpoint_reality.py --base-url http://host.docker.internal:3001
    (add --sample to point at a different labeled file; --json for machine-readable output)

Run it from inside the api container, which holds the dependencies and can reach the lab target.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from asm_inventory import (  # noqa: E402
    _learn_not_found_signatures,
    _path_prefix,
    _probe_auth_curl_config,
    _probe_path_status,
    _soft404_matches,
)
from runtime.endpoint_reality import classify_endpoint_reality  # noqa: E402

DEFAULT_SAMPLE = Path(__file__).resolve().parents[1] / "tests/fixtures/hunt/endpoint_reality_sample.json"


async def evaluate(base_url: str, entries: list[dict], timeout: int = 5) -> list[dict]:
    auth_config = _probe_auth_curl_config(None)
    sem = asyncio.Semaphore(12)
    # A fragment route is not a server path; probe only what the server can address.
    server_paths = [e["path"].split("#", 1)[0] or "/" for e in entries]
    prefixes = sorted({_path_prefix(p) for p in server_paths})
    signatures = await _learn_not_found_signatures(base_url, prefixes, auth_config, timeout, sem)

    async def probe(path: str) -> tuple[str, int]:
        async with sem:
            return await _probe_path_status(base_url, path, auth_config, timeout)

    probes = await asyncio.gather(*(probe(p) for p in server_paths))
    results = []
    for entry, server_path, probed in zip(entries, server_paths, probes):
        sigs = signatures.get(_path_prefix(server_path)) or []
        matched = any(_soft404_matches(probed, sig) for sig in sigs)
        # The three-valued classifier, which may abstain.
        judged = classify_endpoint_reality(
            probe_status=probed[0], probe_size=probed[1], signatures=sigs,
            probed_method="GET", declared_method=entry.get("method"), path=entry.get("path"),
        )
        results.append({
            **entry,
            "probe_status": probed[0],
            "probe_size": probed[1],
            "signatures": [list(s) for s in sigs],
            # The shipping filter's verdict: a match means "drop as phantom".
            "verdict": "phantom" if matched else "kept",
            "classified": judged.outcome,
            "reason": judged.reason,
        })
    return results


def report(results: list[dict]) -> dict:
    buckets: dict[str, dict[str, int]] = {}
    harmful: list[dict] = []
    for row in results:
        label = row["label"]
        bucket = buckets.setdefault(label, {"kept": 0, "phantom": 0})
        bucket[row["verdict"]] += 1
        # A real or client-side route judged phantom is the harmful error.
        if label in {"real", "client_route"} and row["verdict"] == "phantom":
            harmful.append(row)
    real = buckets.get("real", {})
    phantom = buckets.get("phantom", {})

    # The three-valued classifier, scored on the same sample. A wrong decision is the harm;
    # an abstention is an honest "cannot tell" and is counted separately, never as a success.
    classified: dict[str, dict[str, int]] = {}
    wrong: list[dict] = []
    for row in results:
        bucket = classified.setdefault(row["label"], {})
        bucket[row["classified"]] = bucket.get(row["classified"], 0) + 1
        truth, said = row["label"], row["classified"]
        if said == "unknown":
            continue
        if (truth in {"real", "client_route"} and said == "phantom") or (
            truth == "phantom" and said == "real"
        ):
            wrong.append(row)
    return {
        "by_label": buckets,
        "phantoms_identified": phantom.get("phantom", 0),
        "phantoms_total": sum(phantom.values()),
        "real_wrongly_demoted": real.get("phantom", 0),
        "real_total": sum(real.values()),
        "harmful_misclassifications": harmful,
        "classifier_by_label": classified,
        "classifier_wrong_decisions": wrong,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", required=True, help="Target origin, e.g. http://host.docker.internal:3001")
    ap.add_argument("--sample", default=str(DEFAULT_SAMPLE))
    ap.add_argument("--json", action="store_true", help="Emit machine-readable results")
    args = ap.parse_args()

    sample = json.loads(Path(args.sample).read_text())
    entries = sample["entries"]
    results = asyncio.run(evaluate(args.base_url, entries))
    summary = report(results)

    if args.json:
        print(json.dumps({"results": results, "summary": summary}, indent=2))
        return 0

    print(f"target: {args.base_url}   sample: {len(entries)} entries\n")
    print(f"{'label':<14}{'verdict':<10}{'status':<8}{'size':<8}path")
    for row in sorted(results, key=lambda r: (r["label"], r["path"])):
        print(f"{row['label']:<14}{row['verdict']:<10}{row['probe_status']:<8}{row['probe_size']:<8}{row['path']}")
    print("\n--- summary ---")
    print(f"phantoms identified : {summary['phantoms_identified']}/{summary['phantoms_total']}")
    print(f"REAL wrongly demoted: {summary['real_wrongly_demoted']}/{summary['real_total']}")
    for row in summary["harmful_misclassifications"]:
        print(f"  HARM: {row['label']} judged phantom -> {row['method']} {row['path']}")
    print("\nby label:", json.dumps(summary["by_label"]))

    print("\n--- three-valued classifier (runtime.endpoint_reality) ---")
    print(f"{'label':<14}{'says':<10}{'reason':<28}path")
    for row in sorted(results, key=lambda r: (r["label"], r["path"])):
        print(f"{row['label']:<14}{row['classified']:<10}{row['reason']:<28}{row['path']}")
    print(f"\nwrong decisions: {len(summary['classifier_wrong_decisions'])}")
    for row in summary["classifier_wrong_decisions"]:
        print(f"  WRONG: {row['label']} judged {row['classified']} -> {row['method']} {row['path']}")
    print("by label:", json.dumps(summary["classifier_by_label"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
