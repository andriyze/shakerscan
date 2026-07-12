#!/usr/bin/env python3
"""Re-derivable acceptance recompute (Wave 7).

The discipline borrowed from the reviewed reference implementation: *never trust a stored score —
recompute the verdict from the committed raw artifacts and fail on drift.*

The raw scan reports (``tests/benchmark/results/<app>/latest.json``) are large gitignored scratch
outputs, so a **faithful distilled** report (findings + the context the scorer reads) is committed to
``tests/fixtures/benchmarks/samples/<app>.report.json`` alongside a committed oracle
``<app>.acceptance.json``. For each app we recompute the scorecard + gates with the SAME predicate
the live runner uses (``benchmark_targets.collect_scorecard`` / ``apply_gates``) from the committed
sample and diff it against the committed oracle. Distillation faithfulness (distilled recompute ==
full recompute) is asserted at sample-generation time.

Usage:
    python3 scripts/verify_acceptance.py            # recompute + check against committed oracles
    python3 scripts/verify_acceptance.py --update    # (re)write the oracles from the committed samples
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import benchmark_targets as bt  # noqa: E402
import yaml  # noqa: E402

FIXTURE_DIR = os.path.join(ROOT, "tests", "fixtures", "benchmarks")
SAMPLES_DIR = os.path.join(FIXTURE_DIR, "samples")

# app -> fixture stem (fixtures use underscores).
APPS = {"juice-shop": "juice_shop", "crapi": "crapi"}


def _report_path(app: str) -> str:
    return os.path.join(SAMPLES_DIR, f"{app}.report.json")


def _oracle_path(app: str) -> str:
    return os.path.join(SAMPLES_DIR, f"{app}.acceptance.json")


def recompute(app: str, fixture_stem: str) -> dict:
    with open(_report_path(app)) as fh:
        report = json.load(fh)
    with open(os.path.join(FIXTURE_DIR, f"{fixture_stem}.yaml")) as fh:
        fixture = yaml.safe_load(fh)
    card = bt.collect_scorecard(report, fixture)
    gates = bt.apply_gates(card, fixture)
    return {
        "verified_high_critical": card.get("verified_high_critical"),
        "verified_high_critical_families": sorted(card.get("verified_high_critical_families") or []),
        "browser_proven_high_critical_families": sorted(card.get("browser_proven_high_critical_families") or []),
        "false_positive_risk": card.get("false_positive_risk"),
        "gates": {g["gate"]: bool(g["pass"]) for g in gates},
    }


def main(argv: list[str]) -> int:
    update = "--update" in argv[1:]
    exit_code = 0
    for app, fixture_stem in APPS.items():
        if not os.path.exists(_report_path(app)):
            print(f"[skip] {app}: no committed sample report")
            continue
        try:
            metrics = recompute(app, fixture_stem)
        except Exception as exc:  # noqa: BLE001
            print(f"[error] {app}: recompute failed: {type(exc).__name__}: {exc}")
            exit_code = 2
            continue
        if update:
            with open(_oracle_path(app), "w") as fh:
                json.dump(metrics, fh, indent=2, sort_keys=True)
                fh.write("\n")
            print(f"[wrote] {app}: verified_hc={metrics['verified_high_critical']} "
                  f"families={metrics['verified_high_critical_families']}")
            continue
        if not os.path.exists(_oracle_path(app)):
            print(f"[missing-oracle] {app}: run --update to pin the oracle")
            exit_code = 2
            continue
        with open(_oracle_path(app)) as fh:
            oracle = json.load(fh)
        if metrics == oracle:
            gates_pass = sum(1 for v in metrics["gates"].values() if v)
            print(f"[ok] {app}: recompute matches oracle "
                  f"(verified_hc={metrics['verified_high_critical']}, {gates_pass}/{len(metrics['gates'])} gates)")
        else:
            print(f"[DRIFT] {app}: recompute != committed oracle")
            for key in sorted(set(metrics) | set(oracle)):
                if metrics.get(key) != oracle.get(key):
                    print(f"    {key}: oracle={oracle.get(key)!r} recomputed={metrics.get(key)!r}")
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
