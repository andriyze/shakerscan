#!/usr/bin/env python3
"""Analyze DAST benchmark scan reports for misses and proof gaps."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SCANNER_DIR = REPO_ROOT / "scanner"
if str(SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(SCANNER_DIR))

from scanner_tools.benchmark_summary import (  # noqa: E402
    build_benchmark_summary,
    compare_benchmark_summaries,
)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"failed to load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} did not contain a JSON object")
    return value


def _resolve(path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else REPO_ROOT / p


def _expected_from_args(args: argparse.Namespace) -> dict[str, Any]:
    expected: dict[str, Any] = {"families": {}}
    for item in args.expect_family:
        # family:min_severity:min_confirmed, e.g. bola:high:1
        parts = item.split(":")
        if not parts[0]:
            raise ValueError(f"invalid --expect-family value: {item}")
        family = parts[0].strip().lower()
        min_severity = parts[1].strip().lower() if len(parts) > 1 and parts[1] else "high"
        try:
            min_confirmed = int(parts[2]) if len(parts) > 2 and parts[2] else 1
        except ValueError as exc:
            raise ValueError(f"invalid min_confirmed in --expect-family value: {item}") from exc
        expected["families"][family] = {
            "min_severity": min_severity,
            "min_confirmed": min_confirmed,
        }
    if args.expect_auth_state:
        expected["auth_states"] = args.expect_auth_state
    if args.expected_json:
        expected.update(_load_json(_resolve(args.expected_json)))
    return expected


def _summary_for(path: str, args: argparse.Namespace, *, run_mode: str) -> dict[str, Any]:
    report = _load_json(_resolve(path))
    return build_benchmark_summary(
        report,
        profile=args.profile,
        base_url=args.base_url,
        expected=_expected_from_args(args),
        run_mode=run_mode,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze DAST benchmark scan reports.")
    parser.add_argument("--profile", choices=["juice_shop", "crapi", "generic"], default="generic")
    parser.add_argument("--base-url")
    parser.add_argument("--result", help="Scan report JSON for baseline/candidate analysis.")
    parser.add_argument("--baseline-result", help="Baseline report JSON for compare mode.")
    parser.add_argument("--candidate-result", help="Candidate report JSON for compare mode.")
    parser.add_argument("--mode", choices=["baseline", "candidate", "compare"], default="baseline")
    parser.add_argument("--expect-family", action="append", default=[], help="family:min_severity:min_confirmed")
    parser.add_argument("--expect-auth-state", action="append", default=[])
    parser.add_argument("--expected-json", help="JSON object with benchmark expectations.")
    parser.add_argument("--out", help="Write summary JSON to this path.")
    args = parser.parse_args()

    try:
        if args.mode == "compare":
            if not args.baseline_result or not args.candidate_result:
                raise ValueError("compare mode requires --baseline-result and --candidate-result")
            baseline = _summary_for(args.baseline_result, args, run_mode="baseline")
            candidate = _summary_for(args.candidate_result, args, run_mode="candidate")
            output = {
                "baseline": baseline,
                "candidate": candidate,
                "comparison": compare_benchmark_summaries(baseline, candidate),
            }
        else:
            if not args.result:
                raise ValueError(f"{args.mode} mode requires --result")
            output = _summary_for(args.result, args, run_mode=args.mode)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    text = json.dumps(output, indent=2, sort_keys=True)
    if args.out:
        out = _resolve(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n")
        print(f"[benchmark] wrote {out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
