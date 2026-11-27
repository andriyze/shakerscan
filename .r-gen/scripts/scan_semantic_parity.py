#!/usr/bin/env python3
"""Compare content-free artifacts from real local, broker, and parallel Scans."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from api.scan.parity import (  # noqa: E402
    compare_scan_semantic_parity,
    parity_artifact_is_truthful,
)


def _fetch_json(url: str) -> dict:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"parity artifact request failed ({exc.code}): {detail}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("parity artifact response must be an object")
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compare semantic output from three completed real Scans. Runtime "
            "placement, worker IDs, timestamps, durations, and receipt IDs are ignored."
        ),
    )
    parser.add_argument("--api-url", default="http://localhost:8080")
    parser.add_argument("--local", required=True, metavar="SCAN_ID")
    parser.add_argument("--broker", required=True, metavar="SCAN_ID")
    parser.add_argument("--parallel", required=True, metavar="SCAN_ID")
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    base = args.api_url.rstrip("/")
    scan_ids = {
        "local": args.local,
        "broker": args.broker,
        "parallel": args.parallel,
    }
    artifacts = {
        label: _fetch_json(f"{base}/scans/{scan_id}/parity-artifact")
        for label, scan_id in scan_ids.items()
    }
    untruthful = sorted(
        label for label, artifact in artifacts.items()
        if not parity_artifact_is_truthful(artifact)
    )
    comparison = compare_scan_semantic_parity(artifacts)
    receipt = {
        **comparison,
        "scan_ids": scan_ids,
        "semantic_digests": {
            label: artifact.get("semantic_digest")
            for label, artifact in artifacts.items()
        },
        "truthful": not untruthful,
        "untruthful_artifacts": untruthful,
    }
    if args.json_output:
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    else:
        verdict = "PASS" if comparison["consistent"] and not untruthful else "FAIL"
        print(f"V2 Scan semantic parity: {verdict}")
        for item in comparison["comparisons"]:
            print(
                f"  {item['baseline']} vs {item['candidate']}: "
                f"{item['difference_count']} semantic difference(s)"
            )
        if untruthful:
            print(f"  fail-closed report truth violation: {', '.join(untruthful)}")
    return 0 if comparison["consistent"] and not untruthful else 1


if __name__ == "__main__":
    raise SystemExit(main())
