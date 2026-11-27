#!/usr/bin/env python3
"""Exercise one real Hugging Face review through the exact KVM runner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import time
import urllib.error
import urllib.request


def request(base: str, method: str, path: str, payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=body,
        method=method,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{method} {path} returned HTTP {exc.code}: {exc.read(2000)!r}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=10_800)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    health = request(args.api_url, "GET", "/health")
    if health.get("source_revision") != args.candidate_sha:
        raise SystemExit("deployed API source revision does not match the candidate")
    readiness = request(args.api_url, "GET", "/model-intake/runners/readiness")
    if readiness.get("ready") is not True or readiness.get("executor") != "firecracker-jailer":
        raise SystemExit(f"exact KVM runner is not ready: {readiness}")
    started = request(args.api_url, "POST", "/model-intake/automatic-reviews", {
        "source": args.source,
        "intended_environment": "test",
    })
    review_id = str((started.get("review") or {}).get("id") or "")
    if not review_id:
        raise SystemExit("automatic review did not return an identity")
    deadline = time.monotonic() + args.timeout_seconds
    review = {}
    while time.monotonic() < deadline:
        review = request(args.api_url, "GET", f"/model-intake/automatic-reviews/{review_id}")
        if review.get("state") in {"technical_review_complete", "attention_required", "failed", "cancelled"}:
            break
        time.sleep(10)
    timeline = review.get("timeline_json") if isinstance(review.get("timeline_json"), list) else []
    events = {str(item.get("event")) for item in timeline if isinstance(item, dict)}
    passed = (
        review.get("state") == "technical_review_complete"
        and "runtime_verification_completed" in events
        and review.get("technical_outcome") != "INCOMPLETE"
    )
    receipt = {
        "schema_version": "shakerscan-model-intake-physical-acceptance/v1",
        "candidate_sha": args.candidate_sha,
        "review_id": review_id,
        "state": review.get("state"),
        "technical_outcome": review.get("technical_outcome"),
        "runtime_verification_completed": "runtime_verification_completed" in events,
        "runner": {"executor": readiness.get("executor"), "ready": readiness.get("ready")},
        "status": "pass" if passed else "fail",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    if not passed:
        raise SystemExit(f"physical Model Intake acceptance failed: {receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
