#!/usr/bin/env python3
"""Run an authorized safe-remote scan against one physical device target."""

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
    parser.add_argument("--locator", required=True)
    parser.add_argument("--port", action="append", type=int, default=[])
    parser.add_argument("--timeout-seconds", type=int, default=1_800)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    health = request(args.api_url, "GET", "/health")
    if health.get("source_revision") != args.candidate_sha:
        raise SystemExit("deployed API source revision does not match the candidate")
    created = request(args.api_url, "POST", "/devices", {
        "name": f"Release device {args.candidate_sha[:12]}",
        "primary_locator": args.locator,
        "device_class": "generic",
        "identity_confidence": "verified",
        "environment": "lab",
    })
    device_id = str((created.get("device") or {}).get("id") or "")
    if not device_id:
        raise SystemExit("physical device registration returned no identity")
    try:
        queued = request(args.api_url, "POST", f"/devices/{device_id}/scan", {
            "profile": "posture",
            "safety_profile": "safe_remote",
            "confirm_authorized": True,
            "include_web_dast": False,
            "port_hints": args.port,
        })
        scan_id = str(queued.get("scan_id") or "")
        if not scan_id:
            raise SystemExit("physical device scan returned no identity")
        deadline = time.monotonic() + args.timeout_seconds
        scan = {}
        while time.monotonic() < deadline:
            scan = request(args.api_url, "GET", f"/scans/{scan_id}")
            if scan.get("status") in {"completed", "failed", "cancelled"}:
                break
            time.sleep(5)
        result = scan.get("result") if isinstance(scan.get("result"), dict) else {}
        posture = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
        reachability = posture.get("reachability") if isinstance(posture.get("reachability"), dict) else {}
        completeness = posture.get("completeness") if isinstance(posture.get("completeness"), dict) else {}
        passed = (
            scan.get("status") == "completed"
            and reachability.get("status") == "online"
            and completeness.get("reachability_confirmed") is True
        )
        receipt = {
            "schema_version": "shakerscan-device-physical-acceptance/v1",
            "candidate_sha": args.candidate_sha,
            "device_id": device_id,
            "scan_id": scan_id,
            "scan_status": scan.get("status"),
            "reachability_status": reachability.get("status"),
            "reachability_confirmed": completeness.get("reachability_confirmed"),
            "confirmed_services": len(posture.get("services") or []),
            "status": "pass" if passed else "fail",
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        if not passed:
            raise SystemExit(f"physical device acceptance failed: {receipt}")
    finally:
        request(args.api_url, "DELETE", f"/devices/{device_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
