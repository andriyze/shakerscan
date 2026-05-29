#!/usr/bin/env python3
"""Run local Honey calibration scenarios through ShakerScan.

Example:
    python3 scripts/honey_calibration.py --wait
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import urllib.parse
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.calibration import (  # noqa: E402
    request_json,
    try_request_json,
    wait_for_scans as _wait_for_scans,
)


def docker_url(url: str, docker_base: str, run_id: str, scenario_id: str | None = None) -> str:
    parsed = urllib.parse.urlparse(url)
    base = urllib.parse.urlparse(docker_base)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query["calibration_run"] = run_id
    if scenario_id:
        query["calibration_scenario"] = scenario_id
    return urllib.parse.urlunparse((base.scheme, base.netloc, parsed.path, "", urllib.parse.urlencode(query), ""))


def scanner_reachable_url(url: str, docker_base: str, run_id: str, scenario_id: str | None = None) -> str:
    """Map local Honey URLs to a scanner-container-reachable URL."""
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return docker_url(url, docker_base, run_id, scenario_id)
    return url


def request_template_with_prompt(template: Any, surface: str) -> dict[str, Any]:
    updated = copy.deepcopy(template) if isinstance(template, dict) else {}
    if surface in {"rag", "agent"}:
        updated["message"] = "{{prompt}}"
        updated.setdefault("session_id", "{{session_id}}")
    elif surface == "mcp":
        params = updated.setdefault("params", {})
        if not isinstance(params, dict):
            params = {}
            updated["params"] = params
        params["prompt"] = "{{prompt}}"
        updated.setdefault("id", "{{session_id}}")
    else:
        updated["message"] = "{{prompt}}"
    return updated


def queue_error_item(
    *,
    kind: str,
    scenario_id: str,
    safe: bool,
    expected: list[str],
    error: Exception,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "scenario_id": scenario_id,
        "safe": safe,
        "expected": expected,
        "scan_id": None,
        "ui_url": None,
        "queue_error": str(error),
    }


def queue_dast(args: argparse.Namespace, run_id: str) -> list[dict[str, Any]]:
    registry = try_request_json(f"{args.honey_local}/api/dast/scenarios")
    scenarios = registry.get("scenarios", []) if isinstance(registry, dict) else []
    if not scenarios and args.dast_target:
        scenarios = [
            {
                "id": "honey-dast-smoke",
                "target_url": args.dast_target,
                "scan_type": args.dast_scan_type,
                "safe_fixture": False,
                "expected_shakerscan_findings": [],
                "options": {},
            }
        ]

    queued = []
    active_scan_types = {"smart", "full", "aggressive"}
    for scenario in scenarios:
        scenario_id = scenario["id"]
        if args.scenario and args.scenario != scenario_id:
            continue

        scan_type = str(scenario.get("scan_type") or args.dast_scan_type).strip().lower()
        expected = scenario.get("expected_shakerscan_findings", [])
        safe = scenario.get("safe_fixture") is True
        if scan_type in active_scan_types and not args.allow_active_dast:
            queued.append({
                "kind": "dast",
                "scenario_id": scenario_id,
                "safe": safe,
                "expected": expected,
                "scan_id": None,
                "ui_url": None,
                "skipped": f"{scan_type} requires --allow-active-dast",
            })
            continue

        target_url = scanner_reachable_url(
            scenario["target_url"],
            args.honey_docker,
            run_id,
            scenario_id,
        )
        options = dict(scenario.get("options") or {})
        options.update({
            "scan_type": scan_type,
            "budget_profile": scenario.get("budget_profile") or args.dast_budget_profile,
        })
        if scan_type in {"quick", "standard", "deep"}:
            options.setdefault("public", True)

        try:
            scan = request_json(
                f"{args.api}/scans",
                method="POST",
                payload={"target": target_url, "options": options},
            )
            queued.append({
                "kind": "dast",
                "scenario_id": scenario_id,
                "safe": safe,
                "expected": expected,
                "scan_id": scan["scan_id"],
                "ui_url": scan.get("ui_url") or f"/scans/{scan['scan_id']}",
                "target_url": target_url,
                "scan_type": scan_type,
            })
        except Exception as exc:  # noqa: BLE001
            print(f"dast queue error for {scenario_id}: {exc}", file=sys.stderr)
            queued.append(queue_error_item(
                kind="dast",
                scenario_id=scenario_id,
                safe=safe,
                expected=expected,
                error=exc,
            ))
    return queued


def queue_ai_gate(args: argparse.Namespace, run_id: str) -> list[dict[str, Any]]:
    registry = request_json(f"{args.honey_local}/api/ai-gate/scenarios")
    surface_config = {
        "rag": ("rag", "$.answer", "shaker-rag-lite"),
        "agent": ("agent_trace", "$", "shaker-agent-abuse"),
        "mcp": ("mcp_trace", "$.result", "shaker-mcp-security"),
    }
    queued = []
    for scenario in registry.get("scenarios", []):
        scenario_id = scenario["id"]
        if args.scenario and args.scenario != scenario_id:
            continue
        expected = scenario.get("expected_shakerscan_findings", [])
        safe = scenario.get("safe_fixture") is True
        try:
            surface = scenario.get("surface") or "rag"
            target_type, response_path, probe_pack = surface_config.get(surface, surface_config["rag"])
            metadata = copy.deepcopy(scenario.get("metadata_json") or {})
            metadata.update({
                "calibration_run": run_id,
                "honey_scenario_id": scenario_id,
                "expected_shakerscan_findings": expected,
                "safe_fixture": safe,
            })
            target_response = request_json(
                f"{args.api}/ai/targets",
                method="POST",
                payload={
                    "name": f"Local Honey calibration {scenario_id} {run_id}",
                    "target_type": target_type,
                    "endpoint_url": docker_url(scenario["target_url"], args.honey_docker, run_id, scenario_id),
                    "method": scenario.get("method") or "POST",
                    "headers_template": {"Content-Type": "application/json", "Accept": "application/json"},
                    "request_template": request_template_with_prompt(scenario.get("target_template"), surface),
                    "response_path": response_path,
                    "streaming_mode": "json",
                    "rate_limit_rps": 10,
                    "request_budget": args.ai_request_budget,
                    "token_budget": 4000,
                    "production_mode": False,
                    "metadata_json": metadata,
                },
            )
            target = target_response["target"]
            scan = request_json(
                f"{args.api}/ai/targets/{target['id']}/scan",
                method="POST",
                payload={
                    "probe_pack": probe_pack,
                    "scan_profile": args.ai_profile,
                    "environment": "development",
                    "ai_judge_enabled": False,
                    "semantic_judge_enabled": False,
                },
            )
            queued.append({
                "kind": "ai_gate",
                "scenario_id": scenario_id,
                "safe": safe,
                "expected": expected,
                "scan_id": scan["scan_id"],
                "ui_url": scan.get("ui_url") or f"/scans/{scan['scan_id']}",
            })
        except Exception as exc:  # noqa: BLE001
            print(f"ai_gate queue error for {scenario_id}: {exc}", file=sys.stderr)
            queued.append(queue_error_item(
                kind="ai_gate",
                scenario_id=scenario_id,
                safe=safe,
                expected=expected,
                error=exc,
            ))
    return queued


def queue_model_intake(args: argparse.Namespace, run_id: str) -> list[dict[str, Any]]:
    registry = request_json(f"{args.honey_local}/api/model-intake/scenarios")
    queued = []
    for scenario in registry.get("scenarios", []):
        scenario_id = scenario["id"]
        if args.scenario and args.scenario != scenario_id:
            continue
        expected = scenario.get("expected_shakerscan_findings", [])
        safe = scenario.get("should_pass") is True
        try:
            artifact_url = scenario["artifact_url"]
            metadata_url = scenario.get("metadata_url")
            if artifact_url.startswith("https://honey.shakerscan.com"):
                artifact_url = docker_url(artifact_url, args.honey_docker, run_id, scenario_id)
            if isinstance(metadata_url, str) and metadata_url.startswith("https://honey.shakerscan.com"):
                metadata_url = docker_url(metadata_url, args.honey_docker, run_id, scenario_id)
            scan = request_json(
                f"{args.api}/model-intake/scan",
                method="POST",
                payload={
                    "artifact_url": artifact_url,
                    "metadata_url": metadata_url,
                    "expected_sha256": scenario.get("expected_sha256"),
                    "max_download_bytes": 10_000_000,
                    "timeout_seconds": 20,
                },
            )
            queued.append({
                "kind": "model_intake",
                "scenario_id": scenario_id,
                "safe": safe,
                "expected": expected,
                "scan_id": scan["scan_id"],
                "ui_url": scan.get("ui_url") or f"/scans/{scan['scan_id']}",
            })
        except Exception as exc:  # noqa: BLE001
            print(f"model_intake queue error for {scenario_id}: {exc}", file=sys.stderr)
            queued.append(queue_error_item(
                kind="model_intake",
                scenario_id=scenario_id,
                safe=safe,
                expected=expected,
                error=exc,
            ))
    return queued


def wait_for_scans(args: argparse.Namespace, queued: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _wait_for_scans(
        args.api,
        queued,
        timeout=args.timeout,
        poll_interval=args.poll_interval,
    )


def finding_ids(result: dict[str, Any]) -> set[str]:
    return {str(finding.get("id")) for finding in result.get("findings", []) if isinstance(finding, dict)}


def oracle_expected(result: dict[str, Any]) -> set[str]:
    expected = set()
    for finding in result.get("findings", []):
        if not isinstance(finding, dict):
            continue
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        value = evidence.get("expected_finding")
        if value:
            expected.add(str(value))
    return expected


def validate(items: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    passed = []
    failed = []
    for item in items:
        detail = item.get("detail") or {}
        result = detail.get("result") if isinstance(detail.get("result"), dict) else {}
        raw_ids = finding_ids(result)
        expected = set(item.get("expected") or [])
        detected = oracle_expected(result) if item["kind"] == "ai_gate" else raw_ids
        errors = []
        if item.get("queue_error"):
            errors.append(f"queue error: {item['queue_error']}")
        if item.get("skipped"):
            errors.append(f"skipped: {item['skipped']}")
        if not item.get("skipped") and detail.get("status") != "completed":
            errors.append(f"scan status is {detail.get('status')}")
        if item.get("safe") and raw_ids:
            errors.append(f"safe fixture produced findings: {sorted(raw_ids)}")
        missing = expected - detected
        if missing:
            errors.append(f"missing expected findings: {sorted(missing)}")
        verdict = {
            "scenario_id": item["scenario_id"],
            "kind": item["kind"],
            "scan_id": item["scan_id"],
            "ui_url": item["ui_url"],
            "expected": sorted(expected),
            "detected": sorted(detected),
            "raw_findings": sorted(raw_ids),
            "grade": detail.get("grade"),
            "score": detail.get("score"),
            "errors": errors,
        }
        (failed if errors else passed).append(verdict)
    return passed, failed


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local Honey calibration scenarios through ShakerScan.")
    parser.add_argument("--api", default="http://localhost:8080")
    parser.add_argument("--honey-local", default="http://localhost:18080")
    parser.add_argument("--honey-docker", default="http://host.docker.internal:18080")
    parser.add_argument("--suite", choices=["all", "dast", "ai-gate", "model-intake"], default="all")
    parser.add_argument("--scenario", help="Run only one Honey scenario id.")
    parser.add_argument("--wait", action="store_true", help="Wait for scans and validate results.")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--dast-target", default="https://honey.shakerscan.com/")
    parser.add_argument("--dast-scan-type", default="quick", choices=["quick", "standard", "deep", "full", "aggressive", "smart"])
    parser.add_argument("--dast-budget-profile", default="fast", choices=["fast", "balanced", "thorough", "exhaustive"])
    parser.add_argument("--allow-active-dast", action="store_true", help="Allow full/aggressive/smart Honey DAST scenarios.")
    parser.add_argument("--ai-profile", default="smoke", choices=["smoke", "trace", "standard", "deep"])
    parser.add_argument("--ai-request-budget", type=int, default=1)
    args = parser.parse_args()

    run_id = f"local-honey-{int(time.time())}"
    queued: list[dict[str, Any]] = []
    if args.suite in {"all", "dast"}:
        queued.extend(queue_dast(args, run_id))
    if args.suite in {"all", "ai-gate"}:
        queued.extend(queue_ai_gate(args, run_id))
    if args.suite in {"all", "model-intake"}:
        queued.extend(queue_model_intake(args, run_id))

    if not args.wait:
        print(json.dumps({"run_id": run_id, "queued": queued}, indent=2))
        return 1 if any(item.get("queue_error") for item in queued) else 0

    completed = wait_for_scans(args, queued)
    passed, failed = validate(completed)
    print(json.dumps({"run_id": run_id, "passed": passed, "failed": failed}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
