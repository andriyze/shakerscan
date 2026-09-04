#!/usr/bin/env python3
"""Queue DAST benchmark scans and export completed reports.

The benchmark assertion runner checks JSON reports on disk. This script closes
the loop by submitting configured benchmark targets to a running ShakerScan API,
waiting for completion when requested, and writing each scan's report back to
the configured result path.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.calibration import request_json, wait_for_scans  # noqa: E402
from benchmark_targets import _canonical_benchmark_authority  # noqa: E402


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"failed to load {path}: {exc}") from exc


def resolve_path(path_str: str, repo_root: Path) -> Path:
    path = Path(path_str)
    return path if path.is_absolute() else repo_root / path


def parse_name_url(items: list[str]) -> list[dict[str, Any]]:
    benchmarks = []
    for item in items:
        if "=" not in item:
            raise ValueError(f"invalid --target value (expected name=url): {item}")
        name, url = item.split("=", 1)
        name = name.strip()
        url = url.strip()
        if not name or not url:
            raise ValueError(f"invalid --target value (expected name=url): {item}")
        benchmarks.append({
            "name": name,
            "target_url": url,
            "result_path": f"results/{name}/latest.json",
            "scan_options": {},
        })
    return benchmarks


def benchmark_entries(config: dict[str, Any], names: set[str] | None) -> list[dict[str, Any]]:
    entries = []
    for bench in config.get("benchmarks", []):
        name = str(bench.get("name") or "")
        if names and name not in names:
            continue
        if bench.get("disabled"):
            continue
        if not bench.get("target_url"):
            continue
        entries.append(bench)
    return entries


def merged_request(bench: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    options = dict(bench.get("scan_options") or {})
    forbidden = sorted({
        "scan_type", "quick", "thorough", "active", "xss", "sqli",
        "check_family", "asm_check_family",
    }.intersection(options))
    if forbidden:
        raise RuntimeError(
            "benchmark config contains removed Scan authority: " + ", ".join(forbidden)
        )
    budget_profile = args.budget_profile or str(options.pop("budget_profile", "balanced"))
    active_testing = bool(args.active_testing or options.pop("active_testing", False))
    if args.public:
        options["public"] = True
    if args.custom_budget:
        options["custom_budget"] = json.loads(args.custom_budget)
    return {
        "budget_profile": budget_profile,
        "policy": {"active_testing": active_testing},
        "options": options,
    }


def queue_scan(api: str, bench: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    payload = {"target": bench["target_url"], **request}
    if request["policy"]["active_testing"]:
        _target_id, approval_id = _canonical_benchmark_authority(
            api.rstrip('/'), bench["target_url"], credential_risk=False,
        )
        payload["approval_receipt_id"] = approval_id
    scan = request_json(f"{api.rstrip('/')}/scans", method="POST", payload=payload, timeout=60)
    scan_id = scan["scan_id"]
    return {
        "name": bench["name"],
        "target_url": bench["target_url"],
        "scan_id": scan_id,
        "ui_url": scan.get("ui_url") or f"/scans/{scan_id}",
        "result_path": bench.get("result_path"),
        "request": request,
    }


def export_report(repo_root: Path, item: dict[str, Any]) -> dict[str, Any]:
    detail = item.get("detail") or {}
    report = detail.get("result")
    if not isinstance(report, dict):
        raise RuntimeError(f"{item['name']} has no report result to export")

    result_path = item.get("result_path") or f"results/{item['name']}/latest.json"
    latest = resolve_path(str(result_path), repo_root)
    latest.parent.mkdir(parents=True, exist_ok=True)
    latest.write_text(json.dumps(report, indent=2, sort_keys=True))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    scan_short = str(item["scan_id"]).split("-", 1)[0]
    snapshot = latest.with_name(f"{stamp}_{scan_short}.json")
    snapshot.write_text(json.dumps(report, indent=2, sort_keys=True))
    return {"latest": str(latest), "snapshot": str(snapshot)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Queue DAST benchmark scans and export completed reports.")
    parser.add_argument("--api", default="http://127.0.0.1:8080")
    parser.add_argument("--benchmarks", default="tests/benchmark/honey_benchmarks.json")
    parser.add_argument("--benchmark", action="append", default=[], help="Benchmark name to run from config.")
    parser.add_argument("--target", action="append", default=[], help="Ad hoc benchmark target as name=url.")
    parser.add_argument("--budget-profile", choices=["fast", "balanced", "thorough", "deep"])
    parser.add_argument("--active-testing", action="store_true", help="Authorize active DAST for selected targets.")
    parser.add_argument("--custom-budget", help="JSON custom_budget override.")
    parser.add_argument("--public", action="store_true", help="Force public-only option on queued scans.")
    parser.add_argument("--wait", action="store_true", help="Wait for scans to complete.")
    parser.add_argument("--export-results", action="store_true", help="Write completed scan reports to result_path.")
    parser.add_argument("--timeout", type=int, default=7200)
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument("--summary-out", help="Write queue/completion summary JSON.")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    selected_names = set(args.benchmark) if args.benchmark else None

    try:
        config = load_json(resolve_path(args.benchmarks, repo_root))
        entries = benchmark_entries(config, selected_names)
        entries.extend(parse_name_url(args.target))
    except Exception as exc:  # noqa: BLE001
        print(str(exc), file=sys.stderr)
        return 2

    if not entries:
        print("No benchmark targets selected. Add target_url entries or pass --target name=url.", file=sys.stderr)
        return 2

    queued: list[dict[str, Any]] = []
    queue_errors: list[str] = []
    for bench in entries:
        try:
            request = merged_request(bench, args)
            item = queue_scan(args.api, bench, request)
            queued.append(item)
            print(f"[{item['name']}] queued scan_id={item['scan_id']} target={item['target_url']}")
        except Exception as exc:  # noqa: BLE001
            error = f"[{bench['name']}] queue failed: {exc}"
            queue_errors.append(error)
            print(error, file=sys.stderr)

    completed = (
        wait_for_scans(args.api, queued, timeout=args.timeout, poll_interval=args.poll_interval)
        if args.wait
        else queued
    )
    export_errors: list[str] = []
    if args.export_results:
        if not args.wait:
            export_errors.append("--export-results requires --wait")
        for item in completed:
            detail = item.get("detail") or {}
            if detail.get("status") != "completed":
                export_errors.append(f"{item['name']} status is {detail.get('status')}")
                continue
            try:
                item["exports"] = export_report(repo_root, item)
                print(f"[{item['name']}] exported {item['exports']['latest']}")
            except Exception as exc:  # noqa: BLE001
                export_errors.append(f"{item['name']} export failed: {exc}")

    summary = {
        "queued": queued,
        "completed": completed,
        "queue_errors": queue_errors,
        "export_errors": export_errors,
    }
    if args.summary_out:
        out_path = resolve_path(args.summary_out, repo_root)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, indent=2, sort_keys=True))
        print(f"[summary] wrote {out_path}")

    if queue_errors or export_errors:
        for error in queue_errors:
            print(f"ERROR: {error}", file=sys.stderr)
        for error in export_errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
