#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        raise RuntimeError(f"Failed to load JSON: {path} ({exc})") from exc


def _resolve_path(path_str: str, repo_root: Path, results_dir: Path | None = None) -> Path:
    p = Path(path_str)
    if p.is_absolute():
        return p
    if results_dir:
        return results_dir / p
    return repo_root / p


def _collect_metrics(report: dict) -> dict:
    findings = report.get("findings", []) or []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    tool_set = set()
    type_set = set()
    confirmed = 0
    unverified_high = 0
    low_confidence = 0

    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        tool = f.get("tool")
        if tool:
            tool_set.add(tool)
        f_type = f.get("type")
        if f_type:
            type_set.add(str(f_type).lower())
        if f.get("verified") is True:
            confirmed += 1
        if sev in ("high", "critical") and not f.get("verified"):
            unverified_high += 1
        if f.get("confidence_tier") in ("low", "uncertain"):
            low_confidence += 1

    quality_score = (report.get("quality_metrics") or {}).get("quality_score")
    smart_cov = report.get("smart_coverage") or {}
    endpoints_cov = smart_cov.get("endpoints") or {}
    endpoint_coverage = endpoints_cov.get("coverage")
    endpoints_discovered = endpoints_cov.get("discovered")
    endpoints_tested = endpoints_cov.get("tested")

    discovery = report.get("discovery") or {}
    har_stats = (discovery.get("har_discovery") or {}).get("stats") or {}
    methods_used = (discovery.get("summary") or {}).get("methods_used") or []

    return {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "confirmed": confirmed,
        "unverified_high": unverified_high,
        "low_confidence": low_confidence,
        "quality_score": quality_score,
        "endpoint_coverage": endpoint_coverage,
        "endpoints_discovered": endpoints_discovered,
        "endpoints_tested": endpoints_tested,
        "har_api_requests": har_stats.get("api_requests"),
        "har_unique_endpoints": har_stats.get("unique_endpoints"),
        "methods_used": methods_used,
        "tool_set": sorted(tool_set),
        "type_set": sorted(type_set),
    }


def _check_benchmark(name: str, report: dict, config: dict, strict: bool) -> tuple[bool, list[str], list[str], dict]:
    assertions = config.get("assertions") or {}
    allow_missing_har = bool(config.get("allow_missing_har"))

    metrics = _collect_metrics(report)
    failures: list[str] = []
    warnings: list[str] = []

    def fail(msg: str) -> None:
        failures.append(msg)

    def warn(msg: str) -> None:
        if strict:
            failures.append(msg)
        else:
            warnings.append(msg)

    if "min_total_findings" in assertions:
        if metrics["total_findings"] < assertions["min_total_findings"]:
            fail(f"total_findings {metrics['total_findings']} < {assertions['min_total_findings']}")

    if "min_high_or_critical" in assertions:
        high_count = metrics["severity_counts"]["high"] + metrics["severity_counts"]["critical"]
        if high_count < assertions["min_high_or_critical"]:
            fail(f"high_or_critical {high_count} < {assertions['min_high_or_critical']}")

    if "min_confirmed" in assertions:
        if metrics["confirmed"] < assertions["min_confirmed"]:
            fail(f"confirmed {metrics['confirmed']} < {assertions['min_confirmed']}")

    if "min_quality_score" in assertions:
        if metrics["quality_score"] is None:
            fail("quality_score missing")
        elif metrics["quality_score"] < assertions["min_quality_score"]:
            fail(f"quality_score {metrics['quality_score']} < {assertions['min_quality_score']}")

    if "min_endpoint_coverage" in assertions:
        if metrics["endpoint_coverage"] is None:
            fail("endpoint_coverage missing")
        elif metrics["endpoint_coverage"] < assertions["min_endpoint_coverage"]:
            fail(f"endpoint_coverage {metrics['endpoint_coverage']:.2f} < {assertions['min_endpoint_coverage']}")

    if "min_endpoints_discovered" in assertions:
        if metrics["endpoints_discovered"] is None:
            fail("endpoints_discovered missing")
        elif metrics["endpoints_discovered"] < assertions["min_endpoints_discovered"]:
            fail(f"endpoints_discovered {metrics['endpoints_discovered']} < {assertions['min_endpoints_discovered']}")

    if "min_endpoints_tested" in assertions:
        if metrics["endpoints_tested"] is None:
            fail("endpoints_tested missing")
        elif metrics["endpoints_tested"] < assertions["min_endpoints_tested"]:
            fail(f"endpoints_tested {metrics['endpoints_tested']} < {assertions['min_endpoints_tested']}")

    if "min_har_api_requests" in assertions:
        if metrics["har_api_requests"] is None:
            if allow_missing_har:
                warn("har_api_requests missing")
            else:
                fail("har_api_requests missing")
        elif metrics["har_api_requests"] < assertions["min_har_api_requests"]:
            fail(f"har_api_requests {metrics['har_api_requests']} < {assertions['min_har_api_requests']}")

    if "min_har_unique_endpoints" in assertions:
        if metrics["har_unique_endpoints"] is None:
            if allow_missing_har:
                warn("har_unique_endpoints missing")
            else:
                fail("har_unique_endpoints missing")
        elif metrics["har_unique_endpoints"] < assertions["min_har_unique_endpoints"]:
            fail(f"har_unique_endpoints {metrics['har_unique_endpoints']} < {assertions['min_har_unique_endpoints']}")

    if "require_methods_used" in assertions:
        missing = [m for m in assertions["require_methods_used"] if m not in metrics["methods_used"]]
        if missing:
            fail(f"methods_used missing: {missing}")

    if "require_any_finding_tools" in assertions:
        required = set(assertions["require_any_finding_tools"])
        if not required.intersection(set(metrics["tool_set"])):
            fail(f"no findings from required tools: {sorted(required)}")

    if "require_any_finding_types" in assertions:
        required = {t.lower() for t in assertions["require_any_finding_types"]}
        if not required.intersection(set(metrics["type_set"])):
            fail(f"no findings matching required types: {sorted(required)}")

    if "max_unverified_high_ratio" in assertions:
        high_count = metrics["severity_counts"]["high"] + metrics["severity_counts"]["critical"]
        if high_count > 0:
            ratio = metrics["unverified_high"] / high_count
            if ratio > assertions["max_unverified_high_ratio"]:
                fail(f"unverified_high_ratio {ratio:.2f} > {assertions['max_unverified_high_ratio']}")

    if "max_uncertain_ratio" in assertions:
        total = metrics["total_findings"]
        if total > 0:
            ratio = metrics["low_confidence"] / total
            if ratio > assertions["max_uncertain_ratio"]:
                fail(f"uncertain_ratio {ratio:.2f} > {assertions['max_uncertain_ratio']}")

    return (len(failures) == 0), failures, warnings, metrics


def main() -> int:
    parser = argparse.ArgumentParser(description="Run scan benchmark assertions")
    parser.add_argument("--benchmarks", default="tests/benchmark/benchmarks.json", help="Path to benchmarks JSON")
    parser.add_argument("--results-dir", default=None, help="Base directory to resolve relative result paths")
    parser.add_argument("--result", action="append", default=[], help="Override result path: name=path")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as failures")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    bench_path = _resolve_path(args.benchmarks, repo_root)
    config = _load_json(bench_path)
    benchmarks = config.get("benchmarks", [])
    if not benchmarks:
        print("No benchmarks configured.", file=sys.stderr)
        return 2

    results_dir = Path(args.results_dir) if args.results_dir else None
    overrides = {}
    for item in args.result:
        if "=" not in item:
            print(f"Invalid --result override (expected name=path): {item}", file=sys.stderr)
            return 2
        name, path = item.split("=", 1)
        overrides[name.strip()] = path.strip()

    any_fail = False
    for bench in benchmarks:
        name = bench.get("name") or "unnamed"
        result_path = overrides.get(name) or bench.get("result_path")
        if not result_path:
            print(f"[{name}] missing result_path", file=sys.stderr)
            any_fail = True
            continue

        resolved = _resolve_path(result_path, repo_root, results_dir)
        if not resolved.exists():
            print(f"[{name}] result file not found: {resolved}", file=sys.stderr)
            any_fail = True
            continue

        report = _load_json(resolved)
        ok, failures, warnings, metrics = _check_benchmark(name, report, bench, args.strict)
        status = "PASS" if ok else "FAIL"
        print(f"[{name}] {status} | findings={metrics['total_findings']} high+={metrics['severity_counts']['high'] + metrics['severity_counts']['critical']} quality={metrics['quality_score']}")
        for w in warnings:
            print(f"[{name}] WARN: {w}")
        for f in failures:
            print(f"[{name}] FAIL: {f}")
        if not ok:
            any_fail = True

    return 1 if any_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
