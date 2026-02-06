#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path
from typing import Any


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


def _parse_overrides(items: list[str], label: str) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"Invalid {label} override (expected name=path): {item}")
        name, path = item.split("=", 1)
        overrides[name.strip()] = path.strip()
    return overrides


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return numerator / denominator


def _format_ratio(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}"


def _collect_metrics(report: dict) -> dict[str, Any]:
    findings = report.get("findings", []) or []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    tool_set = set()
    type_set = set()
    confirmed = 0
    unverified_high = 0
    low_confidence = 0
    high_verified = 0
    critical_verified = 0

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
        verified = f.get("verified") is True
        if verified:
            confirmed += 1
        if sev in ("high", "critical") and not verified:
            unverified_high += 1
        if sev == "high" and verified:
            high_verified += 1
        if sev == "critical" and verified:
            critical_verified += 1
        if f.get("confidence_tier") in ("low", "uncertain"):
            low_confidence += 1

    high_total = severity_counts["high"]
    critical_total = severity_counts["critical"]
    high_or_critical_total = high_total + critical_total

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
        "high_total": high_total,
        "critical_total": critical_total,
        "high_verified": high_verified,
        "critical_verified": critical_verified,
        "high_precision": _ratio(high_verified, high_total),
        "critical_precision": _ratio(critical_verified, critical_total),
        "unverified_high_ratio": _ratio(unverified_high, high_or_critical_total),
    }


def _apply_assertions(
    assertions: dict[str, Any],
    metrics: dict[str, Any],
    fail,
    warn,
    allow_missing_har: bool = False,
) -> None:
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

    if "min_high_precision" in assertions:
        precision = metrics.get("high_precision")
        if precision is None:
            warn("high_precision unavailable (no high findings)")
        elif precision < assertions["min_high_precision"]:
            fail(f"high_precision {precision:.2f} < {assertions['min_high_precision']}")

    if "min_critical_precision" in assertions:
        precision = metrics.get("critical_precision")
        if precision is None:
            warn("critical_precision unavailable (no critical findings)")
        elif precision < assertions["min_critical_precision"]:
            fail(f"critical_precision {precision:.2f} < {assertions['min_critical_precision']}")

    if "max_unverified_high_ratio" in assertions:
        ratio = metrics.get("unverified_high_ratio")
        if ratio is None:
            warn("unverified_high_ratio unavailable (no high/critical findings)")
        elif ratio > assertions["max_unverified_high_ratio"]:
            fail(f"unverified_high_ratio {ratio:.2f} > {assertions['max_unverified_high_ratio']}")

    if "max_uncertain_ratio" in assertions:
        total = metrics["total_findings"]
        if total > 0:
            ratio = metrics["low_confidence"] / total
            if ratio > assertions["max_uncertain_ratio"]:
                fail(f"uncertain_ratio {ratio:.2f} > {assertions['max_uncertain_ratio']}")


def _apply_regression_assertions(
    assertions: dict[str, Any],
    metrics: dict[str, Any],
    baseline_metrics: dict[str, Any],
    fail,
    warn,
) -> None:
    if "max_high_precision_drop" in assertions:
        current = metrics.get("high_precision")
        baseline = baseline_metrics.get("high_precision")
        if current is None or baseline is None:
            warn("high_precision regression unavailable")
        else:
            drop = baseline - current
            if drop > assertions["max_high_precision_drop"]:
                fail(f"high_precision drop {drop:.2f} > {assertions['max_high_precision_drop']}")

    if "max_critical_precision_drop" in assertions:
        current = metrics.get("critical_precision")
        baseline = baseline_metrics.get("critical_precision")
        if current is None or baseline is None:
            warn("critical_precision regression unavailable")
        else:
            drop = baseline - current
            if drop > assertions["max_critical_precision_drop"]:
                fail(f"critical_precision drop {drop:.2f} > {assertions['max_critical_precision_drop']}")

    if "max_unverified_high_ratio_increase" in assertions:
        current = metrics.get("unverified_high_ratio")
        baseline = baseline_metrics.get("unverified_high_ratio")
        if current is None or baseline is None:
            warn("unverified_high_ratio regression unavailable")
        else:
            increase = current - baseline
            if increase > assertions["max_unverified_high_ratio_increase"]:
                fail(
                    f"unverified_high_ratio increase {increase:.2f} > "
                    f"{assertions['max_unverified_high_ratio_increase']}"
                )

    if "max_quality_score_drop" in assertions:
        current = metrics.get("quality_score")
        baseline = baseline_metrics.get("quality_score")
        if current is None or baseline is None:
            warn("quality_score regression unavailable")
        else:
            drop = baseline - current
            if drop > assertions["max_quality_score_drop"]:
                fail(f"quality_score drop {drop:.2f} > {assertions['max_quality_score_drop']}")


def _aggregate_metrics(metrics_list: list[dict[str, Any]]) -> dict[str, Any]:
    if not metrics_list:
        return _collect_metrics({})

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    methods_used = set()
    tool_set = set()
    type_set = set()
    total_findings = 0
    confirmed = 0
    unverified_high = 0
    low_confidence = 0
    high_total = 0
    critical_total = 0
    high_verified = 0
    critical_verified = 0
    quality_scores = []

    for m in metrics_list:
        total_findings += m.get("total_findings", 0) or 0
        confirmed += m.get("confirmed", 0) or 0
        unverified_high += m.get("unverified_high", 0) or 0
        low_confidence += m.get("low_confidence", 0) or 0
        high_total += m.get("high_total", 0) or 0
        critical_total += m.get("critical_total", 0) or 0
        high_verified += m.get("high_verified", 0) or 0
        critical_verified += m.get("critical_verified", 0) or 0

        for sev, count in (m.get("severity_counts") or {}).items():
            if sev in severity_counts:
                severity_counts[sev] += count or 0

        for item in m.get("methods_used") or []:
            methods_used.add(item)
        for item in m.get("tool_set") or []:
            tool_set.add(item)
        for item in m.get("type_set") or []:
            type_set.add(item)

        if m.get("quality_score") is not None:
            quality_scores.append(m["quality_score"])

    high_or_critical_total = high_total + critical_total
    quality_score = (sum(quality_scores) / len(quality_scores)) if quality_scores else None

    return {
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "confirmed": confirmed,
        "unverified_high": unverified_high,
        "low_confidence": low_confidence,
        "quality_score": quality_score,
        "endpoint_coverage": None,
        "endpoints_discovered": None,
        "endpoints_tested": None,
        "har_api_requests": None,
        "har_unique_endpoints": None,
        "methods_used": sorted(methods_used),
        "tool_set": sorted(tool_set),
        "type_set": sorted(type_set),
        "high_total": high_total,
        "critical_total": critical_total,
        "high_verified": high_verified,
        "critical_verified": critical_verified,
        "high_precision": _ratio(high_verified, high_total),
        "critical_precision": _ratio(critical_verified, critical_total),
        "unverified_high_ratio": _ratio(unverified_high, high_or_critical_total),
    }


def _check_benchmark(
    name: str,
    report: dict,
    config: dict,
    strict: bool,
    baseline_metrics: dict[str, Any] | None = None,
) -> tuple[bool, list[str], list[str], dict[str, Any]]:
    assertions = config.get("assertions") or {}
    regression_assertions = config.get("regression_assertions") or {}
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

    _apply_assertions(assertions, metrics, fail, warn, allow_missing_har=allow_missing_har)

    if regression_assertions:
        if baseline_metrics is None:
            warn("regression_assertions configured but baseline metrics not provided")
        else:
            _apply_regression_assertions(regression_assertions, metrics, baseline_metrics, fail, warn)

    return (len(failures) == 0), failures, warnings, metrics


def main() -> int:
    parser = argparse.ArgumentParser(description="Run scan benchmark assertions")
    parser.add_argument("--benchmarks", default="tests/benchmark/benchmarks.json", help="Path to benchmarks JSON")
    parser.add_argument("--results-dir", default=None, help="Base directory to resolve relative result paths")
    parser.add_argument("--result", action="append", default=[], help="Override result path: name=path")
    parser.add_argument("--baseline-results-dir", default=None, help="Base directory to resolve baseline result paths")
    parser.add_argument("--baseline-result", action="append", default=[], help="Override baseline result path: name=path")
    parser.add_argument("--metrics-out", default=None, help="Write JSON metrics summary to file")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as failures")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    bench_path = _resolve_path(args.benchmarks, repo_root)
    config = _load_json(bench_path)
    benchmarks = config.get("benchmarks", [])
    if not benchmarks:
        print("No benchmarks configured.", file=sys.stderr)
        return 2

    try:
        overrides = _parse_overrides(args.result, "--result")
        baseline_overrides = _parse_overrides(args.baseline_result, "--baseline-result")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    results_dir = Path(args.results_dir) if args.results_dir else None
    baseline_results_dir = Path(args.baseline_results_dir) if args.baseline_results_dir else results_dir

    any_fail = False
    summary: dict[str, Any] = {"benchmarks": []}
    metrics_collection: list[dict[str, Any]] = []
    baseline_metrics_collection: list[dict[str, Any]] = []

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
        baseline_metrics = None
        baseline_path = baseline_overrides.get(name) or bench.get("baseline_result_path")
        if baseline_path:
            baseline_resolved = _resolve_path(str(baseline_path), repo_root, baseline_results_dir)
            if not baseline_resolved.exists():
                msg = f"baseline result file not found: {baseline_resolved}"
                if args.strict:
                    print(f"[{name}] FAIL: {msg}")
                    any_fail = True
                else:
                    print(f"[{name}] WARN: {msg}")
            else:
                baseline_report = _load_json(baseline_resolved)
                baseline_metrics = _collect_metrics(baseline_report)
                baseline_metrics_collection.append(baseline_metrics)

        ok, failures, warnings, metrics = _check_benchmark(
            name=name,
            report=report,
            config=bench,
            strict=args.strict,
            baseline_metrics=baseline_metrics,
        )
        metrics_collection.append(metrics)

        status = "PASS" if ok else "FAIL"
        high_plus = metrics["severity_counts"]["high"] + metrics["severity_counts"]["critical"]
        print(
            f"[{name}] {status} | findings={metrics['total_findings']} high+={high_plus} "
            f"quality={metrics['quality_score']} high_precision={_format_ratio(metrics['high_precision'])} "
            f"critical_precision={_format_ratio(metrics['critical_precision'])} "
            f"unverified_high_ratio={_format_ratio(metrics['unverified_high_ratio'])}"
        )
        for w in warnings:
            print(f"[{name}] WARN: {w}")
        for f in failures:
            print(f"[{name}] FAIL: {f}")
        if not ok:
            any_fail = True

        summary["benchmarks"].append(
            {
                "name": name,
                "status": status,
                "metrics": metrics,
                "warnings": warnings,
                "failures": failures,
            }
        )

    global_assertions = config.get("global_assertions") or {}
    global_regression_assertions = config.get("global_regression_assertions") or {}

    if global_assertions or global_regression_assertions:
        global_metrics = _aggregate_metrics(metrics_collection)
        global_failures: list[str] = []
        global_warnings: list[str] = []

        def g_fail(msg: str) -> None:
            global_failures.append(msg)

        def g_warn(msg: str) -> None:
            if args.strict:
                global_failures.append(msg)
            else:
                global_warnings.append(msg)

        if global_assertions:
            _apply_assertions(global_assertions, global_metrics, g_fail, g_warn)

        if global_regression_assertions:
            if len(baseline_metrics_collection) != len(metrics_collection):
                g_warn("global_regression_assertions configured but full baseline metrics are unavailable")
            else:
                global_baseline = _aggregate_metrics(baseline_metrics_collection)
                _apply_regression_assertions(
                    global_regression_assertions,
                    global_metrics,
                    global_baseline,
                    g_fail,
                    g_warn,
                )
                summary["global_baseline_metrics"] = global_baseline

        global_status = "PASS" if not global_failures else "FAIL"
        print(
            f"[global] {global_status} | findings={global_metrics['total_findings']} "
            f"high_precision={_format_ratio(global_metrics['high_precision'])} "
            f"critical_precision={_format_ratio(global_metrics['critical_precision'])} "
            f"unverified_high_ratio={_format_ratio(global_metrics['unverified_high_ratio'])}"
        )
        for w in global_warnings:
            print(f"[global] WARN: {w}")
        for f in global_failures:
            print(f"[global] FAIL: {f}")
        if global_failures:
            any_fail = True

        summary["global"] = {
            "status": global_status,
            "metrics": global_metrics,
            "warnings": global_warnings,
            "failures": global_failures,
        }
    else:
        summary["global"] = None

    if args.metrics_out:
        metrics_out_path = _resolve_path(args.metrics_out, repo_root)
        metrics_out_path.parent.mkdir(parents=True, exist_ok=True)
        metrics_out_path.write_text(json.dumps(summary, indent=2))
        print(f"[summary] wrote metrics to {metrics_out_path}")

    return 1 if any_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
