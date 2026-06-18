"""DAST benchmark summary and miss-analysis helpers.

This module is intentionally report-oriented. It does not contain lab exploit
solutions; benchmark expectations live in fixtures/configs and are compared to
generic scanner telemetry and findings.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from typing import Any


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
FAMILY_BY_TOOL = {
    "smart_sqli": "sqli",
    "custom_sqli": "sqli",
    "sqlmap": "sqli",
    "nosql_injection": "sqli",
    "smart_xss": "xss",
    "custom_xss": "xss",
    "dom_xss": "xss",
    "hash_route_dom_xss": "xss",
    "stored_xss": "xss",
    "smart_bola": "bola",
    "bola_idor": "bola",
    "bola_check": "bola",
    "smart_auth": "authz",
    "mass_assignment": "authz",
    "api_security": "api_security",
    "csp_evaluator": "headers",
    "http_headers": "headers",
}


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _family_for_finding(finding: dict[str, Any]) -> str:
    evidence = _as_dict(finding.get("evidence"))
    explicit = evidence.get("family") or evidence.get("probe_family") or finding.get("family")
    if explicit:
        return str(explicit).strip().lower()
    tool = str(finding.get("tool") or "").strip().lower()
    return FAMILY_BY_TOOL.get(tool, tool or "unknown")


def _severity_at_least(value: Any, minimum: Any) -> bool:
    return SEVERITY_RANK.get(str(value or "info").lower(), -1) >= SEVERITY_RANK.get(str(minimum or "info").lower(), 0)


def _proof_type(finding: dict[str, Any]) -> str:
    evidence = _as_dict(finding.get("evidence"))
    for key in ("proof_type", "evidence_type", "validation", "verification"):
        value = evidence.get(key) or finding.get(key)
        if value:
            if isinstance(value, dict):
                return str(value.get("type") or value.get("verdict") or "structured")
            return str(value)
    if finding.get("verified") is True:
        return "verified"
    return "missing"


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        if re.search(r"(bearer|token|secret|password|cookie|authorization)", value, re.I):
            return "[redacted]"
        return value
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if re.search(r"(token|secret|password|cookie|authorization|api[_-]?key)", str(key), re.I):
                out[key] = "[redacted]"
            else:
                out[key] = _redact(item)
        return out
    return value


def _param_location_from_custom_endpoint(custom_endpoint: Any) -> str:
    text = str(custom_endpoint or "")
    lowered = text.lower()
    if " multipart:" in lowered:
        return "multipart"
    if " form:" in lowered:
        return "form"
    if " json:" in lowered:
        return "json"
    if " header:" in lowered:
        return "header"
    if "?" in text:
        return "query"
    if re.search(r"/\{[^/]+}", text) or re.search(r"/[0-9a-fA-F-]{3,}(?:/|$)", text):
        return "path"
    return "none"


def _collect_discovery_sources(report: dict[str, Any]) -> dict[str, int]:
    active = _as_dict(report.get("active_checks"))
    sources = Counter()
    for key, value in _as_dict(active.get("active_endpoints_discovered_by_source")).items():
        try:
            sources[str(key)] += int(value or 0)
        except Exception:
            pass
    discovery = _as_dict(report.get("discovery"))
    smart = _as_dict(discovery.get("smart_discovery"))
    if smart:
        stats = _as_dict(smart.get("stats"))
        for key in ("crawl", "js", "browser", "openapi", "har", "forms"):
            raw = stats.get(key) or stats.get(f"{key}_endpoints") or stats.get(f"{key}_urls")
            if raw is not None:
                try:
                    sources[key] += int(raw or 0)
                except Exception:
                    pass
    har_stats = _as_dict(_as_dict(discovery.get("har_discovery")).get("stats"))
    if har_stats.get("unique_endpoints") is not None:
        sources["har"] += int(har_stats.get("unique_endpoints") or 0)
    return dict(sorted(sources.items()))


def _collect_attempts(report: dict[str, Any]) -> tuple[dict[str, Any], dict[str, int]]:
    active = _as_dict(report.get("active_checks"))
    attempts = _as_list(active.get("endpoint_attempts"))
    by_auth_family: Counter[tuple[str, str, str]] = Counter()
    params_by_location: Counter[str] = Counter()
    proof_by_family: Counter[tuple[str, str]] = Counter()
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        family = str(attempt.get("family") or "all").lower()
        auth_state = str(attempt.get("auth_state") or attempt.get("principal_label") or "anonymous").lower()
        status = str(attempt.get("status") or "unknown").lower()
        by_auth_family[(auth_state, family, status)] += 1
        loc = str(attempt.get("param_location") or _param_location_from_custom_endpoint(attempt.get("custom_endpoint")))
        try:
            count = int(attempt.get("attempted_params_count") or attempt.get("param_count") or 0)
        except Exception:
            count = 0
        params_by_location[loc] += max(0, count)
        if attempt.get("proof_type"):
            proof_by_family[(family, str(attempt.get("proof_type")))] += 1

    rollup = _as_dict(report.get("smart_coverage"))
    endpoints = _as_dict(rollup.get("endpoints"))
    if not attempts and endpoints:
        for family, values in _as_dict(endpoints.get("by_check_family")).items():
            attempted = int(_as_dict(values).get("attempted_endpoints") or 0)
            if attempted:
                by_auth_family[("unknown", str(family), "attempted")] += attempted

    return (
        {
            "total": sum(by_auth_family.values()),
            "by_auth_state_family_status": {
                f"{auth}|{family}|{status}": count
                for (auth, family, status), count in sorted(by_auth_family.items())
            },
            "proof_by_family": {
                f"{family}|{proof}": count for (family, proof), count in sorted(proof_by_family.items())
            },
        },
        dict(sorted(params_by_location.items())),
    )


def _collect_findings(report: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    by_family_severity: Counter[tuple[str, str]] = Counter()
    confirmed_by_family_severity: Counter[tuple[str, str]] = Counter()
    proof_gaps: list[dict[str, Any]] = []
    severity_gaps: list[dict[str, Any]] = []
    findings = [f for f in _as_list(report.get("findings")) if isinstance(f, dict)]
    for finding in findings:
        family = _family_for_finding(finding)
        severity = str(finding.get("severity") or "info").lower()
        by_family_severity[(family, severity)] += 1
        if finding.get("verified") is True or str(finding.get("confidence_tier") or "").lower() in {"high", "proven"}:
            confirmed_by_family_severity[(family, severity)] += 1
        proof = _proof_type(finding)
        if severity in {"high", "critical"} and proof == "missing":
            proof_gaps.append({
                "family": family,
                "title": finding.get("title"),
                "severity": severity,
                "reason": "high_or_critical_without_deterministic_proof",
            })
        evidence = _as_dict(finding.get("evidence"))
        if evidence.get("severity_rationale") and severity not in {"high", "critical"}:
            severity_gaps.append({
                "family": family,
                "title": finding.get("title"),
                "severity": severity,
                "severity_rationale": _redact(evidence.get("severity_rationale")),
            })
    return (
        {
            "total": len(findings),
            "by_family_severity": {f"{family}|{sev}": n for (family, sev), n in sorted(by_family_severity.items())},
            "confirmed_by_family_severity": {
                f"{family}|{sev}": n for (family, sev), n in sorted(confirmed_by_family_severity.items())
            },
        },
        proof_gaps + severity_gaps,
    )


def build_benchmark_summary(
    report: dict[str, Any],
    *,
    profile: str = "generic",
    base_url: str | None = None,
    expected: dict[str, Any] | None = None,
    run_mode: str = "baseline",
) -> dict[str, Any]:
    expected = expected or {}
    discovery_sources = _collect_discovery_sources(report)
    attempts, params_by_location = _collect_attempts(report)
    findings, proof_or_severity_gaps = _collect_findings(report)
    misses: list[dict[str, Any]] = []

    expected_families = expected.get("families") if isinstance(expected.get("families"), dict) else {}
    confirmed = findings["confirmed_by_family_severity"]
    for family, spec in expected_families.items():
        min_severity = str(_as_dict(spec).get("min_severity") or "high").lower()
        min_confirmed = int(_as_dict(spec).get("min_confirmed") or 1)
        found = 0
        for key, count in confirmed.items():
            fam, sev = key.split("|", 1)
            if fam == family and _severity_at_least(sev, min_severity):
                found += int(count)
        if found < min_confirmed:
            attempted = sum(
                count
                for key, count in attempts["by_auth_state_family_status"].items()
                if f"|{family}|" in key or (family == "authz" and "|auth|" in key)
            )
            misses.append({
                "family": family,
                "expected_min_confirmed": min_confirmed,
                "expected_min_severity": min_severity,
                "confirmed": found,
                "attempted": attempted,
                "likely_root_cause": "family_not_attempted" if attempted == 0 else "no_confirmed_finding_or_proof_gap",
            })

    required_auth_states = [str(x).lower() for x in _as_list(expected.get("auth_states"))]
    for auth_state in required_auth_states:
        if not any(key.startswith(f"{auth_state}|") for key in attempts["by_auth_state_family_status"]):
            misses.append({
                "family": "auth",
                "auth_state": auth_state,
                "likely_root_cause": "expected_auth_state_untested",
            })

    return {
        "profile": profile,
        "base_url": base_url,
        "run_mode": run_mode,
        "discovery": {"endpoints_by_source": discovery_sources},
        "attempts": attempts,
        "parameters": {"attempted_by_location": params_by_location},
        "findings": findings,
        "misses": misses,
        "proof_or_severity_gaps": proof_or_severity_gaps,
    }


def compare_benchmark_summaries(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    def confirmed_high(summary: dict[str, Any]) -> int:
        total = 0
        for key, count in _as_dict(_as_dict(summary.get("findings")).get("confirmed_by_family_severity")).items():
            _, sev = str(key).split("|", 1)
            if sev in {"high", "critical"}:
                total += int(count)
        return total

    return {
        "baseline_confirmed_high_or_critical": confirmed_high(baseline),
        "candidate_confirmed_high_or_critical": confirmed_high(candidate),
        "confirmed_high_or_critical_delta": confirmed_high(candidate) - confirmed_high(baseline),
        "baseline_misses": len(_as_list(baseline.get("misses"))),
        "candidate_misses": len(_as_list(candidate.get("misses"))),
        "miss_delta": len(_as_list(candidate.get("misses"))) - len(_as_list(baseline.get("misses"))),
    }
