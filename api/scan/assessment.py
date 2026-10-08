"""Assessment visibility across canonical finalization, parent merge and list reads.

Execution success and transport posture are not application examination. These
pure projections never follow redirects, extend scope, or rescore old evidence.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from .reachability import fail_unreachable_parallel_report
from .redirect_evidence import http_origin


SCAN_LIST_ASSESSMENT_COLUMNS = """
    s.result->'result'->>'risk_assessment_state' AS risk_assessment_state,
    s.result->'result'->'application_observed' AS application_observed
"""
_SCORE_FIELDS = ("score", "grade", "risk_score", "risk_grade")


def application_unexamined(summary: Mapping[str, Any]) -> bool:
    return (summary.get("risk_assessment_state") == "not_examined"
            or summary.get("application_observed") is False)


def withhold_unexamined_grade(report: dict[str, Any]) -> bool:
    """Withhold an application grade before hashing/persisting a new report.

    Findings, HTTP/TLS/DNS sections, and independent assurance metrics remain.
    This does not change job status: a reachable redirect is not an offline host.
    """
    summary = report.get("result")
    if not isinstance(summary, dict) or not application_unexamined(summary):
        return False
    if (report.get("reachability") or {}).get("status") == "unavailable":
        # Failed preflight already has a stronger terminal reason and no grade.
        return True
    summary.update({name: None for name in _SCORE_FIELDS})
    summary.update({"risk_assessment_state": "not_examined", "application_observed": False,
                    "grade_reliable": False,
                    "summary": "Application not examined; retained transport/header observations are not an application assessment."})
    summary.pop("original_grade", None)
    # Examination strength measures how much of the application was examined, and none of it
    # was: a not-examined run kept the 64/100 its planned work earned, beside "Not examined".
    # A failed reachability preflight already settles at zero for the same reason.
    summary.update({
        "assurance_score": 0, "assurance_band": "none",
        "assurance_gaps": sorted(
            set(summary.get("assurance_gaps") or ()) | {"application_not_observed"}
        ),
    })
    coverage = report.setdefault("coverage", {})
    reliability = coverage.setdefault("grade_reliability", {})
    reliability["reliable"] = False
    metadata = report.setdefault("scan_metadata", {})
    metadata["grade_reliable"] = False
    for block, field in ((coverage, "reasons"), (reliability, "reasons"),
                         (metadata, "grade_reliability_reasons")):
        block[field] = sorted(set(block.get(field) or ()) | {"application_not_observed"})
    return True


def unexamined_coverage_reason(report: Mapping[str, Any]) -> str:
    """One sentence naming why the bound origin's application was not examined."""
    coverage = report.get("coverage") if isinstance(report.get("coverage"), Mapping) else {}
    if "application_surface_not_examined" in (coverage.get("reasons") or ()):
        return ("the selected families only probe fixed, well-known locations; none examined "
                "the application itself")
    http = report.get("http") if isinstance(report.get("http"), Mapping) else {}
    moved = http.get("application_origin_redirect") or http.get("redirect_origin")
    if moved and http_origin(moved) != http_origin(report.get("target")):
        return f"the target redirects to {moved}, outside this scan's origin"
    status = http.get("status")
    if type(status) is int:
        return f"the target answered HTTP {status} without an application response in scope"
    return "no in-scope application response was observed"


def mark_unexamined_coverage(report: dict[str, Any]) -> bool:
    """An unexamined application cannot leave the scan claiming complete coverage.

    The grade was already withheld, but coverage still read ``complete`` and the scan
    ``completed`` with no findings -- indistinguishable from a clean result. A scan of
    ``http://host`` that only redirects to ``https://host`` examined nothing past the
    redirect: its coverage is incomplete, and the reason says where the application is.
    """
    summary = report.get("result")
    if not isinstance(summary, Mapping) or not application_unexamined(summary):
        return False
    if (report.get("reachability") or {}).get("status") == "unavailable":
        # Failed preflight already ended the coverage as failed with target_unreachable.
        return True
    coverage = report.setdefault("coverage", {})
    reason = unexamined_coverage_reason(report)
    coverage["not_examined_reason"] = reason
    coverage["reasons"] = sorted(set(coverage.get("reasons") or ()) | {"application_not_observed"})
    metadata = report.setdefault("scan_metadata", {})
    metadata["not_examined_reason"] = reason
    if coverage.get("status") == "complete":
        coverage["status"] = "partial"
        if metadata.get("status") == "complete":
            metadata["status"] = "partial"
        metadata["partial"] = True
    return True


def finalize_parallel_assessment(
    report: dict[str, Any], children: Sequence[Mapping[str, Any]],
) -> bool:
    """Reconcile same-target evidence after score union; return preflight failure.

    A completed empty shard cannot rescue an unexamined backbone. Conversely, a
    child that actually observed this bound origin must not lose that evidence
    merely because the backbone stopped at a redirect. Legacy/other-origin rows
    never manufacture positive application evidence.
    """
    failed = fail_unreachable_parallel_report(report, children)
    target = http_origin(report.get("target"))
    summaries = [child.get("result") for child in children
                 if target is not None and http_origin(child.get("target")) == target
                 and child.get("schema_version") == "canonical-scan-report/v2"
                 and isinstance(child.get("result"), Mapping)]
    summary = report.setdefault("result", {})
    if not failed and any(item.get("application_observed") is True
                          and item.get("risk_assessment_state") == "observed" for item in summaries):
        summary.update({"application_observed": True, "risk_assessment_state": "observed"})
        # Other incomplete-coverage qualifiers remain conservative. No claim of
        # a reliable/full assessment follows from one observed application slice.
    elif any(application_unexamined(item) for item in summaries):
        summary.update({"application_observed": False, "risk_assessment_state": "not_examined"})
    withhold_unexamined_grade(report)
    mark_unexamined_coverage(report)
    return failed


def project_scan_assessment_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """Hide an explicitly unexamined scan's list grade without rewriting history."""
    projected = dict(row)
    # asyncpg's default JSON codec returns JSON text for the extracted boolean.
    observed = projected.get("application_observed")
    if observed in ("true", "false", "null"):
        projected["application_observed"] = {"true": True, "false": False, "null": None}[observed]
    if application_unexamined(projected) and not str(projected.get("run_kind") or "").startswith("device_"):
        projected["score"] = projected["grade"] = None
    return projected
