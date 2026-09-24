"""Terminal reachability from settled canonical observations, without sending traffic."""
from __future__ import annotations

from typing import Any, Mapping, Sequence


_SOURCE = "canonical_capability_receipts"


def _positive_evidence(report, observations) -> bool:
    # A failed baseline may coexist with independently verified target traffic.
    if any(item.get("verified") is True and item.get("tool") not in {"tls.inspect", "dns.inspect"}
           for item in report.get("findings", ()) if isinstance(item, Mapping)):
        return True
    for rows in observations.values():
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            kind = row.get("kind")
            response = row.get("response")
            status = (response.get("status") if isinstance(response, Mapping) else None) if kind == "http_observation" else row.get("status") if kind == "http_fingerprint" else None
            if type(status) is int and 100 <= status <= 599:
                return True
            if kind == "tls_protocol" and row.get("status") == "success":
                return True
    return False


def _fail_unassessable(report: dict[str, Any]) -> None:
    report["error"] = "No HTTP or TLS reachability was established during canonical preflight."
    # An adapter failure is not proof that the host is permanently offline.
    report["reachability"] = {"status": "unavailable", "source": _SOURCE}
    report.setdefault("result", {}).update({
        "score": None, "grade": None, "risk_score": None, "risk_grade": None,
        "grade_reliable": False, "risk_assessment_state": "not_examined",
        "application_observed": False, "assurance_score": 0,
        "summary": "Target reachability was not established; no grade is available.",
    })
    report["result"].pop("original_grade", None)
    metadata = report.setdefault("scan_metadata", {})
    metadata.update({"status": "failed", "grade_reliable": False, "partial": False})
    metadata["grade_reliability_reasons"] = sorted(set(metadata.get("grade_reliability_reasons") or ()) | {"target_unreachable"})
    coverage = report.setdefault("coverage", {})
    coverage["status"] = "failed"
    coverage["reasons"] = sorted(set(coverage.get("reasons") or ()) | {"target_unreachable"})
    reliability = coverage.setdefault("grade_reliability", {})
    reliability["reliable"] = False
    reliability["reasons"] = sorted(set(reliability.get("reasons") or ()) | {"target_unreachable"})


def apply_reachability_outcome(
    report: dict[str, Any], *, action_results: Mapping[str, Any],
    observations: Mapping[str, Sequence[Mapping[str, Any]]],
) -> None:
    """Do not grade a failed preflight with no positive HTTP/TLS evidence.

    Coverage failure alone is not scan failure. 401/404/500 responses still
    establish reachability. Policy skips and cancellation retain their meaning.
    The projection is deterministic and runs before the final report is hashed.
    """
    if _positive_evidence(report, observations):
        report["reachability"] = {"status": "reachable", "source": _SOURCE}
        return
    baseline = action_results.get("baseline.http")
    status = getattr(getattr(baseline, "status", None), "value", None)
    report["reachability"] = {"status": "unknown" if baseline else "not_examined", "source": _SOURCE}
    if status not in {"failed", "timed_out", "partial"}:
        return
    if any(getattr(getattr(result, "status", None), "value", None) == "cancelled"
           for result in action_results.values()):
        return
    _fail_unassessable(report)


def fail_unreachable_parallel_report(report: dict[str, Any], children: Sequence[Mapping[str, Any]]) -> bool:
    """Empty successful shards cannot turn a failed backbone into a clean parent.

    Only current explicit reachability projections participate. A legacy or
    unknown child is not assumed unreachable; any positive child preserves the
    partial assessment and its findings.
    """
    states = [str((child.get("reachability") or {}).get("status") or "unknown") for child in children]
    if not states or "unavailable" not in states or any(state not in {"unavailable", "not_examined"} for state in states):
        return False
    _fail_unassessable(report)
    return True
