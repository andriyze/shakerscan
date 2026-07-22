"""Report-block reconciliation tests (docs proposed-next-steps §2).

Every report block that counts the canonical finding set must agree after a
parent/shard merge. These pin the shared `compute_quality_metrics` helper and the
`check_report_invariants` reconciliation checker that both the single-scan and the
parallel-merge paths now share.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from findings import (  # noqa: E402
    check_report_invariants,
    compute_quality_metrics,
    summarize_verification,
)


def _mk(sev, **kw):
    f = {"severity": sev, "title": kw.get("title", f"{sev} finding")}
    f.update(kw)
    return f


def test_quality_metrics_total_matches_findings():
    findings = [_mk("critical"), _mk("high"), _mk("high"), _mk("medium"), _mk("low")]
    qm = compute_quality_metrics(findings)
    assert qm["total_findings"] == 5
    assert qm["severity_distribution"] == {
        "critical": 1, "high": 2, "medium": 1, "low": 1, "info": 0
    }
    assert sum(qm["severity_distribution"].values()) == 5


def test_quality_metrics_tolerates_none_severity():
    # A merged finding with severity=None must not crash the block.
    findings = [_mk(None), _mk("critical")]
    qm = compute_quality_metrics(findings)
    assert qm["total_findings"] == 2
    # None coerces to "info".
    assert qm["severity_distribution"]["info"] == 1
    assert qm["severity_distribution"]["critical"] == 1


def test_invariants_pass_for_consistent_report():
    findings = [_mk("critical", verified=True), _mk("high"), _mk("medium")]
    report = {
        "findings": findings,
        "quality_metrics": compute_quality_metrics(findings),
        "verification_summary": summarize_verification(findings),
        "triage": {"confirmed": {"count": 1}, "suspected_high": {"count": 1}},
    }
    assert check_report_invariants(report) == []


def test_invariants_catch_stale_quality_block_after_merge():
    # Simulate the pre-fix bug: findings[] is the union (5) but quality_metrics
    # still reflects a single shard (2). The checker must flag it.
    union = [_mk("critical"), _mk("high"), _mk("high"), _mk("medium"), _mk("low")]
    stale_qm = compute_quality_metrics([_mk("critical"), _mk("high")])  # only 2
    report = {
        "findings": union,
        "quality_metrics": stale_qm,
        "verification_summary": summarize_verification(union),
    }
    violations = check_report_invariants(report)
    assert any("total_findings" in v for v in violations)
    assert any("severity_distribution" in v for v in violations)


def test_invariants_catch_stale_verification_total():
    findings = [_mk("high"), _mk("low")]
    report = {
        "findings": findings,
        "quality_metrics": compute_quality_metrics(findings),
        "verification_summary": {"total": 7},  # stale
    }
    violations = check_report_invariants(report)
    assert any("verification_summary.total" in v for v in violations)


def test_invariants_flag_impossible_triage_bucket():
    findings = [_mk("high")]
    report = {
        "findings": findings,
        "triage": {"confirmed": {"count": 9}},  # more than total
    }
    violations = check_report_invariants(report)
    assert any("triage.confirmed" in v for v in violations)


def test_degraded_report_without_findings_list_is_exempt():
    # synthesize_degraded_result paths may omit a findings list; don't false-positive.
    assert check_report_invariants({"quality_metrics": {"total_findings": 3}}) == []


# --- §1 harness extensions: proof-state + active-execution ------------------

def test_invariants_catch_verified_count_mismatch():
    findings = [_mk("critical", verified=True), _mk("high")]
    report = {
        "findings": findings,
        "verification_summary": {"total": 2, "verified": 5},  # impossible
    }
    violations = check_report_invariants(report)
    assert any("verification_summary.verified" in v for v in violations)


def test_invariants_catch_finding_both_verified_and_suspected():
    findings = [_mk("high", verified=True, suspected=True)]
    report = {"findings": findings}
    violations = check_report_invariants(report)
    assert any("both verified and suspected" in v for v in violations)


def test_invariants_catch_ai_only_verified():
    # §8: a verified finding resting only on AI support is forbidden.
    findings = [_mk("high", verified=True, proof_state="likely_vulnerable",
                    precision_policy={"ai_supported_likely": True})]
    report = {"findings": findings, "verification_summary": summarize_verification(findings)}
    violations = check_report_invariants(report)
    assert any("AI never promotes" in v for v in violations)


def test_invariants_catch_active_failed_but_grade_reliable():
    report = {
        "findings": [],
        "scan_metadata": {"active_execution_failed": True},
        "result": {"grade_reliable": True},
    }
    violations = check_report_invariants(report)
    assert any("active_execution_failed" in v for v in violations)


def test_invariants_catch_incomplete_grade_marked_reliable():
    report = {"findings": [], "result": {"grade": "C*", "grade_reliable": True}}
    violations = check_report_invariants(report)
    assert any("incomplete but grade_reliable" in v for v in violations)


def test_consistent_active_failed_report_passes():
    # The honest degraded shape (F4) must NOT trip the harness.
    report = {
        "findings": [],
        "scan_metadata": {"active_execution_failed": True},
        "result": {"grade": "C*", "grade_reliable": False},
    }
    assert check_report_invariants(report) == []
