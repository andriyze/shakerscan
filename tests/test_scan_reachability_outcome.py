"""Failed preflight must not acquire a success-looking grade during finalization."""
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
from api.scan.finalizer import finalize_scan_report
from api.scan.reachability import apply_reachability_outcome, fail_unreachable_parallel_report
from tests.test_scan_finalizer import _plan, _results, _result_with_observation_count


def _failed_preflight():
    plan = _plan()
    results = _results(plan)
    baseline = plan.actions[0]
    results[baseline.action_id] = replace(_result_with_observation_count(baseline, 1),
        status=CapabilityResultStatus.FAILED, reason_code=CapabilityResultReason.ADAPTER_FAILED,
        result_digest=None)
    observations = {baseline.action_id: ({"kind": "http_observation", "request": {
        "origin": "https://app.example.test", "pinned_address": "192.0.2.10"}, "response": {}},)}
    return plan, results, observations


def test_failed_canonical_preflight_produces_an_ungraded_terminal_error_and_valid_digest():
    plan, results, observations = _failed_preflight()
    report = finalize_scan_report(plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations)
    assert report["error"]
    assert report["scan_metadata"]["status"] == "failed"
    for field in ("score", "grade", "risk_score", "risk_grade"):
        assert report["result"][field] is None
    assert report["result"]["risk_assessment_state"] == "not_examined"
    assert report["canonical_action_execution"]["actions"]
    digest = report.pop("report_digest")
    assert hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode()).hexdigest() == digest


@pytest.mark.parametrize("status", [200, 301, 401, 403, 404, 500, 503])
def test_an_observed_http_response_is_reachable_even_when_not_successful(status):
    plan, results, observations = _failed_preflight()
    observations["baseline.http"][0]["response"]["status"] = status
    report = finalize_scan_report(plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations)
    assert "error" not in report
    assert report["result"]["score"] is not None


@pytest.mark.parametrize("positive", [
    {"kind": "tls_protocol", "status": "success", "protocol": "TLSv1.3"},
    {"kind": "http_fingerprint", "status": 200},
    {"kind": "http_observation", "response": {"status": 401}},
])
def test_later_positive_evidence_prevents_unreachable_classification(positive):
    _, results, observations = _failed_preflight()
    report = {"result": {"score": 75}, "findings": []}
    observations["later"] = [positive]
    apply_reachability_outcome(report, action_results=results, observations=observations)
    assert report["result"]["score"] == 75
    assert report["reachability"]["status"] == "reachable"
    assert "error" not in report


@pytest.mark.parametrize("baseline_status", ["blocked", "cancelled", "skipped"])
def test_policy_or_cancellation_is_not_rewritten_as_unreachable(baseline_status):
    results = {"baseline.http": SimpleNamespace(status=SimpleNamespace(value=baseline_status))}
    report = {"result": {"score": None}}
    apply_reachability_outcome(report, action_results=results, observations={})
    assert "error" not in report


def test_shard_without_baseline_and_prior_verified_finding_are_not_rewritten():
    report = {"findings": [{"tool": "templates.scan", "verified": True}]}
    _, results, _ = _failed_preflight()
    apply_reachability_outcome(report, action_results=results, observations={})
    assert "error" not in report
    report = {}
    apply_reachability_outcome(report, action_results={}, observations={})
    assert report["reachability"]["status"] == "not_examined"
    assert "error" not in report


def test_empty_completed_shards_do_not_hide_failed_backbone_reachability():
    children = [{"reachability": {"status": "unavailable"}}, {"reachability": {"status": "not_examined"}}]
    report = {"result": {"score": 100, "grade": "A*"}}
    assert fail_unreachable_parallel_report(report, children) is True
    assert report["result"]["score"] is None and report["error"]
    for extra in ({"reachability": {"status": "reachable"}}, {}):
        report = {"result": {"score": 80}}
        assert fail_unreachable_parallel_report(report, children + [extra]) is False
        assert "error" not in report
