import pytest

from scripts.score_hunt_investigation import score_run


def inputs():
    record = {"schema_version": "hunt-record/v1", "hunt": {"hunt_id": "h1", "target_id": "t1", "status": "completed"},
              "decision_trace": [{"action_id": "a1", "status": "completed", "result": {
                  "reference_ids": {"finding_ids": ["f1"]},
                  "budget_accounting": {"basis": "exact_settlement", "actual": {"http_requests": 4}, "reserved": {"http_requests": 24}}}}],
              "methodology_trace": [{"event_type": "bound", "skill_id": "selected"},
                  {"event_type": "used", "skill_id": "executed", "body_sha256": "digest", "action_id": "a1"}]}
    oracle = {"hunt_id": "h1", "target_id": "t1", "baseline_fingerprints": ["old"],
              "expected": [{"cwe": "CWE-79", "path": "/search"}],
              "negative_controls": [{"cwe": "CWE-79", "path": "/escaped"}]}
    finding = {"id": "f1", "target_id": "t1", "fingerprint": "new", "is_verified": True,
               "proof_state": "verified", "cwe": "CWE-79", "url": "https://app.test/search?q=redacted"}
    return record, [finding], oracle


def test_scoring_requires_linked_authoritative_proof_and_measured_cost():
    record, findings, oracle = inputs()
    record["decision_trace"][0]["result"]["reference_ids"]["finding_ids"] += ["f2", "f3", "f4"]
    findings += [dict(findings[0], id="f2", fingerprint="claim", is_verified=False),
                 dict(findings[0], id="f3", fingerprint="foreign", target_id="other"),
                 dict(findings[0], id="f4", fingerprint="old"),
                 dict(findings[0], id="unlinked", fingerprint="unrelated")]
    result = score_run(record, findings, oracle)
    assert result["recall"] == 1
    assert result["new_verified_fingerprints"] == 1
    assert result["rejected_linked_findings"] == 2
    assert result["measured_action_budget"] == {"http_requests": 4}
    assert result["action_linked_skill_revisions"] == 1
    assert result["methodology_compliance_proven"] is False


def test_negative_controls_unlisted_discoveries_and_incomplete_cost_are_distinct():
    record, findings, oracle = inputs()
    record["decision_trace"][0]["result"]["reference_ids"]["finding_ids"] += ["f2", "f3"]
    findings += [dict(findings[0], id="f2", fingerprint="false", url="https://app.test/escaped"),
                 dict(findings[0], id="f3", fingerprint="unknown", url="https://app.test/unknown")]
    record["decision_trace"][0]["result"]["budget_accounting"]["basis"] = "legacy_reported_charge"
    result = score_run(record, findings, oracle)
    assert result["false_promotion_classes"] == 1
    assert result["unexpected_classes_requiring_review"] == [["CWE-79", "/unknown"]]
    assert result["complete_exact_accounting"] is False
    assert result["measured_action_budget"] == {}


def test_omitting_linked_findings_cannot_hide_negative_control_failures():
    record, findings, oracle = inputs()
    record["decision_trace"][0]["result"]["reference_ids"]["finding_ids"].append("omitted")
    with pytest.raises(ValueError, match="omits"):
        score_run(record, findings, oracle)


@pytest.mark.parametrize("field,value", [("hunt_id", "wrong"), ("target_id", "wrong"), ("status", "active"), ("status", "awaiting_planner")])
def test_scope_and_terminal_status_are_required(field, value):
    record, findings, oracle = inputs()
    record["hunt"][field] = value
    with pytest.raises(ValueError): score_run(record, findings, oracle)
