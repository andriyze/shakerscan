"""Retest API keeps deterministic proof separate from AI assessment."""

from api.retest_routes.router import public_retest_row


def test_ai_assessment_cannot_masquerade_as_deterministic_proof():
    row = public_retest_row({
        "proof": '{"proven": false, "confidence": 0.0}',
        "artifacts": '{"steps_tried": ["boolean_diff"]}',
        "replay_commands": '["curl https://example.test"]',
        "verification_mode": "ai_driven",
        "result_status": "inconclusive",
        "verdict": "likely_vulnerable",
        "ai_reasoning": "The prose claims verification.",
    })

    assert row["proof"] == {"proven": False, "confidence": 0.0}
    assert row["artifacts"]["steps_tried"] == ["boolean_diff"]
    assert row["replay_commands"] == ["curl https://example.test"]
    assert row["deterministic_proof_state"] == "not_proven"
    assert row["verdict_basis"] == "ai_assessment"


def test_satisfied_replay_is_labeled_deterministic_proof():
    row = public_retest_row({
        "proof": {"proven": True},
        "verification_mode": "deterministic",
        "result_status": "still_vulnerable",
        "verdict": "exploited",
    })

    assert row["deterministic_proof_state"] == "proven"
    assert row["verdict_basis"] == "deterministic_proof"


def test_retest_exposes_exact_tested_scope_without_conflating_base_target():
    row = public_retest_row({
        "target_url": "http://host.docker.internal:3001",
        "original_url": "/rest/products/search",
        "artifacts": {
            "attempted_url": "/rest/products/search?q=test",
            "ai_step_results": [
                {"step": {"url": "http://host.docker.internal:3001/"}, "result": {"status": 200}},
                {"step": {"url": "/rest/products/search?q=probe"}, "result": {"status": 200}},
            ],
        },
        "ai_plan": {
            "steps": [
                {"url": "http://host.docker.internal:3001/"},
                {"url": "/rest/products/search?q=probe"},
            ]
        },
    })

    assert row["primary_tested_endpoint"] == "http://host.docker.internal:3001/rest/products/search?q=test"
    assert row["tested_endpoints"] == [
        "http://host.docker.internal:3001/rest/products/search?q=test",
        "http://host.docker.internal:3001/",
        "http://host.docker.internal:3001/rest/products/search?q=probe",
    ]
    assert row["tested_scope"] == "multiple_endpoints"


def test_retest_with_no_executed_steps_does_not_claim_tested_scope():
    row = public_retest_row({
        "target_url": "https://example.test",
        "original_url": "/planned-only",
        "artifacts": {"ai_step_results": []},
        "ai_plan": {"steps": [{"url": "/never-executed"}]},
    })

    assert row["primary_tested_endpoint"] is None
    assert row["tested_endpoints"] == []
    assert row["tested_scope"] is None
