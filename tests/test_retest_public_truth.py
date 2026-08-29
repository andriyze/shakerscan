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
