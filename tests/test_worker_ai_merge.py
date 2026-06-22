"""
Unit tests for merging AI retest verdicts into deterministic outcomes.
"""

import os
import sys
import types
from datetime import datetime, timedelta


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace())
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

from worker import (  # noqa: E402
    _enforce_verdict_invariants,
    _has_partial_deterministic_evidence,
    _merge_ai_result_into_retest_result,
    _is_ai_circuit_open,
    _is_retryable_ai_error,
    _result_status_for_verdict,
    _scan_time_verification_fields,
    _should_open_ai_circuit,
    _slot_wait_backoff_seconds,
    _slot_wait_state,
    _stale_retest_should_requeue,
    classify_retest_outcome,
    RETEST_AI_CIRCUIT_ERROR_THRESHOLD,
    RETEST_STALE_REQUEUE_LIMIT,
)


def test_scan_time_verification_fields_promote_fresh_verified_finding():
    status, verdict, confidence = _scan_time_verification_fields(
        {"proof_of_exploitation": True, "confidence": 0.95, "last_verification_verdict": "false_positive"}
    )

    assert status == "still_vulnerable"
    assert verdict == "exploited"
    assert confidence == 0.95


def test_scan_time_verification_fields_accept_nested_validation_proof():
    status, verdict, confidence = _scan_time_verification_fields(
        {"validation": {"verified": True, "evidence_level": "confirmed_exploit", "confidence": "0.88"}}
    )

    assert status == "still_vulnerable"
    assert verdict == "exploited"
    assert confidence == 0.88


def test_scan_time_verification_fields_rejects_generic_verified_flags():
    assert _scan_time_verification_fields(
        {"verified": True, "confidence": 0.95}
    ) == (None, None, None)
    assert _scan_time_verification_fields(
        {"validation": {"verified": True, "confidence": "0.88"}}
    ) == (None, None, None)


def test_scan_time_verification_fields_rejects_failed_browser_proof():
    assert _scan_time_verification_fields(
        {"verified": True, "browser_proof": {"proven": False, "confidence": 0.2}}
    ) == (None, None, None)


def test_scan_time_verification_fields_accepts_proven_browser_proof():
    status, verdict, confidence = _scan_time_verification_fields(
        {"browser_proof": {"proven": True, "confidence": 0.99}}
    )

    assert status == "still_vulnerable"
    assert verdict == "exploited"
    assert confidence == 0.99


def test_scan_time_verification_fields_ignores_stale_false_positive_without_fresh_proof():
    assert _scan_time_verification_fields(
        {"verified": False, "last_verification_verdict": "false_positive", "confidence": 0.9}
    ) == (None, None, None)


def test_result_status_mapping_for_supported_verdicts():
    assert _result_status_for_verdict("exploited") == "still_vulnerable"
    assert _result_status_for_verdict("likely_fixed") == "likely_fixed"
    assert _result_status_for_verdict("false_positive") == "inconclusive"
    assert _result_status_for_verdict("blocked_by_security") == "inconclusive"
    assert _result_status_for_verdict("out_of_scope_internal") == "inconclusive"
    assert _result_status_for_verdict("inconclusive") == "inconclusive"
    assert _result_status_for_verdict("unknown") == "error"


def test_ai_likely_fixed_upgrades_error_to_completed():
    result = {
        "status": "failed",
        "result_status": "error",
        "verdict": "error",
        "verification_mode": "deterministic",
    }
    ai_result = {"verdict": "likely_fixed", "confidence": 0.81, "reasoning": "No repro"}
    merged = _merge_ai_result_into_retest_result(result, ai_result)

    assert merged["status"] == "completed"
    assert merged["verification_mode"] == "ai_driven"
    assert merged["verdict"] == "likely_fixed"
    assert merged["result_status"] == "likely_fixed"
    assert merged["confidence"] == 0.81


def test_ai_inconclusive_upgrades_error_to_completed_inconclusive():
    result = {
        "status": "failed",
        "result_status": "error",
        "verdict": "error",
        "verification_mode": "deterministic",
    }
    ai_result = {"verdict": "inconclusive", "confidence": 0.45, "reasoning": "Needs manual verification"}
    merged = _merge_ai_result_into_retest_result(result, ai_result)

    assert merged["status"] == "completed"
    assert merged["verification_mode"] == "ai_driven"
    assert merged["verdict"] == "inconclusive"
    assert merged["result_status"] == "inconclusive"


def test_ai_exploited_does_not_override_deterministic_verdict():
    # Verification Depth C: AI never overrides a deterministic conclusion, and an AI
    # "exploited" verdict is NOT proof — a deterministic 'likely_fixed' survives.
    result = {
        "status": "completed",
        "result_status": "likely_fixed",
        "verdict": "likely_fixed",
        "verification_mode": "deterministic",
    }
    ai_result = {"verdict": "exploited", "confidence": 0.92, "reasoning": "Exploit replay succeeded"}
    merged = _merge_ai_result_into_retest_result(result, ai_result)

    assert merged["verdict"] == "likely_fixed"           # deterministic conclusion wins
    assert merged["verification_mode"] == "deterministic"


def test_ai_exploited_on_inconclusive_becomes_likely_vulnerable_not_verified():
    # Verification Depth C: AI fills an inconclusive deterministic outcome but can only
    # raise it to 'likely_vulnerable' (suspected) — never 'exploited' (verified).
    result = {
        "status": "running",
        "result_status": "inconclusive",
        "verdict": "inconclusive",
        "verification_mode": "deterministic",
    }
    ai_result = {"verdict": "exploited", "confidence": 0.92, "reasoning": "AI thinks exploited"}
    merged = _merge_ai_result_into_retest_result(result, ai_result)

    assert merged["verdict"] == "likely_vulnerable"      # NOT 'exploited'
    assert merged["verdict"] != "exploited"
    assert merged["result_status"] == "inconclusive"     # not 'still_vulnerable' (verified)
    assert merged["verification_mode"] == "ai_driven"


def test_ai_false_positive_does_not_override_existing_non_error_verdict():
    result = {
        "status": "completed",
        "result_status": "likely_fixed",
        "verdict": "likely_fixed",
        "verification_mode": "deterministic",
    }
    ai_result = {"verdict": "false_positive", "confidence": 0.74, "reasoning": "Not exploitable"}
    merged = _merge_ai_result_into_retest_result(result, ai_result)

    assert merged["status"] == "completed"
    assert merged["verification_mode"] == "deterministic"
    assert merged["verdict"] == "likely_fixed"
    assert merged["result_status"] == "likely_fixed"


# ---------------------------------------------------------------------------
# Verdict semantics: false_positive must mean "objectively invalid", never
# "we failed to replay" or "AI timed out".
# ---------------------------------------------------------------------------

def test_classify_low_confidence_no_proof_is_inconclusive_not_false_positive():
    result_status, verdict, _reason = classify_retest_outcome(
        proof={"evidence_type": ""},
        proven=False,
        confidence=0.0,
        inputs={"target_url": "https://example.com/x"},
    )
    assert (result_status, verdict) == ("inconclusive", "inconclusive")


def test_classify_missing_replay_context_is_inconclusive_not_false_positive():
    _result_status, verdict, _reason = classify_retest_outcome(
        proof={"evidence_type": "no_url"},
        proven=False,
        confidence=None,
        inputs={"target_url": "https://example.com/x"},
    )
    assert verdict == "inconclusive"


def test_classify_catch_all_is_inconclusive():
    _result_status, verdict, _reason = classify_retest_outcome(
        proof={"evidence_type": "catch_all_server"},
        proven=False,
        confidence=None,
        inputs={"target_url": "https://example.com/x"},
    )
    assert verdict == "inconclusive"


def test_ai_timeout_over_low_conf_no_proof_stays_inconclusive():
    # Deterministic produced an inconclusive (post-fix) verdict; AI then times
    # out. The final verdict must be inconclusive, never false_positive.
    result = {
        "status": "completed",
        "result_status": "inconclusive",
        "verdict": "inconclusive",
        "confidence": 0.0,
        "verification_mode": "deterministic",
    }
    ai_result = {
        "verdict": "inconclusive",
        "confidence": None,
        "reasoning": "AI verification timeout: exceeded 120s budget",
        "error": "AI verification timeout: exceeded 120s budget",
    }
    merged = _merge_ai_result_into_retest_result(result, ai_result)
    assert merged["verdict"] == "inconclusive"
    assert merged["result_status"] == "inconclusive"


def test_high_confidence_ai_false_positive_classifies_as_false_positive():
    result = {
        "status": "completed",
        "result_status": "inconclusive",
        "verdict": "inconclusive",
        "verification_mode": "deterministic",
    }
    ai_result = {"verdict": "false_positive", "confidence": 0.88, "reasoning": "Vendor static asset"}
    merged = _merge_ai_result_into_retest_result(result, ai_result)
    assert merged["verdict"] == "false_positive"
    assert merged["confidence"] == 0.88


def test_low_confidence_ai_false_positive_downgraded_to_inconclusive():
    result = {
        "status": "completed",
        "result_status": "inconclusive",
        "verdict": "inconclusive",
        "verification_mode": "deterministic",
    }
    ai_result = {"verdict": "false_positive", "confidence": 0.3, "reasoning": "Probably not real"}
    merged = _merge_ai_result_into_retest_result(result, ai_result)
    assert merged["verdict"] == "inconclusive"


def test_enforce_verdict_invariants_downgrades_weak_false_positive():
    downgraded = _enforce_verdict_invariants(
        {"verdict": "false_positive", "confidence": 0.0, "result_status": "inconclusive"}
    )
    assert downgraded["verdict"] == "inconclusive"
    assert downgraded["result_status"] == "inconclusive"

    kept = _enforce_verdict_invariants(
        {"verdict": "false_positive", "confidence": 0.9, "result_status": "inconclusive"}
    )
    assert kept["verdict"] == "false_positive"


def test_failed_retest_steps_with_zero_confidence_are_not_partial_evidence():
    result = {
        "proof": {
            "proven": False,
            "confidence": 0.0,
            "evidence_type": "",
            "technique": "",
            "request": None,
        },
        "artifacts": {
            "step_attempts": [
                {"step": "dbms_extraction", "proven": False, "confidence": 0.0, "technique": "", "evidence_type": ""},
                {"step": "boolean_diff", "proven": False, "confidence": 0.0, "technique": "", "evidence_type": ""},
                {"step": "timing_fallback", "proven": False, "confidence": 0.0, "technique": "", "evidence_type": ""},
            ]
        },
    }

    assert _has_partial_deterministic_evidence(result) is False


def test_meaningful_nonproven_signal_is_partial_evidence():
    result = {
        "proof": {
            "proven": False,
            "confidence": 0.6,
            "evidence_type": "cross_user_access_suspected",
            "technique": "idor_replay",
        },
        "artifacts": {"step_attempts": []},
    }

    assert _has_partial_deterministic_evidence(result) is True


def test_benign_evidence_types_are_not_partial_vulnerability_evidence():
    for evidence_type in ("access_denied", "not_found", "catch_all_server", "soft_404_page"):
        result = {
            "proof": {
                "proven": False,
                "confidence": 0.9,
                "evidence_type": evidence_type,
                "technique": "replay",
            },
            "artifacts": {"step_attempts": []},
        }
        assert _has_partial_deterministic_evidence(result) is False


def test_slot_wait_state_defaults_to_now_and_first_cycle():
    now = datetime(2026, 2, 9, 6, 0, 0)
    started_at, cycles, waited = _slot_wait_state({}, now)
    assert started_at == now
    assert cycles == 1
    assert waited == 0


def test_slot_wait_state_parses_existing_started_at_and_increments_cycles():
    started = datetime(2026, 2, 9, 5, 59, 30)
    now = datetime(2026, 2, 9, 6, 0, 0)
    started_at, cycles, waited = _slot_wait_state(
        {"slot_wait_started_at": started.isoformat(), "slot_wait_cycles": 3},
        now,
    )
    assert started_at == started
    assert cycles == 4
    assert waited == 30


def test_slot_wait_backoff_is_exponential_and_capped():
    assert _slot_wait_backoff_seconds(1) >= 1
    assert _slot_wait_backoff_seconds(2) >= _slot_wait_backoff_seconds(1)
    assert _slot_wait_backoff_seconds(3) >= _slot_wait_backoff_seconds(2)
    assert _slot_wait_backoff_seconds(50) <= 30


def test_retryable_ai_error_detection():
    assert _is_retryable_ai_error("Network error: ClientConnectionError: Connection closed")
    assert _is_retryable_ai_error("Timeout after 60s")
    assert _is_retryable_ai_error("HTTP 503: upstream unavailable")
    assert not _is_retryable_ai_error("No steps in plan")


def test_ai_circuit_open_predicate():
    now = datetime(2026, 2, 9, 6, 0, 0)
    assert _is_ai_circuit_open(now + timedelta(seconds=60), now)
    assert not _is_ai_circuit_open(now - timedelta(seconds=1), now)
    assert not _is_ai_circuit_open(None, now)


def test_ai_circuit_threshold_predicate():
    assert not _should_open_ai_circuit(max(0, RETEST_AI_CIRCUIT_ERROR_THRESHOLD - 1))
    assert _should_open_ai_circuit(RETEST_AI_CIRCUIT_ERROR_THRESHOLD)


def test_stale_retest_requeue_limit_predicate():
    assert _stale_retest_should_requeue(RETEST_STALE_REQUEUE_LIMIT)
    assert not _stale_retest_should_requeue(RETEST_STALE_REQUEUE_LIMIT + 1)
