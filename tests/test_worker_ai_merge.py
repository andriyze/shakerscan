"""
Unit tests for merging AI retest verdicts into deterministic outcomes.
"""

import os
import sys
import types


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace())
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

from worker import (  # noqa: E402
    _merge_ai_result_into_retest_result,
    _result_status_for_verdict,
)


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


def test_ai_exploited_overrides_non_error_result():
    result = {
        "status": "completed",
        "result_status": "likely_fixed",
        "verdict": "likely_fixed",
        "verification_mode": "deterministic",
    }
    ai_result = {"verdict": "exploited", "confidence": 0.92, "reasoning": "Exploit replay succeeded"}
    merged = _merge_ai_result_into_retest_result(result, ai_result)

    assert merged["status"] == "completed"
    assert merged["verification_mode"] == "ai_driven"
    assert merged["verdict"] == "exploited"
    assert merged["result_status"] == "still_vulnerable"
    assert merged["confidence"] == 0.92


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
