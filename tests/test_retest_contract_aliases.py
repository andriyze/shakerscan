"""
Tests for retest type normalization and inference coverage.
"""

import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from retest_contract import (  # noqa: E402
    SUPPORTED_RETEST_TYPES,
    get_attempt_ladder,
    infer_retest_inputs,
    normalize_retest_type,
)


def test_2fa_bypass_is_supported_retest_type():
    assert "2fa_bypass" in SUPPORTED_RETEST_TYPES
    ladder = get_attempt_ladder("2fa_bypass")
    assert "ai_reasoning" in ladder


def test_2fa_aliases_normalize_to_single_type():
    for alias in ("2fa_bypass", "2fa-bypass", "mfa_bypass", "mfa-bypass", "otp_bypass"):
        assert normalize_retest_type(alias) == "2fa_bypass"


def test_infer_retest_inputs_detects_2fa_from_title_and_tool():
    inferred = infer_retest_inputs(
        {
            "title": "2FA bypass possible via no_rate_limiting",
            "tool": "2fa_bypass",
            "target_url": "https://example.com",
        }
    )
    assert inferred["finding_type"] == "2fa_bypass"
    assert inferred["target_url"] == "https://example.com"
