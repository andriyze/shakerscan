"""
Tests for retest type normalization and inference coverage.
"""

import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from retest_contract import (  # noqa: E402
    AI_ONLY_RETEST_TYPES,
    SUPPORTED_RETEST_TYPES,
    VerificationPolicy,
    build_replay_commands,
    get_attempt_ladder,
    infer_retest_inputs,
    infer_type_from_title_tool,
    normalize_retest_type,
)


def test_auto_fp_policy_is_off_by_default():
    p = VerificationPolicy.from_env(overrides={})
    assert p.auto_fp_on_retest is False
    assert p.auto_fp_min_confidence == 0.9


def test_auto_fp_policy_reads_overrides_and_clamps_confidence():
    p = VerificationPolicy.from_env(
        overrides={"auto_fp_on_retest": "true", "auto_fp_min_confidence": "1.4"}
    )
    assert p.auto_fp_on_retest is True
    assert p.auto_fp_min_confidence == 1.0


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


def test_exposed_file_is_supported_retest_type():
    assert "exposed_file" in SUPPORTED_RETEST_TYPES
    ladder = get_attempt_ladder("exposed_file")
    assert "content_marker_replay" in ladder
    assert "ai_reasoning" in ladder


def test_exposed_file_inferred_from_tool_names():
    assert infer_type_from_title_tool("Exposed file: id_rsa (confidence: high)", "exposed_files") == "exposed_file"
    assert infer_type_from_title_tool("Accessible Sensitive File: /wp-config.php", "forced_browsing") == "exposed_file"
    # Title-only fallback when tool is missing
    assert infer_type_from_title_tool("Exposed file: .env", None) == "exposed_file"
    assert infer_type_from_title_tool("Accessible Backup File: /dump.sql", "") == "exposed_file"


def test_nosql_injection_never_routes_to_sqli_prover():
    # The SQLi prover cannot reproduce NoSQL operator injection; routing it
    # there yields a false "likely_fixed". These must stay un-inferred.
    assert infer_type_from_title_tool("NoSQL Injection in username", "nosql_injection") is None
    assert infer_type_from_title_tool("NoSQL Injection Vulnerability", "") is None
    # Plain SQLi still infers
    assert infer_type_from_title_tool("SQL Injection in id parameter", "") == "sqli"


def test_nosql_guard_runs_before_tool_map():
    # Even if a NoSQL finding were mistagged with a sqli-family tool, the guard
    # (which runs before the tool map) must prevent misrouting to the SQLi prover.
    assert infer_type_from_title_tool("NoSQL Injection in username", "smart_sqli") is None
    assert infer_type_from_title_tool("Some title", "nosql_injection") is None


def test_tool_map_covers_types_previously_missing_from_api_inference():
    assert infer_type_from_title_tool("Broken object level authorization", "smart_bola") == "bola"
    assert infer_type_from_title_tool("Command Injection in cmd parameter", "") == "command_injection"
    assert infer_type_from_title_tool("JWT signature not validated", "") == "jwt"
    assert infer_type_from_title_tool("SSTI in template parameter", "") == "ssti"


def test_generic_http_is_ai_only():
    assert "generic_http" in SUPPORTED_RETEST_TYPES
    assert "generic_http" in AI_ONLY_RETEST_TYPES
    assert get_attempt_ladder("generic_http") == ["ai_reasoning"]
    # generic_http is assigned explicitly by the API, never inferred
    assert infer_type_from_title_tool("Sensitive data exposed in API response", "api_security") is None


def test_replay_commands_for_exposed_file_are_plain_get():
    commands = build_replay_commands(
        {
            "finding_type": "exposed_file",
            "target_url": "https://example.com/id_rsa",
            "original_url": "https://example.com/id_rsa",
        }
    )
    assert commands == ["curl -i -k 'https://example.com/id_rsa'"]


def test_infer_retest_inputs_for_exposed_file_finding_row():
    inferred = infer_retest_inputs(
        {
            "title": "Exposed file: id_rsa (confidence: high)",
            "tool": "exposed_files",
            "target_url": "https://example.com",
            "finding_url": "https://example.com/id_rsa",
            "evidence": '{"url": "https://example.com/id_rsa", "path": "id_rsa", "markers": ["private_key_marker"]}',
        }
    )
    assert inferred["finding_type"] == "exposed_file"
    assert inferred["original_url"] == "https://example.com/id_rsa"
    assert inferred["evidence"]["markers"] == ["private_key_marker"]
