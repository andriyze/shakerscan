import pytest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import check_registry as r  # noqa: E402


def test_registry_exposes_runnable_asm_focus_families():
    names = r.asm_focus_family_names()

    assert names == ("all", "sqli", "xss", "bola", "auth")
    assert r.CHECK_REGISTRY_BY_NAME["sqli"].scanner_options == {
        "sqli": True,
        "xss": False,
        "asm_check_family": "sqli",
    }
    assert r.CHECK_REGISTRY_BY_NAME["xss"].scanner_options == {
        "xss": True,
        "sqli": False,
        "asm_check_family": "xss",
    }
    assert r.CHECK_REGISTRY_BY_NAME["bola"].scanner_options == {
        "sqli": False,
        "xss": False,
        "asm_check_family": "bola",
    }
    assert r.CHECK_REGISTRY_BY_NAME["auth"].scanner_options == {
        "sqli": False,
        "xss": False,
        "asm_check_family": "auth",
    }
    assert r.CHECK_REGISTRY_BY_NAME["auth"].requires_credentials is True
    assert "payload" in r.CHECK_REGISTRY_BY_NAME["sqli"].proof_contract
    assert r.CHECK_REGISTRY_BY_NAME["sqli"].severity_rules["critical_requires"] == ["exploitation_proof"]


def test_registry_gates_high_risk_families_by_runnable_state():
    bola = r.CHECK_REGISTRY_BY_NAME["bola"]
    ssrf = r.CHECK_REGISTRY_BY_NAME["ssrf"]

    assert bola.runnable is True
    assert bola.requires_auth_states is True
    assert bola.requires_credentials is True
    assert bola.allowed_presets == ("lab",)
    assert ssrf.risk_level == "high"
    assert ssrf.allowed_presets == ("lab",)
    assert ssrf.runnable is False


def test_validate_asm_focus_rejects_registered_but_unrunnable_family():
    with pytest.raises(ValueError, match="registered but not runnable"):
        r.validate_asm_focus_family("ssrf")


def test_validate_asm_focus_rejects_unknown_family_with_allowed_list():
    with pytest.raises(ValueError, match="allowed families: all, sqli, xss, bola, auth"):
        r.validate_asm_focus_family("nosuch")


def test_apply_asm_focus_uses_registry_scanner_options():
    opts, family = r.apply_asm_focus({"scan_type": "smart", "xss": True}, "sql")

    assert family == "sqli"
    assert opts["sqli"] is True
    assert opts["xss"] is False
    assert opts["asm_check_family"] == "sqli"


def test_all_focus_preserves_normal_mix_and_clears_marker():
    opts, family = r.apply_asm_focus({"scan_type": "smart", "asm_check_family": "xss"}, "all")

    assert family is None
    assert "asm_check_family" not in opts


def test_default_parallel_focus_families_exclude_high_risk_bola():
    assert tuple(spec.name for spec in r.default_parallel_focus_families()) == ("sqli", "xss")


def test_describe_check_families_includes_proof_and_severity_contracts():
    described = {item["name"]: item for item in r.describe_check_families()}

    assert described["headers"]["proof_contract"] == [
        "request_url",
        "response_headers",
        "parsed_policy_state",
    ]
    assert described["headers"]["severity_rules"]["csp_absent"] == "medium"
    assert described["bola"]["severity_rules"]["critical_requires"] == ["cross_user_data_access"]


def test_scanner_execution_plan_uses_registry_gates():
    plan = r.scanner_execution_plan(
        scan_mode="smart",
        active_checks=True,
        check_family_scope={"families": ["sqli"], "focused_family": "sqli"},
    )
    families = {item["name"]: item for item in plan["families"]}

    assert plan["registry_version"] == "check_family_v1"
    assert plan["summary"]["enabled_count"] >= 4
    assert "sqli" in plan["summary"]["enabled_families"]
    assert plan["summary"]["proof_contracts"]["sqli"] == families["sqli"]["proof_contract"]
    assert plan["summary"]["enabled_by_phase"]["active"] >= 1
    assert families["recon"]["enabled"] is True
    assert families["headers"]["enabled"] is True
    assert families["nuclei"]["enabled"] is True
    assert families["sqli"]["enabled"] is True
    assert families["sqli"]["reason"] == "selected_by_check_family_scope"
    assert families["sqli"]["dispatch_adapter"] == "legacy_active_loop"
    assert families["sqli"]["requested"] is True
    assert families["xss"]["enabled"] is False
    assert families["ssrf"]["enabled"] is False
    assert families["ssrf"]["reason"] == "registered_not_runnable"
    assert "payload" in families["sqli"]["proof_contract"]
    assert plan["summary"]["dispatch_adapter_counts"]["legacy_active_loop"] == 1
    # Every enabled family in a normal plan is wired to a dispatch adapter, so the
    # coverage-honesty fields report zero unwired and full dispatched coverage.
    assert plan["summary"]["unwired_enabled"] == []
    assert plan["summary"]["dispatched_enabled_count"] == plan["summary"]["enabled_count"]


def test_scanner_execution_plan_records_passive_skip_reasons():
    plan = r.scanner_execution_plan(
        scan_mode="quick",
        public_only=True,
        quick_mode=True,
        active_checks=True,
        check_family_scope={"families": ["xss"], "focused_family": "xss"},
        skip_global_checks=True,
        zero_rediscovery=True,
    )
    families = {item["name"]: item for item in plan["families"]}

    assert families["recon"]["enabled"] is False
    assert families["recon"]["reason"] == "zero_rediscovery_scope"
    assert families["headers"]["enabled"] is False
    assert families["headers"]["reason"] == "global_checks_skipped"
    assert families["nuclei"]["enabled"] is False
    assert families["nuclei"]["reason"] == "public_only"
    assert families["xss"]["enabled"] is False
    assert families["xss"]["reason"] == "public_only"
    assert plan["summary"]["skip_reason_counts"]["public_only"] >= 1
    assert "recon" in plan["summary"]["skipped_families"]


def test_scanner_execution_plan_blocks_requested_unrunnable_family():
    plan = r.scanner_execution_plan(
        scan_mode="smart",
        active_checks=True,
        check_family_scope={"families": ["ssrf"], "focused_family": "ssrf"},
    )
    families = {item["name"]: item for item in plan["families"]}

    assert families["ssrf"]["requested"] is True
    assert families["ssrf"]["enabled"] is False
    assert families["ssrf"]["reason"] == "registered_not_runnable"
    assert families["ssrf"]["blocked_by"] == ["registry_family_not_runnable"]
    assert plan["summary"]["requested_blocked"] == [
        {
            "name": "ssrf",
            "reason": "registered_not_runnable",
            "blocked_by": ["registry_family_not_runnable"],
        }
    ]
