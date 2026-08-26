from dataclasses import replace

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
    mass_assignment = r.CHECK_REGISTRY_BY_NAME["mass_assignment"]
    assert mass_assignment.runnable is True
    assert mass_assignment.telemetry_schema == "mass_assignment_attempt_v1"
    assert "observed_privilege_effect" in mass_assignment.proof_contract
    assert "CWE-915" in mass_assignment.finding_cwes
    jwt = r.CHECK_REGISTRY_BY_NAME["jwt"]
    assert jwt.runnable is True
    assert jwt.telemetry_schema == "jwt_probe_attempt_v1"
    assert "jwt" in jwt.finding_title_markers
    assert "forged_status" in jwt.proof_contract
    passive_nuclei = r.CHECK_REGISTRY_BY_NAME["nuclei_passive"]
    active_nuclei = r.CHECK_REGISTRY_BY_NAME["nuclei_active"]
    assert passive_nuclei.runnable is True
    assert passive_nuclei.is_active is False
    assert active_nuclei.runnable is True
    assert active_nuclei.is_active is True
    assert active_nuclei.telemetry_schema == "nuclei_template"
    assert active_nuclei.proof_contract == (
        "template_id", "matched_at", "matcher_name", "request_url",
    )
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


def test_managed_profile_refs_satisfy_auth_context_without_secret_values():
    options = {"managed_credential_profiles": [
        {"auth_state": "user1", "profile_id": "p1", "option_key": "auth_header"},
        {"auth_state": "user2", "profile_id": "p2", "option_key": "user2_header"},
    ]}

    assert r.has_primary_auth_context(options) is True
    assert r.has_second_user_auth_context(options) is True
    assert r.family_precondition_error("bola", options, exploit_depth=True) is None


def test_describe_check_families_includes_proof_and_severity_contracts():
    described = {item["name"]: item for item in r.describe_check_families()}

    assert described["headers"]["proof_contract"] == [
        "request_url",
        "response_headers",
        "parsed_policy_state",
    ]
    assert described["headers"]["severity_rules"]["csp_absent"] == "medium"
    assert described["bola"]["severity_rules"]["critical_requires"] == ["cross_user_data_access"]
    assert described["headers"]["dispatch_adapter"] == "legacy_config_findings"


def test_scanner_focus_contracts_come_from_registry_in_legacy_order():
    contracts = r.scanner_active_family_contracts()

    assert [item["name"] for item in contracts] == ["all", "sqli", "xss", "auth", "bola"]
    assert contracts[1]["tools"] == ["smart_sqli", "custom_sqli", "sqlmap", "nosql_injection"]
    assert contracts[-1]["requires_two_auth_states"] is True
    assert r.normalize_check_family("access-control") == "auth"


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
    assert families["nuclei_passive"]["enabled"] is False
    assert families["nuclei_passive"]["reason"] == "canonical_action_only"
    assert families["nuclei_active"]["enabled"] is True
    assert families["sqli"]["enabled"] is True
    assert families["sqli"]["reason"] == "selected_by_check_family_scope"
    assert families["sqli"]["dispatch_adapter"] == "legacy_active_loop"
    assert families["sqli"]["requested"] is True
    assert families["xss"]["enabled"] is False
    assert families["mass_assignment"]["enabled"] is False
    assert families["ssrf"]["enabled"] is False
    assert families["ssrf"]["reason"] == "registered_not_runnable"
    assert "payload" in families["sqli"]["proof_contract"]
    assert plan["summary"]["dispatch_adapter_counts"]["legacy_active_loop"] == 1
    # Every enabled family in a normal plan is wired to a dispatch adapter, so the
    # coverage-honesty fields report zero unwired and full dispatched coverage.
    assert plan["summary"]["unwired_enabled"] == []
    assert plan["summary"]["dispatched_enabled_count"] == plan["summary"]["enabled_count"]


def test_scanner_execution_plan_dispatches_registered_mass_assignment():
    plan = r.scanner_execution_plan(
        scan_mode="complete",
        active_checks=True,
        check_family_scope={"families": ["mass_assignment"]},
    )
    families = {item["name"]: item for item in plan["families"]}

    assert families["mass_assignment"]["enabled"] is True
    assert families["mass_assignment"]["dispatch_adapter"] == "legacy_phase4_mass_assignment"
    assert families["sqli"]["enabled"] is False
    assert plan["summary"]["proof_contracts"]["mass_assignment"] == list(
        r.CHECK_REGISTRY_BY_NAME["mass_assignment"].proof_contract
    )


def test_scanner_execution_plan_dispatches_registered_jwt():
    plan = r.scanner_execution_plan(
        scan_mode="smart",
        active_checks=True,
        check_family_scope={"families": ["jwt"]},
    )
    families = {item["name"]: item for item in plan["families"]}

    assert families["jwt"]["enabled"] is True
    assert families["jwt"]["dispatch_adapter"] == "legacy_advanced_jwt"
    assert families["sqli"]["enabled"] is False


def test_scanner_execution_plan_honors_registry_policy_independently(monkeypatch):
    monkeypatch.setattr(
        r,
        "CHECK_REGISTRY",
        tuple(
            replace(spec, scanner_enabled=False) if spec.name == "jwt" else spec
            for spec in r.CHECK_REGISTRY
        ),
    )

    plan = r.scanner_execution_plan(
        scan_mode="smart",
        active_checks=True,
        check_family_scope={"families": ["jwt"]},
    )
    jwt = next(item for item in plan["families"] if item["name"] == "jwt")

    assert jwt["requested"] is True
    assert jwt["runnable"] is True
    assert jwt["scanner_enabled"] is False
    assert jwt["enabled"] is False
    assert jwt["reason"] == "registry_policy_disabled"
    assert jwt["blocked_by"] == ["registry_policy_disabled"]


def test_scanner_execution_plan_enforces_canonical_family_policy_at_dispatch():
    plan = r.scanner_execution_plan(
        scan_mode="canonical",
        active_checks=True,
        check_family_scope={"families": ["sqli", "xss"], "focused_family": None},
        include_families=("sqli",),
        exclude_families=("headers",),
    )
    families = {item["name"]: item for item in plan["families"]}

    assert families["sqli"]["enabled"] is True
    assert families["xss"]["enabled"] is False
    assert families["xss"]["reason"] == "policy_not_included"
    assert families["xss"]["blocked_by"] == ["family_policy_not_included"]
    assert families["headers"]["enabled"] is False
    assert families["headers"]["reason"] == "policy_excluded"
    assert plan["family_policy"] == {
        "include_families": ["sqli"],
        "exclude_families": ["headers"],
    }


def test_scanner_execution_plan_dispatches_only_active_nuclei_through_legacy_adapter():
    standard = r.scanner_execution_plan(
        scan_mode="standard",
        active_checks=False,
    )
    active = r.scanner_execution_plan(
        scan_mode="standard",
        active_checks=True,
    )
    quick = r.scanner_execution_plan(
        scan_mode="quick",
        quick_mode=True,
        active_checks=False,
    )
    standard_families = {item["name"]: item for item in standard["families"]}
    active_families = {item["name"]: item for item in active["families"]}
    quick_families = {item["name"]: item for item in quick["families"]}

    assert standard_families["nuclei_passive"]["reason"] == "canonical_action_only"
    assert standard_families["nuclei_active"]["enabled"] is False
    assert standard_families["nuclei_active"]["reason"] == "active_testing_required"
    assert active_families["nuclei_active"]["enabled"] is True
    assert active_families["nuclei_active"]["dispatch_adapter"] == "legacy_nuclei_template"
    assert quick_families["nuclei_active"]["enabled"] is False
    assert quick_families["nuclei_active"]["reason"] == "quick_mode"


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
    assert families["nuclei_passive"]["reason"] == "canonical_action_only"
    assert families["nuclei_active"]["enabled"] is False
    assert families["nuclei_active"]["reason"] == "public_only"
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
