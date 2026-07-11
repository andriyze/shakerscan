import asyncio
import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
_added_scanner_dir = False
if _SCANNER_DIR not in sys.path:
    sys.path.insert(0, _SCANNER_DIR)
    _added_scanner_dir = True

_spec = importlib.util.spec_from_file_location(
    "shaker_scanner_scope_under_test", os.path.join(_SCANNER_DIR, "scanner.py")
)
scanner_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner_mod)
if _added_scanner_dir:
    sys.path.remove(_SCANNER_DIR)


def test_check_family_scope_marks_focused_sqli():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=False,
        active_sqli=True,
        requested_family="sqli",
    )

    assert scope["mode"] == "focused"
    assert scope["focused"] is True
    assert scope["focused_family"] == "sqli"
    assert scope["families"] == ["sqli"]
    assert scope["source"] == "check_family"
    assert scope["requested_family"] == "sqli"
    assert scope["legacy_flags"] == {"xss": False, "sqli": True}


def test_check_family_scope_marks_focused_bola():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=False,
        active_sqli=False,
        requested_family="bola",
    )

    assert scope["mode"] == "focused"
    assert scope["focused"] is True
    assert scope["focused_family"] == "bola"
    assert scope["families"] == ["bola"]
    assert scope["source"] == "check_family"
    assert scope["requested_family"] == "bola"
    assert scope["legacy_flags"] == {"xss": False, "sqli": False}


def test_bola_candidate_budget_distinguishes_inventory_from_execution_ceiling():
    summary = scanner_mod.summarize_bola_candidate_budget(500, 300)

    assert summary == {
        "candidate_endpoints": 500,
        "max_endpoints": 300,
        "scheduled_endpoints_upper_bound": 300,
    }


def test_bola_candidate_budget_normalizes_invalid_or_negative_values():
    assert scanner_mod.summarize_bola_candidate_budget("invalid", -5) == {
        "candidate_endpoints": 0,
        "max_endpoints": 0,
        "scheduled_endpoints_upper_bound": 0,
    }


def test_check_family_scope_marks_focused_auth():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=False,
        active_sqli=False,
        requested_family="auth",
    )

    assert scope["mode"] == "focused"
    assert scope["focused"] is True
    assert scope["focused_family"] == "auth"
    assert scope["families"] == ["auth"]
    assert scope["source"] == "check_family"
    assert scope["requested_family"] == "auth"
    assert scope["legacy_flags"] == {"xss": False, "sqli": False}


def test_bola_resource_mapper_uses_manual_path_placeholders():
    endpoints = scanner_mod.normalize_manual_endpoints(
        "https://crapi.test",
        scanner_mod.parse_manual_endpoints([
            "GET /workshop/api/shop/orders/<orderId>?order_id=42&limit=1",
        ]),
    )

    resources = scanner_mod.bola_resource_endpoints_from_manual_endpoints(endpoints)

    assert resources[0]["path"] == "/workshop/api/shop/orders/{id}?order_id={id}&limit=1"
    assert resources[0]["ids"][:2] == ["42", "1"]


def test_bola_resource_mapper_uses_id_query_params_and_skips_posts():
    endpoints = scanner_mod.normalize_manual_endpoints(
        "https://api.test",
        scanner_mod.parse_manual_endpoints([
            "GET /api/orders?order_id=7&limit=1",
            "POST /api/orders json:{\"order_id\":7}",
        ]),
    )

    resources = scanner_mod.bola_resource_endpoints_from_manual_endpoints(endpoints)

    assert resources == [
        {"path": "/api/orders?order_id={id}&limit=1", "ids": ["7", "1", "2", "100", "999"]}
    ]


def test_check_family_scope_marks_normal_active_mix():
    scope = scanner_mod.build_check_family_scope(True, active_xss=True, active_sqli=True)

    assert scope["mode"] == "active_mix"
    assert scope["focused"] is False
    assert scope["focused_family"] is None
    assert scope["families"] == ["xss", "sqli"]


def test_check_family_scope_includes_legacy_mass_assignment_executor():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=True,
        active_sqli=True,
        mass_assignment=True,
    )

    assert scope["mode"] == "active_mix"
    assert scope["families"] == ["xss", "sqli", "mass_assignment"]


def test_check_family_scope_keeps_explicit_mass_assignment_without_global_active_flag():
    scope = scanner_mod.build_check_family_scope(
        False,
        active_xss=True,
        active_sqli=True,
        mass_assignment=True,
    )

    assert scope["families"] == ["mass_assignment"]
    assert scope["mode"] == "focused"
    assert scope["focused_family"] == "mass_assignment"


def test_check_family_scope_includes_automatic_advanced_jwt_executor():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=True,
        active_sqli=True,
        jwt=True,
    )

    assert scope["families"] == ["xss", "sqli", "jwt"]


def test_check_family_scope_plans_broad_smart_bola_without_legacy_override():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=True,
        active_sqli=True,
        jwt=True,
        bola=True,
    )
    plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="smart",
        public_only=False,
        quick_mode=False,
        active_checks=True,
        check_family_scope=scope,
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )
    families = {item["name"]: item for item in plan["families"]}

    assert scope["families"] == ["xss", "sqli", "jwt", "bola"]
    assert families["bola"]["enabled"] is True
    assert scanner_mod.registry_dispatch_enabled(plan, "bola") is True


def test_check_family_scope_marks_inactive_scan():
    scope = scanner_mod.build_check_family_scope(False, active_xss=True, active_sqli=True)

    assert scope["mode"] == "inactive"
    assert scope["focused"] is False
    assert scope["families"] == []


def test_nuclei_dispatch_uses_registry_profile_gate():
    standard_plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="standard",
        public_only=False,
        quick_mode=False,
        active_checks=False,
        check_family_scope={"families": []},
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )
    quick_plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="quick",
        public_only=False,
        quick_mode=True,
        active_checks=False,
        check_family_scope={"families": []},
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )

    assert scanner_mod.registry_dispatch_decision(standard_plan, "nuclei")["dispatch_enabled"] is True
    assert scanner_mod.registry_dispatch_decision(quick_plan, "nuclei")["dispatch_enabled"] is False


def test_nuclei_template_phase_dispatches_only_registry_enabled_adapter():
    called = []
    standard_plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="standard",
        public_only=False,
        quick_mode=False,
        active_checks=False,
        check_family_scope={"families": []},
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )
    quick_plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="quick",
        public_only=False,
        quick_mode=True,
        active_checks=False,
        check_family_scope={"families": []},
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )

    async def nuclei_adapter():
        await asyncio.sleep(0)
        called.append("nuclei")

    standard_receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        standard_plan,
        "template",
        {"legacy_nuclei_template": nuclei_adapter},
    ))
    quick_receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        quick_plan,
        "template",
        {"legacy_nuclei_template": nuclei_adapter},
    ))

    assert called == ["nuclei"]
    assert standard_receipts == [{
        "family": "nuclei",
        "phase": "template",
        "dispatch_adapter": "legacy_nuclei_template",
        "status": "completed",
        "telemetry_schema": "nuclei_template",
        "proof_contract": ["template_id", "matched_at", "matcher_name", "request_url"],
    }]
    assert quick_receipts[0]["status"] == "skipped"
    assert quick_receipts[0]["reason"] == "quick_mode"


def test_recon_phase_dispatches_normal_plan_and_skips_zero_rediscovery():
    called = []
    standard_plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="standard",
        public_only=False,
        quick_mode=False,
        active_checks=False,
        check_family_scope={"families": []},
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )
    zero_plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="smart",
        public_only=False,
        quick_mode=False,
        active_checks=True,
        check_family_scope={"families": ["sqli"], "focused": True},
        skip_global_checks=True,
        focused_endpoints_only=True,
        zero_rediscovery=True,
    )

    async def recon_adapter():
        called.append("recon")
        return scanner_mod.RegistryPhaseOutcome(
            "completed",
            telemetry={"discovered_urls": 3, "browser_pages": 1},
        )

    standard_receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        standard_plan,
        "recon",
        {"legacy_discovery": recon_adapter},
    ))
    zero_receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        zero_plan,
        "recon",
        {"legacy_discovery": recon_adapter},
    ))

    assert called == ["recon"]
    assert standard_receipts[0]["status"] == "completed"
    assert standard_receipts[0]["adapter_telemetry"]["discovered_urls"] == 3
    assert zero_receipts[0]["status"] == "skipped"
    assert zero_receipts[0]["reason"] == "zero_rediscovery_scope"


def test_resolve_active_check_flags_uses_registry_family_aliases():
    active_xss, active_sqli, family = scanner_mod.resolve_active_check_flags(check_family="sql")

    assert active_xss is False
    assert active_sqli is True
    assert family == "sqli"


def test_resolve_active_check_flags_all_family_keeps_active_mix():
    active_xss, active_sqli, family = scanner_mod.resolve_active_check_flags(check_family="all")

    assert active_xss is True
    assert active_sqli is True
    assert family == "all"


def test_resolve_active_check_flags_accepts_bola_without_injection_flags():
    active_xss, active_sqli, family = scanner_mod.resolve_active_check_flags(check_family="idor")

    assert active_xss is False
    assert active_sqli is False
    assert family == "bola"


def test_resolve_active_check_flags_accepts_auth_without_injection_flags():
    active_xss, active_sqli, family = scanner_mod.resolve_active_check_flags(check_family="authentication")

    assert active_xss is False
    assert active_sqli is False
    assert family == "auth"


def test_resolve_active_check_flags_rejects_unsupported_family():
    with pytest.raises(ValueError, match="not runnable"):
        scanner_mod.resolve_active_check_flags(check_family="ssrf")


def test_resolve_active_check_flags_rejects_conflicting_legacy_flags():
    with pytest.raises(ValueError, match="conflicts"):
        scanner_mod.resolve_active_check_flags(check_family="sqli", xss=True)


def test_focused_sqli_does_not_allow_xss_or_bola_enrichment():
    assert scanner_mod.focused_family_allows_active_module("sqli", "dom_xss") is False
    assert scanner_mod.focused_family_allows_active_module("sqli", "bola_idor") is False
    assert scanner_mod.focused_family_allows_active_module("sqli", "nosql_injection") is True
    assert scanner_mod.focused_family_allows_active_module("sqli", "sqlmap") is True


def test_focused_xss_and_bola_allow_only_their_enrichment_modules():
    assert scanner_mod.focused_family_allows_active_module("xss", "dom_xss") is True
    assert scanner_mod.focused_family_allows_active_module("xss", "bola_idor") is False
    assert scanner_mod.focused_family_allows_active_module("bola", "bola_idor") is True
    assert scanner_mod.focused_family_allows_active_module("bola", "dom_xss") is False


def test_focused_bola_uses_bola_deadline_even_when_primary_active_budget_is_exhausted():
    active_block = {"post_active_enrichment_skipped": "active_time_budget_exhausted"}

    decision = scanner_mod.bola_enrichment_decision(
        bola_focused=True,
        post_active_budget_exhausted=True,
        active_block=active_block,
    )

    assert decision.run is True
    assert decision.reason is None
    assert active_block["active_enrichment_decisions"]["bola_idor"] == {
        "run": True,
        "reason": None,
        "source": "focused_bola_deadline",
    }


def test_broad_bola_still_respects_post_active_budget_gate():
    active_block = {"post_active_enrichment_skipped": "active_time_budget_exhausted"}

    decision = scanner_mod.bola_enrichment_decision(
        bola_focused=False,
        post_active_budget_exhausted=True,
        active_block=active_block,
    )

    assert decision.run is False
    assert decision.reason == "active_time_budget_exhausted"


def test_focused_bola_poe_settings_are_bounded_and_faster_than_global_safe_delay():
    assert scanner_mod.resolve_focused_bola_poe_settings(1) == {
        "bola_max_requests_per_target": 800,
        "rate_limit_ms": 100,
    }
    assert scanner_mod.resolve_focused_bola_poe_settings(500) == {
        "bola_max_requests_per_target": 10000,
        "rate_limit_ms": 100,
    }


def test_focused_bola_keeps_phase4_bola_checker_enabled():
    assert scanner_mod.focused_mode_keeps_phase4_bola("bola", False) is True
    assert scanner_mod.focused_mode_keeps_phase4_bola("idor", False) is True


def test_other_focused_families_disable_phase4_bola_checker():
    assert scanner_mod.focused_mode_keeps_phase4_bola("sqli", True) is False
    assert scanner_mod.focused_mode_keeps_phase4_bola("xss", True) is False
    assert scanner_mod.focused_mode_keeps_phase4_bola(None, True) is True
    assert scanner_mod.focused_mode_keeps_phase4_bola(None, False) is False


def test_broad_active_scan_allows_enrichment_modules():
    assert scanner_mod.focused_family_allows_active_module(None, "dom_xss") is True
    assert scanner_mod.focused_family_allows_active_module("all", "bola_idor") is True


# --- ACTIVE_CHECK_FAMILIES registry: single source of truth (keystone) ---

def test_registry_is_single_source_of_truth_for_runnable_families():
    assert scanner_mod.runnable_active_families() == ("all", "sqli", "xss", "auth", "bola")
    assert set(scanner_mod.ACTIVE_CHECK_FAMILIES) == {"all", "sqli", "xss", "auth", "bola"}


def test_legacy_flag_view_is_derived_byte_identical():
    assert scanner_mod.SCANNER_ACTIVE_FAMILY_FLAGS == {
        "all": (True, True),
        "sqli": (False, True),
        "xss": (True, False),
        "auth": (False, False),
        "bola": (False, False),
    }
    # order is preserved so the "allowed families" error message is unchanged
    assert ", ".join(scanner_mod.SCANNER_ACTIVE_FAMILY_FLAGS) == "all, sqli, xss, auth, bola"


def test_alias_view_is_derived_byte_identical():
    assert scanner_mod.SCANNER_ACTIVE_FAMILY_ALIASES == {
        "all": "all",
        "sql": "sqli",
        "sql-injection": "sqli",
        "sql_injection": "sqli",
        "cross-site-scripting": "xss",
        "cross_site_scripting": "xss",
        "authentication": "auth",
        "access-control": "auth",
        "access_control": "auth",
        "idor": "bola",
        "object_authorization": "bola",
        "object-authorization": "bola",
    }


def test_focused_rules_view_is_derived_and_excludes_all():
    rules = scanner_mod.FOCUSED_FAMILY_RULES
    assert set(rules) == {"sqli", "xss", "auth", "bola"}  # "all" carries no focused rules
    # representative entries preserve their content exactly
    assert rules["sqli"]["tools"] == {"smart_sqli", "custom_sqli", "sqlmap", "nosql_injection"}
    assert rules["sqli"]["cwes"] == {"CWE-89", "CWE-943"}
    assert rules["bola"]["cwes"] == {"CWE-639"}
    assert rules["bola"]["remediation"][0].startswith("Enforce object-level authorization")
    assert isinstance(rules["auth"]["title_markers"], tuple)
    assert isinstance(rules["xss"]["remediation"], list)


def test_family_requires_two_auth_states_is_registry_driven():
    assert scanner_mod.family_requires_two_auth_states("bola") is True
    assert scanner_mod.family_requires_two_auth_states("idor") is True  # alias resolves
    assert scanner_mod.family_requires_two_auth_states("sqli") is False
    assert scanner_mod.family_requires_two_auth_states("xss") is False
    assert scanner_mod.family_requires_two_auth_states("auth") is False
    assert scanner_mod.family_requires_two_auth_states("nope") is False


def test_scanner_execution_plan_is_registry_driven_for_focused_family():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=False,
        active_sqli=True,
        requested_family="sqli",
    )

    plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="smart",
        public_only=False,
        quick_mode=False,
        active_checks=True,
        check_family_scope=scope,
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )
    families = {item["name"]: item for item in plan["families"]}

    assert plan["registry_version"] == "check_family_v1"
    assert plan["check_family_scope"]["focused_family"] == "sqli"
    assert plan["summary"]["proof_contracts"]["sqli"] == families["sqli"]["proof_contract"]
    assert "sqli" in plan["summary"]["enabled_families"]
    assert families["sqli"]["enabled"] is True
    assert families["sqli"]["telemetry_schema"] == "active_endpoint_attempt_v1"
    assert "payload" in families["sqli"]["proof_contract"]
    assert families["xss"]["enabled"] is False
    assert families["headers"]["enabled"] is True


def test_scanner_execution_plan_records_zero_rediscovery_and_public_skips():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=True,
        active_sqli=False,
        requested_family="xss",
    )

    plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="quick",
        public_only=True,
        quick_mode=True,
        active_checks=True,
        check_family_scope=scope,
        skip_global_checks=True,
        focused_endpoints_only=True,
        zero_rediscovery=True,
    )
    families = {item["name"]: item for item in plan["families"]}

    assert families["recon"]["reason"] == "zero_rediscovery_scope"
    assert families["headers"]["reason"] == "global_checks_skipped"
    assert families["nuclei"]["reason"] == "public_only"
    assert families["xss"]["enabled"] is False
    assert plan["summary"]["skip_reason_counts"]["public_only"] >= 1
    assert families["xss"]["reason"] == "public_only"


def test_scanner_execution_plan_fails_loudly_when_registry_is_unavailable(monkeypatch):
    monkeypatch.setattr(scanner_mod, "_check_registry", None)

    with pytest.raises(RuntimeError, match="scanner_check_registry_unavailable"):
        scanner_mod.build_scanner_execution_plan(
            scan_mode="smart",
            public_only=False,
            quick_mode=False,
            active_checks=True,
            check_family_scope={"families": ["sqli"]},
            skip_global_checks=False,
            focused_endpoints_only=False,
            zero_rediscovery=False,
        )


def test_scanner_execution_plan_fails_loudly_on_partial_registry(monkeypatch):
    monkeypatch.setattr(
        scanner_mod,
        "_check_registry",
        SimpleNamespace(scanner_execution_plan=lambda **_kwargs: {
            "registry_version": "check_family_v1",
            "families": [{"name": "sqli"}],
            "summary": {},
        }),
    )

    with pytest.raises(RuntimeError, match="required_families_missing"):
        scanner_mod.build_scanner_execution_plan(
            scan_mode="smart",
            public_only=False,
            quick_mode=False,
            active_checks=True,
            check_family_scope={"families": ["sqli"]},
            skip_global_checks=False,
            focused_endpoints_only=False,
            zero_rediscovery=False,
        )


def test_registry_dispatch_enabled_is_authoritative_for_explicit_family():
    plan = {
        "check_family_scope": {"requested_family": "bola"},
        "families": [
            {"name": "bola", "enabled": False, "runnable": True, "dispatch_adapter": "asm_endpoint_batch"},
            {"name": "auth", "enabled": True, "runnable": True, "dispatch_adapter": "asm_endpoint_batch"},
        ],
    }

    assert scanner_mod.registry_dispatch_enabled(plan, "bola") is False
    assert scanner_mod.registry_dispatch_enabled(plan, "auth") is True


def test_registry_dispatch_enabled_does_not_override_disabled_broad_plan():
    plan = {
        "check_family_scope": {"requested_family": None},
        "families": [{"name": "bola", "enabled": False, "runnable": True, "dispatch_adapter": "asm_endpoint_batch"}],
    }

    assert scanner_mod.registry_dispatch_enabled(plan, "bola") is False
    assert scanner_mod.registry_dispatch_enabled(plan, "auth") is False


def test_registry_dispatch_decision_fails_closed_on_adapter_contract_drift():
    plan = {
        "check_family_scope": {"requested_family": "jwt"},
        "families": [{
            "name": "jwt",
            "phase": "active",
            "enabled": True,
            "runnable": True,
            "dispatch_adapter": "wrong_adapter",
            "blocked_by": [],
        }],
    }

    decision = scanner_mod.registry_dispatch_decision(
        plan,
        "jwt",
        expected_adapter="legacy_advanced_jwt",
    )

    assert decision["dispatch_enabled"] is False
    assert decision["decision"] == "blocked"
    assert decision["reason"] == "registry_dispatch_adapter_mismatch"
    assert decision["dispatch_adapter"] == "wrong_adapter"


def test_scanner_adapter_contracts_match_canonical_runnable_registry():
    assert scanner_mod._check_registry is not None
    for family, adapter in scanner_mod.SCANNER_REGISTRY_ADAPTER_CONTRACTS.items():
        spec = scanner_mod._check_registry.get_check_family(family)
        assert spec is not None
        assert spec.runnable is True
        assert spec.dispatch_adapter == adapter


def test_registry_dispatch_decision_rejects_unmapped_scanner_adapter():
    plan = {
        "check_family_scope": {"requested_family": "new_family"},
        "families": [{
            "name": "new_family",
            "phase": "active",
            "enabled": True,
            "runnable": True,
            "dispatch_adapter": "new_adapter",
            "blocked_by": [],
        }],
    }

    decision = scanner_mod.registry_dispatch_decision(plan, "new_family")

    assert decision["dispatch_enabled"] is False
    assert decision["reason"] == "scanner_adapter_contract_missing"


def test_registry_dispatch_decision_keeps_disabled_broad_family_skipped():
    plan = {
        "check_family_scope": {"requested_family": None},
        "families": [{
            "name": "bola",
            "phase": "active",
            "enabled": False,
            "runnable": True,
            "dispatch_adapter": "asm_endpoint_batch",
            "blocked_by": [],
            "reason": "not_selected",
        }],
    }

    decision = scanner_mod.registry_dispatch_decision(
        plan,
        "bola",
        expected_adapter="asm_endpoint_batch",
    )

    assert decision["dispatch_enabled"] is False
    assert decision["decision"] == "skipped"
    assert decision["reason"] == "not_selected"


def test_registry_report_phase_dispatches_only_enabled_declared_adapters():
    called = []
    plan = {"families": [
        {
            "name": "headers", "phase": "passive", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_config_findings",
            "telemetry_schema": "planned_passive_attempt", "proof_contract": ["response_headers"],
        },
        {"name": "recon", "phase": "recon", "enabled": True, "dispatch_adapter": "recon_adapter"},
    ]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan, "passive", {"legacy_config_findings": lambda: called.append("headers")}
    ))

    assert called == ["headers"]
    assert receipts[0]["status"] == "completed"
    assert receipts[0]["dispatch_adapter"] == "legacy_config_findings"
    assert receipts[0]["telemetry_schema"] == "planned_passive_attempt"
    assert receipts[0]["proof_contract"] == ["response_headers"]


def test_registry_report_phase_records_disabled_family_as_skipped():
    called = []
    plan = {"families": [{
        "name": "headers", "phase": "passive", "enabled": False, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "reason": "global_checks_skipped",
        "dispatch_adapter": "legacy_config_findings",
    }]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan, "passive", {"legacy_config_findings": lambda: called.append("headers")}
    ))

    assert called == []
    assert receipts[0]["status"] == "skipped"
    assert receipts[0]["reason"] == "global_checks_skipped"


def test_registry_report_phase_records_missing_adapter_without_running():
    plan = {"families": [{
        "name": "headers", "phase": "passive", "enabled": True, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_config_findings",
    }]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(plan, "passive", {}))

    assert receipts[0]["status"] == "blocked"
    assert receipts[0]["reason"] == "dispatch_adapter_not_registered"


def test_registry_report_phase_awaits_async_adapter():
    called = []
    plan = {"families": [{
        "name": "headers", "phase": "passive", "enabled": True, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_config_findings",
    }]}

    async def adapter():
        await asyncio.sleep(0)
        called.append("headers")

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan, "passive", {"legacy_config_findings": adapter}
    ))

    assert called == ["headers"]
    assert receipts[0]["status"] == "completed"


def test_registry_report_phase_uses_typed_adapter_outcome():
    plan = {"families": [{
        "name": "nuclei", "phase": "template", "enabled": True, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_nuclei_template",
        "telemetry_schema": "nuclei_template", "proof_contract": ["template_id"],
    }]}

    async def incomplete_nuclei():
        return scanner_mod.RegistryPhaseOutcome(
            "failed",
            "nuclei_scan_incomplete",
            {"scan_completed": False, "templates_used": 0, "findings_count": 0},
        )

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan,
        "template",
        {"legacy_nuclei_template": incomplete_nuclei},
    ))

    assert receipts == [{
        "family": "nuclei",
        "phase": "template",
        "dispatch_adapter": "legacy_nuclei_template",
        "status": "failed",
        "telemetry_schema": "nuclei_template",
        "proof_contract": ["template_id"],
        "reason": "nuclei_scan_incomplete",
        "adapter_telemetry": {
            "scan_completed": False,
            "templates_used": 0,
            "findings_count": 0,
        },
    }]


def test_registry_report_phase_rejects_invalid_typed_adapter_outcome():
    plan = {"families": [{
        "name": "nuclei", "phase": "template", "enabled": True, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_nuclei_template",
    }]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan,
        "template",
        {"legacy_nuclei_template": lambda: scanner_mod.RegistryPhaseOutcome("partial")},
    ))

    assert receipts[0]["status"] == "failed"
    assert receipts[0]["reason"] == "invalid_adapter_outcome_status:partial"


def test_registry_report_phase_blocks_adapter_contract_drift():
    plan = {"families": [{
        "name": "headers", "phase": "passive", "enabled": True, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "wrong_adapter",
    }]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan, "passive", {"wrong_adapter": lambda: None}
    ))

    assert receipts[0]["status"] == "blocked"
    assert receipts[0]["reason"] == "registry_dispatch_adapter_mismatch"


def test_registry_report_phase_records_cancellation_without_dispatch():
    called = []
    plan = {"families": [{
        "name": "headers", "phase": "passive", "enabled": True, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_config_findings",
    }]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan,
        "passive",
        {"legacy_config_findings": lambda: called.append("headers")},
        cancel_requested=lambda: True,
    ))

    assert called == []
    assert receipts[0]["status"] == "cancelled"
    assert receipts[0]["reason"] == "scanner_cancel_requested"


def test_registry_report_phase_limits_dispatch_to_explicit_family_subset():
    called = []
    plan = {"families": [
        {
            "name": "jwt", "phase": "active", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_advanced_jwt",
        },
        {
            "name": "mass_assignment", "phase": "active", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_phase4_mass_assignment",
        },
    ]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan,
        "active",
        {
            "legacy_advanced_jwt": lambda: called.append("jwt"),
            "legacy_phase4_mass_assignment": lambda: called.append("mass_assignment"),
        },
        families={"jwt"},
    ))

    assert called == ["jwt"]
    assert [receipt["family"] for receipt in receipts] == ["jwt"]


def test_registry_report_phase_runs_shared_batch_adapter_once_with_family_outcomes():
    calls = []
    plan = {"families": [
        {
            "name": "sqli", "phase": "active", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_active_loop",
        },
        {
            "name": "xss", "phase": "active", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_active_loop",
        },
    ]}

    async def active_batch(rows):
        calls.append([row["name"] for row in rows])
        return scanner_mod.RegistryPhaseBatchOutcome({
            "sqli": scanner_mod.RegistryPhaseOutcome(
                "completed", telemetry={"attempted_params_count": 3}
            ),
            "xss": scanner_mod.RegistryPhaseOutcome(
                "failed", "xss_budget_exhausted", {"attempted_params_count": 1}
            ),
        })

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan,
        "active",
        {
            "legacy_active_loop": scanner_mod.RegistryPhaseBatchAdapter(active_batch),
        },
        families={"sqli", "xss"},
    ))

    assert calls == [["sqli", "xss"]]
    assert [receipt["status"] for receipt in receipts] == ["completed", "failed"]
    assert receipts[1]["reason"] == "xss_budget_exhausted"


def test_registry_report_phase_fails_closed_when_batch_omits_family_outcome():
    plan = {"families": [
        {
            "name": "sqli", "phase": "active", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_active_loop",
        },
        {
            "name": "xss", "phase": "active", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_active_loop",
        },
    ]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan,
        "active",
        {
            "legacy_active_loop": scanner_mod.RegistryPhaseBatchAdapter(
                lambda rows: scanner_mod.RegistryPhaseBatchOutcome({
                    "sqli": scanner_mod.RegistryPhaseOutcome("completed"),
                })
            ),
        },
        families={"sqli", "xss"},
    ))

    assert receipts[0]["status"] == "completed"
    assert receipts[1]["status"] == "failed"
    assert receipts[1]["reason"] == "batch_adapter_family_outcome_missing"


def test_auth_and_bola_network_checks_are_registry_adapter_owned():
    source = Path(scanner_mod.__file__).read_text(encoding="utf-8")

    assert "auth_dispatch_decision = registry_dispatch_decision" not in source
    assert "bola_dispatch_decision = registry_dispatch_decision" not in source
    assert "async def run_asm_endpoint_batch_auth()" in source
    assert "async def run_asm_endpoint_batch_bola()" in source
    assert 'families={"auth"}' in source
    assert 'families={"bola"}' in source


def _load_reporting_module():
    import importlib.util as _ilu
    scanner_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
    spec = _ilu.spec_from_file_location(
        "shaker_reporting_under_test", os.path.join(scanner_dir, "reporting.py")
    )
    module = _ilu.module_from_spec(spec)
    added = scanner_dir not in sys.path
    if added:
        sys.path.insert(0, scanner_dir)
    try:
        spec.loader.exec_module(module)
    finally:
        if added:
            sys.path.remove(scanner_dir)
    return module


def test_emit_config_findings_is_the_host_posture_funnel():
    """emit_config_findings is the single source of host-level posture findings
    (CSP/headers/TLS/DNS). build_report gates this call on skip_global_checks so
    parallel coverage shards don't each re-emit them; if posture emission ever
    moves elsewhere this test flags that the gate has become incomplete."""
    reporting = _load_reporting_module()
    report = {
        "input": {"normalized_host": "example.com", "port": 443},
        "http": {
            "final_url": "https://example.com",
            "security_headers": {},
            "csp_evaluation": {"present": False},
        },
        "dns": {},
        "tls": {},
        "discovery": {},
        "findings": [],
    }
    reporting.emit_config_findings(report)
    titles = [f.get("title", "") for f in report["findings"]]
    assert any("CSP header missing" in t for t in titles)
    assert any("HSTS header missing" in t for t in titles)
