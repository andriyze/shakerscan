import importlib.util
import os
import sys

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


def test_check_family_scope_marks_inactive_scan():
    scope = scanner_mod.build_check_family_scope(False, active_xss=True, active_sqli=True)

    assert scope["mode"] == "inactive"
    assert scope["focused"] is False
    assert scope["families"] == []


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


def test_registry_family_enabled_drives_legacy_active_dispatch_gate():
    plan = {
        "families": [
            {"name": "xss", "enabled": False},
            {"name": "sqli", "enabled": True},
        ]
    }

    assert scanner_mod.registry_family_enabled(plan, "xss", fallback=True) is False
    assert scanner_mod.registry_family_enabled(plan, "sqli", fallback=False) is True
    assert scanner_mod.registry_family_enabled(plan, "headers", fallback=True) is True
    assert scanner_mod.registry_family_enabled(None, "xss", fallback=True) is True


def test_registry_dispatch_enabled_is_authoritative_for_explicit_family():
    plan = {
        "check_family_scope": {"requested_family": "bola"},
        "families": [
            {"name": "bola", "enabled": False},
            {"name": "auth", "enabled": True},
        ],
    }

    assert scanner_mod.registry_dispatch_enabled(plan, "bola", legacy_default=True) is False
    assert scanner_mod.registry_dispatch_enabled(plan, "auth", legacy_default=False) is True


def test_registry_dispatch_enabled_preserves_broad_legacy_default():
    plan = {
        "check_family_scope": {"requested_family": None},
        "families": [{"name": "bola", "enabled": False}],
    }

    assert scanner_mod.registry_dispatch_enabled(plan, "bola", legacy_default=True) is True
    assert scanner_mod.registry_dispatch_enabled(plan, "auth", legacy_default=False) is False


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
