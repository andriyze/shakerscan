from argparse import Namespace

import pytest

from scanner.scanner_tools.discovery_policy import (
    PASSIVE_DISCOVERY_HTTP_METHODS,
    enforce_discovery_manifest_safety,
    passive_http_methods_for_scan,
)
from scanner.scanner import (
    _apply_canonical_scan_execution,
    _reject_canonical_cli_behavior,
    _validate_canonical_scan_target,
    build_check_family_scope,
)
from api.runtime.models import ScanBudget, ScanPolicy, TargetBinding
from api.scan.execution import ScanExecutionPlan
from api.scan.executor import build_native_scan_execution


def test_discovery_manifest_removes_every_active_authority_flag():
    args = Namespace(
        discovery_manifest_only=True,
        active=True,
        xss=True,
        sqli=True,
        check_family="sqli",
        network_discovery=True,
        active_enforced=True,
    )

    assert enforce_discovery_manifest_safety(args) is True
    assert args.active is False
    assert args.xss is False
    assert args.sqli is False
    assert args.check_family is None
    assert args.network_discovery is False
    assert args.active_enforced is False


def test_normal_scan_policy_is_unchanged():
    args = Namespace(
        discovery_manifest_only=False,
        active=True,
        xss=True,
        sqli=False,
        check_family="xss",
        network_discovery=True,
        active_enforced=True,
    )

    assert enforce_discovery_manifest_safety(args) is False
    assert args.active is True
    assert args.xss is True
    assert args.check_family == "xss"


def test_discovery_and_public_modes_have_a_non_overridable_method_ceiling():
    assert passive_http_methods_for_scan(
        discovery_manifest_only=True, public_only=False,
    ) == PASSIVE_DISCOVERY_HTTP_METHODS
    assert passive_http_methods_for_scan(
        discovery_manifest_only=False, public_only=True,
    ) == PASSIVE_DISCOVERY_HTTP_METHODS
    assert passive_http_methods_for_scan(
        discovery_manifest_only=False, public_only=False,
    ) is None
    assert passive_http_methods_for_scan(
        discovery_manifest_only=False,
        public_only=False,
        allow_state_changing_http=False,
    ) == PASSIVE_DISCOVERY_HTTP_METHODS


def test_discovery_manifest_cannot_claim_active_check_families():
    scope = build_check_family_scope(
        active_checks=True,
        active_xss=True,
        active_sqli=True,
        requested_family="sqli",
        mass_assignment=True,
        jwt=True,
        bola=True,
        discovery_manifest_only=True,
    )

    assert scope["mode"] == "inactive"
    assert scope["families"] == []
    assert scope["requested_family"] is None
    assert scope["legacy_flags"] == {"xss": False, "sqli": False}


def test_scanner_applies_native_execution_without_a_legacy_preset():
    plan = ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=True,
            allow_state_changing_http=False,
            include_families=("sqli",),
            approval_receipt_id="approval-1",
        ),
        budget_profile="balanced",
        budget=ScanBudget(1200, 5000, 2000, 200, 5000, 900, 4),
    )
    execution = build_native_scan_execution(
        plan,
        {"asm_check_family": "sqli"},
        target_binding=TargetBinding(
            target_id="target-1",
            target_kind="web",
            canonical_host="example.test",
            allowed_origins=("https://example.test",),
            allowed_addresses=("192.0.2.10",),
            allowed_root_domains=("example.test",),
        ),
    ).payload()
    _validate_canonical_scan_target("https://example.test/path", execution)
    with pytest.raises(SystemExit, match="host does not match"):
        _validate_canonical_scan_target("https://other.test", execution)
    with pytest.raises(SystemExit, match="origin does not match"):
        _validate_canonical_scan_target("http://example.test", execution)
    args = Namespace(
        quick=False,
        standard=False,
        deep=False,
        full=False,
        aggressive=False,
        smart=False,
        complete=False,
        nuclei=False,
        subfinder=False,
    )

    _apply_canonical_scan_execution(args, execution)

    assert args.active is False
    assert args.active_enforced is True
    assert args.check_family is None
    assert args.vuln_auth is False
    assert args.vuln_injection is False
    assert args.vuln_web is False
    assert args.network_discovery is False
    assert args.exposure_client is False
    assert args.exposure_infra is False
    assert args.enhanced_dns is False
    assert args.deep_discovery is False
    assert args.websocket_testing is False
    assert args.budget_profile == "balanced"
    assert args.budget_request_max == 5000
    assert args.budget_max_urls == 2000
    assert args.oob_callback_url is None


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("auth_header", "Bearer secret"),
        ("auth_config_file", "/tmp/secret-auth.json"),
        ("login_password", "secret"),
        ("oauth_client_secret", "secret"),
        ("user2_cookies", "session=secret"),
        ("auto_auth", True),
        ("ai", True),
        ("ai_api_key", "provider-secret"),
    ],
)
def test_canonical_scanner_rejects_direct_auth_authority(name, value):
    args = Namespace()
    setattr(args, name, value)

    with pytest.raises(SystemExit, match=name.replace("_", "-")):
        _reject_canonical_cli_behavior(args)


def test_canonical_cli_rejects_parallel_behavior_and_budget_selectors():
    with pytest.raises(SystemExit, match="derives behavior and budgets"):
        _reject_canonical_cli_behavior(Namespace(
            active=True,
            budget_request_max=999999,
            complete_tier="safe",
            exploit_level="safe",
        ))
