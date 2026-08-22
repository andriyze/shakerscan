from argparse import Namespace

from scanner.scanner_tools.discovery_policy import (
    PASSIVE_DISCOVERY_HTTP_METHODS,
    enforce_discovery_manifest_safety,
    passive_http_methods_for_scan,
)
from scanner.scanner import build_check_family_scope


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
