from argparse import Namespace

from scanner.scanner_tools.discovery_policy import enforce_discovery_manifest_safety


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
