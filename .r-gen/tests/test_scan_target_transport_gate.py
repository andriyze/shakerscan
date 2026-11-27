from __future__ import annotations

from pathlib import Path

from scripts.check_scan_target_transport import (
    DEFAULT_ROOTS,
    NON_TARGET_EGRESS_ALLOWLIST,
    NON_TARGET_EGRESS_CLASSES,
    REPOSITORY_ROOT,
    find_device_connect_site_violations,
    find_device_pin_violations,
    find_non_target_egress_allowlist_violations,
    find_target_transport_anchor_violations,
    find_violations,
)


def test_canonical_scan_modules_have_no_unreviewed_network_bypass():
    assert find_violations(DEFAULT_ROOTS) == ()
    assert find_target_transport_anchor_violations() == ()
    assert find_non_target_egress_allowlist_violations() == ()


def test_non_target_egress_is_explicitly_separate_from_target_authority():
    assert {item[2] for item in NON_TARGET_EGRESS_ALLOWLIST} == NON_TARGET_EGRESS_CLASSES
    assert all(item[2] != "target" for item in NON_TARGET_EGRESS_ALLOWLIST)
    assert all(len(item) == 3 for item in NON_TARGET_EGRESS_ALLOWLIST)


def test_transport_gate_rejects_a_new_direct_http_client(tmp_path: Path):
    bypass = tmp_path / "bypass.py"
    bypass.write_text(
        "import httpx\n\nasync def bypass():\n"
        "    async with httpx.AsyncClient() as client:\n"
        "        return await client.get('https://target.test')\n",
        encoding="utf-8",
    )

    violations = find_violations((bypass,))

    assert any("unreviewed network import httpx" in item for item in violations)
    assert any("unreviewed network call httpx.AsyncClient" in item for item in violations)


def test_device_connect_sites_are_reviewed_and_pinned():
    assert find_device_connect_site_violations() == ()
    assert find_device_pin_violations() == ()


def test_transport_gate_rejects_an_unreviewed_device_connect_site():
    """Review gap (e) of #358: the gate did not cover the device modules."""
    source = (
        "import asyncio\n\nasync def probe(host):\n"
        "    return await asyncio.open_connection(host, 80)\n"
    )
    violations = find_device_connect_site_violations({
        "scanner/scanner_tools/device_web.py": source,
        "api/devices/router.py": source,
    })
    assert len(violations) == 2
    assert all("unreviewed device connect site asyncio.open_connection in probe" in item
               for item in violations)


def test_transport_gate_requires_the_pin_before_each_api_side_device_request():
    """S1 of the #358 review: deleting either ``_pin_device_origin`` call left every test green."""
    source = (REPOSITORY_ROOT / "api" / "devices" / "router.py").read_text(encoding="utf-8")
    pin = "origin = await _pin_device_origin(device_target_id, origin)"
    assert source.count(pin) == 2
    for index in range(2):
        parts = source.split(pin)
        unpinned = pin.join(parts[:index + 1]) + "pass" + pin.join(parts[index + 1:])
        violations = find_device_pin_violations({"api/devices/router.py": unpinned})
        assert len(violations) == 1, violations
        assert ("_execute_device_capability_operation", "_verify_device_control_authorization_candidate")[
            index] in violations[0]
    late = (
        "async def send(origin):\n"
        "    await _device_request_pinned_http(connect_address=origin)\n"
        "    await _pin_device_origin(1, origin)\n"
    )
    assert find_device_pin_violations({"api/devices/router.py": late})
