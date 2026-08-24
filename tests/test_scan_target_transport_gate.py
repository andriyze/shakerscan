from __future__ import annotations

from pathlib import Path

from scripts.check_scan_target_transport import (
    DEFAULT_ROOTS,
    NON_TARGET_EGRESS_ALLOWLIST,
    NON_TARGET_EGRESS_CLASSES,
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
