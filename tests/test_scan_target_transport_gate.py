from __future__ import annotations

from pathlib import Path

from scripts.check_scan_target_transport import DEFAULT_ROOTS, find_violations


def test_canonical_scan_modules_have_no_unreviewed_network_bypass():
    assert find_violations(DEFAULT_ROOTS) == ()


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
