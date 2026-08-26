from __future__ import annotations

import asyncio
from pathlib import Path

from api.scan import read_router


ROOT = Path(__file__).resolve().parents[1]


def test_canonical_scan_read_routes_are_owned_by_native_router():
    paths = {route.path: route.name for route in read_router.router.routes}

    assert paths == {
        "/scan/contracts": "get_scan_public_contract",
        "/scan/contracts/preview": "preview_scan_contract",
        "/scans/{scan_id}/actions": "get_scan_actions",
        "/scans/{scan_id}/capabilities": "get_scan_capabilities",
        "/scans/{scan_id}/coverage": "get_scan_coverage",
        "/scans/{scan_id}/parity-artifact": "get_scan_parity_artifact",
    }


def test_primary_api_mounts_router_without_duplicate_endpoint_implementations():
    source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")

    assert "app.include_router(scan_read_router)" in source
    for path in (
        "/scan/contracts",
        "/scans/{scan_id}/actions",
        "/scans/{scan_id}/capabilities",
        "/scans/{scan_id}/coverage",
        "/scans/{scan_id}/parity-artifact",
    ):
        assert f'@app.get("{path}")' not in source


def test_family_preview_resolves_standard_active_without_ai_or_implicit_families():
    preview = asyncio.run(read_router.preview_scan_contract(
        read_router.ScanFamilyPreviewRequest(
            preset="standard_active",
            active_testing=True,
            execution_topology="single_worker",
        )
    ))

    assert preview["resolved_families"] == [
        "recon", "nuclei_passive", "xss", "sqli",
    ]
    assert preview["requested_families"] == []
    assert preview["minimum_family_quotas"] == {"xss": 1, "sqli": 1}
    assert preview["execution_topology"] == "single_worker"
    assert preview["ai_used"] is False


def test_scan_detail_reuses_router_owned_public_projection():
    source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")

    assert "PUBLIC_SCAN_ACTIONS_SQL as _PUBLIC_SCAN_ACTIONS_SQL" in source
    assert (
        "public_scan_execution_explanation as "
        "_public_scan_execution_explanation"
    ) in source
