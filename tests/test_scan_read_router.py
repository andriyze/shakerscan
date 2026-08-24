from __future__ import annotations

from pathlib import Path

from api.scan import read_router


ROOT = Path(__file__).resolve().parents[1]


def test_canonical_scan_read_routes_are_owned_by_native_router():
    paths = {route.path: route.name for route in read_router.router.routes}

    assert paths == {
        "/scan/contracts": "get_scan_public_contract",
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


def test_scan_detail_reuses_router_owned_public_projection():
    source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")

    assert "PUBLIC_SCAN_ACTIONS_SQL as _PUBLIC_SCAN_ACTIONS_SQL" in source
    assert (
        "public_scan_execution_explanation as "
        "_public_scan_execution_explanation"
    ) in source
