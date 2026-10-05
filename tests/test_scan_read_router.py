from __future__ import annotations

import asyncio
from pathlib import Path

from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)

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
    source = api_tree_source()

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
    # Quotas are what balanced executes at the measured per-attempt cost, not a breadth promise.
    assert preview["minimum_family_quotas"] == {"xss": 4, "sqli": 4}
    assert preview["execution_topology"] == "single_worker"
    assert preview["ai_used"] is False


def test_scan_detail_reuses_router_owned_public_projection():
    source = api_tree_source()

    assert "PUBLIC_SCAN_ACTIONS_SQL as _PUBLIC_SCAN_ACTIONS_SQL" in source
    assert (
        "public_scan_execution_explanation as "
        "_public_scan_execution_explanation"
    ) in source


def test_live_scan_projection_explains_credential_interruption_from_action_records():
    from tests.test_scan_explanation import _plan, _rows, SCAN_ID

    rows = _rows()
    rows[0].update(status="blocked", reason_code="authentication_uncertain", result_json={})
    explanation = read_router.public_scan_execution_explanation(
        {"id": SCAN_ID, "status": "running", "scan_action_plan_json": _plan(), "options": {}}, rows)
    assurance = explanation["authentication_assurance"]
    assert assurance["state"] == "unknown"
    assert assurance["authentication_requested"] is True
    assert assurance["reason_code"] == "authentication_gap"
    assert assurance["interrupted_action_count"] == 1
    assert "review the identity and approval" in explanation["actions"][0]["reason"]
    rows[0].update(reason_code="timed_out", receipt_json={"redacted_execution": {
        "identity_interruption": {"reason_code": "authentication_uncertain"}}})
    explanation = read_router.public_scan_execution_explanation(
        {"id": SCAN_ID, "status": "completed", "scan_action_plan_json": _plan(), "options": {}}, rows)
    assert explanation["authentication_assurance"]["interrupted_action_count"] == 1


def test_scan_explanation_says_why_an_injection_scan_had_no_candidates():
    """The read path loads the executed manifests and names the withheld body endpoints."""
    import json

    from tests.test_scan_explanation import _plan, _rows
    from tests.test_scan_work_manifests import SCAN_ID as MANIFEST_SCAN_ID
    from tests.test_scan_work_manifests import _agent_run_endpoints
    from api.scan.work_manifests import build_candidate_manifest

    endpoints = _agent_run_endpoints()
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.candidates",), maximum=20,
    )
    stored = {
        manifest.manifest_id: manifest.canonical_dict() for manifest in (endpoints, candidates)
    }

    class Conn:
        def __init__(self):
            self.loaded = []

        async def fetchrow(self, query, manifest_id, scan_id):
            assert "FROM scan_work_manifests" in query
            assert str(scan_id) == MANIFEST_SCAN_ID
            self.loaded.append(str(manifest_id))
            content = stored.get(str(manifest_id))
            return None if content is None else {"content_json": json.dumps(content)}

    scan = {
        "id": MANIFEST_SCAN_ID, "status": "completed", "scan_action_plan_json": _plan(),
        "options": {"scan_policy": {
            "include_families": ["xss", "sqli"], "allow_state_changing_http": False,
        }},
        "result": {"canonical_action_execution": {"work_manifests": [
            endpoints.reference().canonical_dict(), candidates.reference().canonical_dict(),
        ]}},
    }
    explanation = read_router.public_scan_execution_explanation(scan, _rows())
    assert explanation["coverage"]["injection_candidates"] is None
    conn = Conn()
    asyncio.run(read_router.explain_injection_candidates(conn, scan, explanation))
    gap = explanation["coverage"]["injection_candidates"]
    assert gap["cause"] == "state_changing_http_not_authorized"
    assert gap["withheld_body_endpoints"] == 1
    assert set(conn.loaded) == {endpoints.manifest_id, candidates.manifest_id}

    # Mutation authority held: nothing was withheld and the endpoint manifest is not read.
    scan["options"]["scan_policy"]["allow_state_changing_http"] = True
    explanation = read_router.public_scan_execution_explanation(scan, _rows())
    conn = Conn()
    asyncio.run(read_router.explain_injection_candidates(conn, scan, explanation))
    assert explanation["coverage"]["injection_candidates"]["cause"] == "no_injectable_surface"
    assert conn.loaded == [candidates.manifest_id]


def test_scan_detail_explains_injection_candidates_through_the_router():
    source = api_tree_source()
    assert "explain_injection_candidates as _explain_injection_candidates" in source
    assert "await _explain_injection_candidates(conn, scan, execution_explanation)" in source
