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


def _round_one_without_injection_candidates():
    """A real round-1 continuation over a JSON-body API, without mutation authority.

    Unit fixture (no target): the shared round fixture's settled parent plan plus one spec-ingest
    POST route with a body. The compiled candidate manifest is empty, so round 1 plans no
    injection verifier, and only the plan revision names the candidate manifest.
    """
    from tests.test_continuation_rounds import _settle_round_fixture, _shared_round_fixture
    from api.scan.continuation_rounds import compile_next_continuation

    fixture = _shared_round_fixture(endpoint_count=0)
    fixture["observations"] = {"discover.spec": ({
        "kind": "discovered_route", "method": "POST", "url": "https://app.example.test/agent/run",
        "content_type": "application/json", "body_field_names": ["prompt"],
    },)}
    _settle_round_fixture(fixture)
    return compile_next_continuation(**fixture, revision_number=1)


def test_scan_explanation_says_why_an_injection_scan_had_no_candidates():
    """The read path loads the executed manifests and names the withheld body endpoints.

    As on a finished scan, the finalizer's work_manifests come from action arguments: the
    template and endpoint manifests only. The empty candidate manifest planned no verify
    action, so it is named only by the plan revision's work_manifest_references.
    """
    import json

    from tests.test_scan_explanation import _plan, _rows
    from api.scan.work_manifests import unique_work_manifest_reference_dicts

    prepared = _round_one_without_injection_candidates()
    scan_id = prepared.plan.scan_id
    stored = {manifest.manifest_id: manifest.canonical_dict() for manifest in prepared.manifests}
    kinds = {manifest.kind.value: manifest.manifest_id for manifest in prepared.manifests}
    action_refs = unique_work_manifest_reference_dicts(
        action.capability_args for action in prepared.plan.actions
    )
    revision = prepared.revision.canonical_dict()
    assert {ref["kind"] for ref in action_refs} == {"template", "endpoint"}
    assert [ref["entry_count"] for ref in revision["work_manifest_references"] if ref["kind"] == "candidate"] == [0]

    class Conn:
        def __init__(self):
            self.loaded = []

        async def fetchrow(self, query, manifest_id, scan_id_value):
            assert "FROM scan_work_manifests" in query
            assert str(scan_id_value) == scan_id
            self.loaded.append(str(manifest_id))
            content = stored.get(str(manifest_id))
            return None if content is None else {"content_json": json.dumps(content)}

    scan = {
        "id": scan_id, "status": "completed", "scan_action_plan_json": _plan(),
        "options": {"scan_policy": {
            "include_families": ["xss", "sqli"], "allow_state_changing_http": False,
        }},
        "result": {"canonical_action_execution": {
            "work_manifests": [dict(ref) for ref in action_refs],
            "plan_revision": revision,
        }},
    }
    explanation = read_router.public_scan_execution_explanation(scan, _rows())
    assert explanation["coverage"]["injection_candidates"] is None
    assert {ref["kind"] for ref in explanation["coverage"]["work_manifests"]} == {"template", "endpoint"}
    conn = Conn()
    asyncio.run(read_router.explain_injection_candidates(conn, scan, explanation))
    gap = explanation["coverage"]["injection_candidates"]
    assert gap is not None, "the candidate ref in the plan revision was ignored"
    assert gap["cause"] == "state_changing_http_not_authorized"
    assert gap["withheld_body_endpoints"] == 1
    assert set(conn.loaded) == {kinds["endpoint"], kinds["candidate"]}

    # Mutation authority held: nothing was withheld and the endpoint manifest is not read.
    scan["options"]["scan_policy"]["allow_state_changing_http"] = True
    explanation = read_router.public_scan_execution_explanation(scan, _rows())
    conn = Conn()
    asyncio.run(read_router.explain_injection_candidates(conn, scan, explanation))
    assert explanation["coverage"]["injection_candidates"]["cause"] == "no_injectable_surface"
    assert conn.loaded == [kinds["candidate"]]


def test_injection_candidate_refs_are_deduplicated_across_both_sources():
    """A ref in both coverage.work_manifests and the plan revision is loaded once."""
    import json

    from tests.test_scan_work_manifests import SCAN_ID, _agent_run_endpoints
    from api.scan.work_manifests import build_candidate_manifest

    endpoints = _agent_run_endpoints()
    candidates = build_candidate_manifest(endpoints, source_action_ids=("discover.candidates",), maximum=20)
    refs = [endpoints.reference().canonical_dict(), candidates.reference().canonical_dict()]
    stored = {manifest.manifest_id: manifest.canonical_dict() for manifest in (endpoints, candidates)}

    class Conn:
        def __init__(self):
            self.loaded: list[str] = []

        async def fetchrow(self, query, manifest_id, scan_id_value):
            self.loaded.append(str(manifest_id))
            return {"content_json": json.dumps(stored[str(manifest_id)])}

    scan = {"id": SCAN_ID, "options": {"scan_policy": {"include_families": ["sqli"]}}}
    explanation = {
        "coverage": {"work_manifests": [dict(ref, status="complete") for ref in refs]},
        "plan_revision": {"work_manifest_references": [dict(ref, status="complete") for ref in refs]},
    }
    conn = Conn()
    asyncio.run(read_router.explain_injection_candidates(conn, scan, explanation))
    assert explanation["coverage"]["injection_candidates"]["withheld_body_endpoints"] == 1
    assert sorted(conn.loaded) == sorted([endpoints.manifest_id, candidates.manifest_id])


def test_scan_detail_explains_injection_candidates_through_the_router():
    source = api_tree_source()
    assert "explain_injection_candidates as _explain_injection_candidates" in source
    assert "await _explain_injection_candidates(conn, scan, execution_explanation)" in source
