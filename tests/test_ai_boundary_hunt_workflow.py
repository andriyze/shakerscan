"""One controlled-principal journey from Hunt evidence to repeatable proof."""
from __future__ import annotations

import copy
import json
from contextlib import asynccontextmanager
from uuid import UUID

import pytest

from api.ai_gate.boundary.hypothesis import materialize_boundary_contract
from api.ai_gate.boundary.runner import run_boundary_scan
from api.ai_targets import router as ai_router
from api.hunt import interaction_router as hunt_router
from tests.ai_boundary_fixtures import boundary_fixture
from tests.test_hunt_boundary_context import CANDIDATE, DB, HUNT, RUN, uid


AI_TARGET = uid(301)
SOURCE_SCAN = uid(302)
LATER_SCAN = uid(303)


def _principals(contract):
    return {
        slot: {key: contract[slot][key] for key in ("role", "subject", "tenant", "resource_id")}
        for slot in ("owner", "attacker")
    }


class AIStore:
    def __init__(self, target):
        self.target = target
        self.scans = {}
        self.readonly = []

    @asynccontextmanager
    async def acquire(self):
        yield self

    @asynccontextmanager
    async def transaction(self, **kwargs):
        self.readonly.append(kwargs)
        yield self

    async def fetchrow(self, query, *args):
        if "FROM scans" in query:
            scan_id, target_id = args
            row = self.scans.get(str(scan_id))
            return row if row and row["ai_target_id"] == str(target_id) else None
        if "FROM ai_target_credentials" in query:
            return None
        if "FROM ai_targets" in query:
            return self.target if str(args[0]) == AI_TARGET else None
        raise AssertionError(query)

    async def fetch(self, query, *_args):
        assert "FROM ai_target_principals" in query
        return []


def _stored_scan(scan_id, result, *, created_at):
    return {
        "id": scan_id, "ai_target_id": AI_TARGET, "status": "completed",
        "run_kind": "ai_api", "created_at": created_at,
        "options": {
            "ai_probe_pack": "shaker-ai-boundary", "ai_environment": "preview",
            "ai_scan_profile": "standard",
        },
        "result": result,
    }


@pytest.mark.asyncio
async def test_hunt_candidate_verification_and_later_regression_share_one_contract(monkeypatch):
    hunt_db = DB()
    hunt_db.db.execute("UPDATE investigation_candidates SET family=?, canonical_locus=?", (
        "cross_tenant_retrieval", json.dumps({"route": "/records/owner-record"}),
    ))
    hunt_db.guard()
    monkeypatch.setattr(hunt_router, "_pool", lambda: hunt_db)

    async def run_lookup(conn, hunt_id):
        assert conn is hunt_db and hunt_id == HUNT
        return RUN

    monkeypatch.setattr(hunt_router, "_hunt_run_or_404", run_lookup)

    async with boundary_fixture("vulnerable") as fixture:
        options = fixture.options()
        base = copy.deepcopy(options["ai_target"]["metadata_json"]["boundary_contract"])
        principals = _principals(base)
        request = hunt_router.HuntBoundaryHandoffRequest(**principals)
        handoff = await hunt_router.compile_hunt_candidate_boundary_proposal(
            HUNT, CANDIDATE, request,
        )
        proposal = handoff["proposal"]
        assert handoff["status"] == "ready"
        assert proposal["provenance"][0] == {"kind": "hunt_candidate", "id": CANDIDATE}
        assert handoff["verification_performed"] is False
        materialized = materialize_boundary_contract(proposal, boundary_base=base)

        target = {
            "id": AI_TARGET, "name": "Fixture agent", "target_type": "api_chat",
            "endpoint_url": options["ai_target"]["endpoint_url"], "method": "POST",
            "headers_template": {}, "request_template": options["ai_target"]["request_template"],
            "response_path": "answer", "streaming_mode": "json", "rate_limit_rps": 20,
            "token_budget": 32000, "request_budget": 64, "production_mode": False,
            "metadata_json": {}, "is_active": True,
        }
        ai_store = AIStore(target)
        monkeypatch.setattr(ai_router, "_pool", lambda: ai_store)

        async def credential_refs(*_args, **_kwargs):
            return None, []

        monkeypatch.setattr(ai_router, "_resolve_ai_gate_credential_refs", credential_refs)
        queued = {}

        async def queue(target_id, scan_request, **kwargs):
            queued.update(target_id=target_id, request=scan_request, kwargs=kwargs)
            return {"scan_id": SOURCE_SCAN, "status": "queued"}

        monkeypatch.setattr(ai_router, "_queue_ai_target_scan", queue)
        receipt = await ai_router.verify_ai_boundary_proposal(
            AI_TARGET,
            ai_router.AIBoundaryVerifyRequest(
                proposal=proposal, boundary_base=base, environment="preview",
                scan_profile="standard",
            ),
        )
        assert receipt["status"] == "queued"
        assert queued["target_id"] == AI_TARGET
        assert queued["request"].probe_pack == "shaker-ai-boundary"
        queued_contract = queued["kwargs"]["target_override"]["metadata_json"]["boundary_contract"]
        assert materialized["boundary_contract_sha256"] == (
            ai_router.materialize_boundary_contract(proposal, boundary_base=base)["boundary_contract_sha256"]
        )
        options["ai_target"]["metadata_json"]["boundary_contract"] = queued_contract

        source_result = await run_boundary_scan(options["ai_target"]["endpoint_url"], options)
        source_boundary = source_result["ai_gate"]["boundary"]
        assert source_boundary["state"] == "failed"
        assert source_boundary["contract_sha256"] == materialized["boundary_contract_sha256"]
        assert any(
            finding["verified"] and finding["proof_contract_v2"]["predicate"]["satisfied"]
            for finding in source_result["findings"]
        )
        assert all(control["passed"] for control in source_boundary["controls"])
        ai_store.scans[SOURCE_SCAN] = _stored_scan(
            SOURCE_SCAN, source_result, created_at="2026-09-25T12:00:00+00:00",
        )
        artifact = await ai_router.export_ai_boundary_regression(
            AI_TARGET, ai_router.AIBoundaryRegressionExportRequest(
                proposal=proposal, boundary_base=base, source_scan_id=SOURCE_SCAN,
            ),
        )
        assert artifact["source_boundary_state"] == "failed"
        assert artifact["execution_enabled"] is False

        fixture.mode = "secure"
        later_result = await run_boundary_scan(options["ai_target"]["endpoint_url"], options)
        assert later_result["ai_gate"]["boundary"]["state"] == "passed"
        ai_store.scans[LATER_SCAN] = _stored_scan(
            LATER_SCAN, later_result, created_at="2026-09-26T12:00:00+00:00",
        )
        evaluation = await ai_router.evaluate_ai_boundary_regression(
            AI_TARGET, ai_router.AIBoundaryRegressionEvaluateRequest(
                artifact=artifact, scan_id=LATER_SCAN,
            ),
        )
        assert evaluation["status"] == "pass"
        assert evaluation["promotion_authority"] is False
        assert ai_store.readonly == [
            {"isolation": "repeatable_read", "readonly": True},
            {"isolation": "repeatable_read", "readonly": True},
        ]
        assert all(query.lstrip().startswith("SELECT") for query in hunt_db.queries)
