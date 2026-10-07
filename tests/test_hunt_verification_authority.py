"""Hunt candidate verification runs under the Hunt's own authority.

Regressions for the Enterprise soak of 2026-10-07 (main 96224a9d):

* D1: every ``candidate.verify`` and ``POST /hunts/{id}/candidates/{cid}/verify`` answered
  400 ``execution_feature_disabled`` (Hunts 4bab21a8, 956315ab, 8f1f3528, eea3bdab). Enterprise
  sets ``AI_OPS_ROUTER_EXECUTE_ENABLED=false`` while autonomous Hunt is off, and the web verifier
  checked that autonomous-execution switch even when a Hunt's own operator or planner asked.
"""
from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager

import pytest
from api import api as api_module
from fastapi import HTTPException
from hunt import interaction_router as router

HUNT = uuid.UUID(int=11)
CANDIDATE = uuid.UUID("7d2c5d0e-4b1a-4f6e-9a7c-3e2b1f0a9c11")
APPROVAL = str(uuid.UUID(int=14))


# --- D1: the verifier gate -------------------------------------------------------------------

class VerifierPool:
    """The first queries of the web verifier: the candidate does not exist."""

    def __init__(self):
        self.queries = []

    @asynccontextmanager
    async def acquire(self):
        yield self

    async def fetchval(self, query, *args):
        self.queries.append(query)
        if "pg_try_advisory_lock" in query:
            return True
        if "FROM investigation_candidates" in query:
            return True  # a web candidate, so the candidate verifier is used
        raise AssertionError(query)

    async def fetchrow(self, query, *args):
        self.queries.append(query)
        assert "FROM investigation_candidates" in query, query

    async def execute(self, query, *args):
        assert "pg_advisory_unlock" in query, query


@pytest.fixture
def router_switch_off(monkeypatch):
    monkeypatch.setenv("AI_OPS_ROUTER_EXECUTE_ENABLED", "false")
    pool = VerifierPool()
    monkeypatch.setattr(api_module, "db_pool", pool)
    return pool


def test_hunt_verification_does_not_depend_on_the_autonomous_execution_switch(router_switch_off):
    # The candidate is missing, so reaching the 404 proves the switch did not refuse first.
    with pytest.raises(HTTPException) as exc:
        asyncio.run(api_module._verify_suspected_finding_workflow(
            CANDIDATE, APPROVAL, created_by="hunt_v2:fixture", autonomous=False,
        ))
    assert exc.value.status_code == 404
    assert exc.value.detail == "Investigation candidate not found"


def test_a_hunt_verification_reaches_the_verifier_with_the_switch_off(router_switch_off, monkeypatch):
    # The Hunt's own path into the real api.py verifier, as candidate.verify and POST .../verify
    # take it. On the soak every call stopped here with 400 execution_feature_disabled.
    monkeypatch.setattr(
        router, "_verify_suspected_finding_workflow", api_module._verify_suspected_finding_workflow,
    )
    with pytest.raises(HTTPException) as exc:
        asyncio.run(router._execute_hunt_candidate_verification(
            run={"id": HUNT, "device_target_id": None}, context={},
            policy={"approval_receipt_id": APPROVAL}, candidate_uuid=CANDIDATE,
        ))
    assert exc.value.detail != "execution_feature_disabled"
    assert (exc.value.status_code, exc.value.detail) == (404, "Investigation candidate not found")


@pytest.mark.parametrize("verifier", [
    "_verify_web_candidate_workflow_unlocked", "_verify_suspected_finding_workflow_unlocked",
])
def test_autonomous_verification_stays_gated_by_the_switch(router_switch_off, verifier):
    # The default is autonomous: router-driven verification keeps the global off switch.
    with pytest.raises(HTTPException) as exc:
        asyncio.run(getattr(api_module, verifier)(CANDIDATE, APPROVAL, created_by="agent"))
    assert (exc.value.status_code, exc.value.detail) == (400, "execution_feature_disabled")
    assert router_switch_off.queries == []


def test_the_hunt_asks_for_verification_under_its_own_authority(monkeypatch):
    calls = []

    async def verifier(*args, **kwargs):
        calls.append(kwargs)
        raise HTTPException(status_code=422, detail="verification_route_unresolved")

    monkeypatch.setattr(router, "_verify_suspected_finding_workflow", verifier)
    run = {"id": HUNT, "device_target_id": None}
    with pytest.raises(HTTPException) as exc:
        asyncio.run(router._execute_hunt_candidate_verification(
            run=run, context={}, policy={"approval_receipt_id": APPROVAL}, candidate_uuid=CANDIDATE,
        ))
    assert calls == [{"created_by": f"hunt_v2:{HUNT}", "autonomous": False}]
    # The caller still gets the verifier's own answer.
    assert (exc.value.status_code, exc.value.detail) == (422, "verification_route_unresolved")
