"""Behavioral tests of read continuity and the materialization critical section."""
import asyncio
from contextlib import asynccontextmanager
import json
from types import SimpleNamespace

import pytest

from api.hunt import authorization_candidate as module


HUNT = "00000000-0000-0000-0000-000000000001"
TARGET = "00000000-0000-0000-0000-000000000002"
PROPOSAL = "00000000-0000-0000-0000-000000000003"
ACTION = "00000000-0000-0000-0000-000000000004"
CANDIDATE = "00000000-0000-0000-0000-000000000005"


def state():
    return {"proposal_id": PROPOSAL, "proposal_digest": "a" * 64,
            "baseline_kind": "own_object", "expected_access": "denied",
            "authorization_assessment": "potential_violation", "cross_access_observed": True,
            "selected_request_examined": True, "route": "/records/<owner-object>",
            "attempts": [{"attempt": 1, "action_id": ACTION, "receipt_id": HUNT,
                          "cross_access_observed": True, "authorization_assessment": "potential_violation",
                          "certainty": "observed", "proof_state": "inconclusive"}]}


class Store:
    def __init__(self):
        self.links = {}
        self.observations = 0
        self.lock = asyncio.Lock()

    @asynccontextmanager
    async def acquire(self):
        yield Connection(self)


class Connection:
    def __init__(self, store):
        self.store = store
        self.locked = False

    @asynccontextmanager
    async def transaction(self):
        try:
            yield self
        finally:
            if self.locked:
                self.store.lock.release()

    async def fetchrow(self, sql, *args):
        if "application_graph_nodes" in sql:
            value = self.store.links.get(args[-1])
            return {"attributes": json.dumps(value)} if value else None
        return {"id": CANDIDATE, "status": "new", "fingerprint": "f" * 64}


class Repo:
    async def run(self, conn, hunt_id):
        return {"id": hunt_id, "target_id": TARGET}

    async def proposal(self, conn, run, proposal_id, *, lock=False):
        assert str(proposal_id) == PROPOSAL
        assert lock, "the existing proposal must be locked before checking the link"
        await conn.store.lock.acquire()
        conn.locked = True
        return {}

    async def insert_node(self, conn, run, node_id, kind, key, attributes):
        conn.store.links.setdefault(key, dict(attributes))


@pytest.mark.parametrize("assessment", ["access_denied", "inconclusive"])
def test_api_read_and_nonqualifying_approval_preserve_historical_candidate(assessment, monkeypatch):
    async def exercise():
        store = Store()
        store.links[f"authz:{PROPOSAL}:candidate:{ACTION}"] = {"candidate_id": CANDIDATE}
        service = SimpleNamespace(pool=store, repo=Repo())
        current = state()
        current.update(authorization_assessment=assessment, cross_access_observed=False)
        current["attempts"].append({"attempt": 2, "action_id": TARGET, "authorization_assessment": assessment})
        for call in (module.attach_authorization_candidate, module.ensure_authorization_candidate):
            result = await call(service, HUNT, current)
            assert result["candidate"]["id"] == CANDIDATE
            assert result["candidate_relation"] == "historical_only"
            assert result["authorization_assessment"] == assessment
        assert store.observations == 0
        assert len(store.links) == 1
    asyncio.run(exercise())


def test_concurrent_materializers_recheck_link_after_entering_critical_section(monkeypatch):
    async def upsert(conn, candidate, **kwargs):
        conn.store.observations += 1
        await asyncio.sleep(0)  # Expose the old check-then-insert race deterministically.
        return {"id": CANDIDATE, "status": "new", "fingerprint": "f" * 64}

    monkeypatch.setattr(module.investigation_candidates, "upsert_candidate", upsert)
    monkeypatch.setattr(module.investigation_candidates, "normalize_candidate", lambda **kwargs: kwargs)

    async def exercise():
        store = Store()
        service = SimpleNamespace(pool=store, repo=Repo())
        results = await asyncio.gather(*(module.ensure_authorization_candidate(service, HUNT, state()) for _ in range(8)))
        assert store.observations == 1
        assert len(store.links) == 1
        assert {result["candidate"]["id"] for result in results} == {CANDIDATE}
        assert all(result["candidate_matches_latest_attempt"] for result in results)
    asyncio.run(exercise())
