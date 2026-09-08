"""All non-executing workflow responses preserve the same retained associations."""
import json

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from api.hunt.authorization_router import authorization_service, router


HUNT = "00000000-0000-0000-0000-000000000001"
TARGET = "00000000-0000-0000-0000-000000000002"
PROPOSAL = "00000000-0000-0000-0000-000000000003"
ACTION = "00000000-0000-0000-0000-000000000004"
CANDIDATE = "00000000-0000-0000-0000-000000000005"


@pytest.mark.parametrize("operation", ["read", "propose", "skip"])
def test_nonexecuting_routes_keep_a_prior_lead_after_an_inconclusive_retry(operation):
    from contextlib import asynccontextmanager

    writes = []
    class Connection:
        async def fetchrow(self, sql, *args):
            if "application_graph_nodes" in sql:
                return {"attributes": json.dumps({"candidate_id": CANDIDATE})} if args[-1].endswith(ACTION) else None
            return {"id": CANDIDATE, "status": "new", "fingerprint": "f" * 64}
        async def execute(self, *args):
            writes.append(args)
    class Pool:
        @asynccontextmanager
        async def acquire(self):
            yield Connection()
    class Repository:
        async def run(self, conn, hunt_id):
            return {"id": hunt_id, "target_id": TARGET}
    class Service:
        pool, repo = Pool(), Repository()
        async def read(self, *args, **kwargs):
            return {"hunt_id": HUNT, "proposal_id": PROPOSAL,
                "baseline_kind": "own_object", "expected_access": "denied",
                "authorization_assessment": "inconclusive", "cross_access_observed": False,
                "attempts": [{"attempt": 1, "action_id": ACTION}, {"attempt": 2, "action_id": TARGET}]}
        propose = read
        skip = read
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[authorization_service] = Service
    root = f"/hunts/{HUNT}/authorization-investigations"
    with TestClient(app) as client:
        if operation == "read":
            response = client.get(f"{root}/{PROPOSAL}")
        elif operation == "skip":
            response = client.post(f"{root}/{PROPOSAL}/skip")
        else:
            response = client.post(root, json={"capture_id": ACTION, "baseline_capture_id": TARGET,
                "primary_session_ref": HUNT, "secondary_session_ref": CANDIDATE})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["candidate"]["id"] == CANDIDATE
    assert result["candidate_relation"] == "historical_only"
    assert result["authorization_assessment"] == "inconclusive"
    assert writes == []
