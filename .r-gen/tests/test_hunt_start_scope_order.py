"""A privileged Hunt against a target whose scope is blocked is refused for the scope.

On a deployment with ``SHAKERSCAN_PRIVATE_NETWORK_TARGETS=refuse`` a network Hunt against a
private address was told to authorize the target with ``POST /targets/{id}/authorization`` --
an instruction that can never succeed, because that endpoint refuses the same blocked scope.
The scope verdict is the more fundamental refusal, so it is answered first, with its reason.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.hunt import run_router

TARGET = str(uuid.uuid4())
REFUSAL = {
    "blocked_by": ["loopback_or_private_range"],
    "message": (
        "the target's scope is blocked: loopback_or_private_range: 10.0.0.5 is a "
        "private-network address; this deployment does not allow private-network targets "
        "outside a Lab environment. ... set SHAKERSCAN_PRIVATE_NETWORK_TARGETS=allow ..."
    ),
    "environment": "production",
}


class _Recorder:
    def __init__(self, result=None):
        self.result = result
        self.calls: list[str] = []

    async def __call__(self, target_id):
        self.calls.append(target_id)
        return self.result


class _Harness:
    def __init__(self):
        self.started: list = []
        self.standing = _Recorder(None)
        self.scope = _Recorder(REFUSAL)

    async def start(self, contract):
        self.started.append(contract)
        return {"hunt_id": "h-1", "target_id": contract.target_id, "status": "created"}

    def client(self):
        run_router.configure_hunt_run_router(
            lambda: None,
            start_handler=self.start,
            standing_authorization_resolver=self.standing,
            target_scope_refusal_resolver=self.scope,
        )
        app = FastAPI()
        app.include_router(run_router.router)
        return TestClient(app)


@pytest.fixture
def harness():
    saved = {
        name: getattr(run_router, name)
        for name in (
            "_service_provider", "_start_handler", "_metrics_provider",
            "_standing_authorization_resolver", "_target_scope_refusal_resolver",
        )
        if hasattr(run_router, name)
    }
    yield _Harness()
    for name, value in saved.items():
        setattr(run_router, name, value)
    if "_target_scope_refusal_resolver" not in saved and hasattr(run_router, "_target_scope_refusal_resolver"):
        run_router._target_scope_refusal_resolver = None


def _body(**policy):
    return {
        "schema_version": "hunt-start/v2", "target_id": TARGET, "target_kind": "network",
        "goal": "map the host", "policy": policy,
    }


def test_blocked_scope_is_refused_before_the_receipt_question(harness):
    with harness.client() as client:
        response = client.post("/hunts", json=_body(network_discovery=True, authorization_confirmed=True))
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["error"] == "target_scope_blocked"
    assert "loopback_or_private_range" in detail["blocked_by"]
    assert "SHAKERSCAN_PRIVATE_NETWORK_TARGETS" in detail["message"]
    assert "/authorization" not in detail["message"]
    assert detail["schema_version"] == "hunt-start/v2"
    assert harness.scope.calls == [TARGET]
    assert harness.started == []


def test_an_admissible_scope_still_gets_the_receipt_remedy(harness):
    harness.scope.result = None
    with harness.client() as client:
        response = client.post("/hunts", json=_body(network_discovery=True, authorization_confirmed=True))
    assert response.status_code == 422
    assert "POST /targets/{target_id}/authorization" in response.json()["detail"]["message"]
    assert harness.scope.calls == [TARGET]
    assert harness.started == []


def test_a_passive_hunt_never_evaluates_the_scope_here(harness):
    with harness.client() as client:
        response = client.post("/hunts", json={**_body(), "target_kind": "web"})
    assert response.status_code == 200, response.text
    assert harness.scope.calls == []
    assert len(harness.started) == 1


def test_a_named_receipt_is_left_to_receipt_validation(harness):
    with harness.client() as client:
        response = client.post("/hunts", json=_body(
            network_discovery=True, authorization_confirmed=True, approval_receipt_id="receipt-1",
        ))
    assert response.status_code == 200, response.text
    assert harness.scope.calls == []
    assert harness.standing.calls == []
    assert len(harness.started) == 1


def test_a_standing_receipt_is_left_to_receipt_validation(harness):
    harness.standing.result = {"approval_receipt_id": "r1", "scope_receipt_id": "s1"}
    with harness.client() as client:
        response = client.post("/hunts", json=_body(network_discovery=True, authorization_confirmed=True))
    assert response.status_code == 200, response.text
    assert harness.standing.calls == [TARGET]
    assert harness.scope.calls == []
    assert harness.started[0].policy.approval_receipt_id == "r1"
