"""Service-origin spelling never changes evidence, scope, or operator intent."""
from __future__ import annotations

import asyncio
import json
from urllib.parse import urlsplit

import pytest

from api.capabilities.authz import _public_proof_url
from api.hunt.authorization_evidence import AuthorizationWorkflowError
from api.hunt.authorization_service import AuthorizationInvestigationService
from tests import test_hunt_authorization_api as fixture


async def no_execution(*args, **kwargs):
    pytest.fail("proposing an investigation must not execute or ask for another approval")


def prepare(kind="web", *, object_origin=None, baseline_origin=None):
    pool = fixture.RelationalPool()
    pool.seed()
    pool.db.execute("UPDATE hunt_runs SET target_kind=?,policy_json=? WHERE id=?",
                    (kind, json.dumps({"active_testing": True, "network_discovery": False}), fixture.HUNT))
    pool.db.execute("UPDATE auth_sessions SET target_kind=?", (kind,))
    if kind == "device":
        pool.db.execute("UPDATE hunt_runs SET device_target_id=target_id,target_id=NULL WHERE id=?", (fixture.HUNT,))
    pool.db.execute("UPDATE http_transactions SET url=? WHERE id=?",
                    ((object_origin or fixture.ORIGIN) + "/orders/1001", fixture.CAPTURE))
    pool.db.execute("UPDATE http_transactions SET url=? WHERE id=?",
                    ((baseline_origin or object_origin or fixture.ORIGIN) + "/orders", fixture.BASELINE))
    service = AuthorizationInvestigationService(pool, no_execution, _public_proof_url)
    return pool, service


@pytest.mark.parametrize("kind", ["web", "api", "network", "device"])
@pytest.mark.parametrize("origin", ["https://fixture.example.test:8443", "http://fixture.example.test:8080"])
def test_authorized_alternate_service_proposal_preserves_real_evidence_origin(kind, origin):
    pool, service = prepare(kind, object_origin=origin)
    try:
        first = fixture.propose(service)
        second = fixture.propose(service)
        assert first["proposal_id"] == second["proposal_id"]
        row = pool.db.execute("SELECT attributes FROM application_graph_nodes").fetchone()
        proposal = json.loads(row[0])
        for key in ("public_consumer_url", "public_baseline_url"):
            value = urlsplit(proposal[key])
            expected = urlsplit(origin)
            assert (value.scheme, value.netloc) == (expected.scheme, expected.netloc)
        assert "1001" not in proposal["public_consumer_url"]
        assert not pool.db.execute("SELECT 1 FROM application_graph_nodes WHERE node_type='authorization_attempt'").fetchone()
    finally:
        pool.db.close()


@pytest.mark.parametrize("object_origin,baseline_origin", [
    (fixture.ORIGIN + ":443", fixture.ORIGIN),
    (fixture.ORIGIN, fixture.ORIGIN + ":443"),
])
def test_equivalent_default_ports_do_not_refuse_collection_baseline(object_origin, baseline_origin):
    pool, service = prepare(object_origin=object_origin, baseline_origin=baseline_origin)
    try:
        assert fixture.propose(service)["proposal_id"]
    finally:
        pool.db.close()


@pytest.mark.parametrize("origin", ["https://other.example.test", "https://fixture.example.test:0", "https://fixture.example.test:70000"])
def test_invalid_capture_service_is_actionable_422_not_internal_error(origin):
    pool, service = prepare(object_origin=origin)
    try:
        with pytest.raises(AuthorizationWorkflowError) as raised:
            fixture.propose(service)
        assert raised.value.status_code == 422
        assert not pool.db.execute("SELECT 1 FROM application_graph_nodes").fetchone()
    finally:
        pool.db.close()


def test_two_different_services_cannot_be_mistaken_for_same_service_baseline():
    pool, service = prepare(object_origin=fixture.ORIGIN + ":8443", baseline_origin=fixture.ORIGIN + ":9443")
    try:
        with pytest.raises(AuthorizationWorkflowError) as raised:
            fixture.propose(service)
        assert raised.value.status_code == 422
    finally:
        pool.db.close()
