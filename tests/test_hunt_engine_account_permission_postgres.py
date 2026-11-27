"""The engine asks before it makes accounts (allow_account_creation), on real PostgreSQL.

Harness of test_hunt_grant_revocation_postgres (labelled doubles for the approval-receipt validator
and the standing authorization). A launch bound grants the request at once; without one it waits
for a person and the engine makes no account.
"""
from __future__ import annotations

import json

import pytest
from hunt.engine_account_permission import REASON_CODE, request_account_creation

from tests.test_hunt_grant_revocation_postgres import ROOMY, _preauthorize, standing  # noqa: F401 - fixture
from tests.test_hunt_permission_requests_postgres import DSN, permission_environment, run

pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")


@pytest.fixture
def env(monkeypatch):
    yield from permission_environment(monkeypatch)


def _policy(env, hunt) -> dict:
    raw = run(env, env.conn.fetchval("SELECT policy_json FROM hunt_runs WHERE id=$1", hunt["id"]))
    return json.loads(raw) if isinstance(raw, str) else dict(raw)


def test_a_launch_bound_grants_account_creation_at_once(env, standing):
    hunt = run(env, env.hunt(budget=ROOMY, policy={"active_testing": True}))
    _preauthorize(env, hunt, ["capability:account-creation"])
    assert run(env, request_account_creation(env.pool, hunt["id"], routes=["/api/Users"])) == "granted"
    policy = _policy(env, hunt)
    assert policy["allow_account_creation"] is True and policy["allow_state_changing_http"] is True
    (grant,) = run(env, env.conn.fetch(
        "SELECT * FROM hunt_permission_grants WHERE hunt_run_id=$1 AND kind='capability.enable'", hunt["id"]))
    assert grant["preauthorization_id"] is not None
    # Asked again once it is on: granted with no second request.
    assert run(env, request_account_creation(env.pool, hunt["id"])) == "granted"
    assert run(env, env.conn.fetchval(
        "SELECT count(*) FROM hunt_permission_requests WHERE hunt_run_id=$1", hunt["id"])) == 1


def test_without_a_launch_bound_the_request_waits_for_a_person(env, standing):
    hunt = run(env, env.hunt(budget=ROOMY, policy={"active_testing": True, "allow_state_changing_http": True}))
    assert run(env, request_account_creation(env.pool, hunt["id"], routes=["/register"])) == "pending"
    assert run(env, request_account_creation(env.pool, hunt["id"])) == "pending"  # the same request, once
    (request,) = run(env, env.conn.fetch(
        "SELECT * FROM hunt_permission_requests WHERE hunt_run_id=$1", hunt["id"]))
    assert request["status"] == "pending" and request["reason_code"] == REASON_CODE
    assert json.loads(request["subject_json"]) == {"capability": "http.request", "flag": "account-creation"}
    assert _policy(env, hunt).get("allow_account_creation") is not True


def test_a_finished_hunt_asks_nothing(env, standing):
    hunt = run(env, env.hunt(budget=ROOMY, policy={"active_testing": True}, status="completed"))
    assert run(env, request_account_creation(env.pool, hunt["id"])) == "unavailable"
