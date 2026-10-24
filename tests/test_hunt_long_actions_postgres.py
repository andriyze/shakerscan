"""A Hunt has at most two long actions in flight, on real PostgreSQL.

The agent-tool worker runs three jobs at once and a long action (a verifier, a template or port
scan) in at most two of them, so a short call always finds a worker. Admission keeps one Hunt
within that: a third long action while two hold live reservations is refused with
``long_actions_in_flight`` (429), reserving and recording nothing, so the same key is sent again
once one settles; a short call is admitted meanwhile; a settled or expired hold does not count.

Admission runs through the real ``_execute_hunt_capability_lifecycle`` up to dispatch (the
``env`` fixture of test_hunt_permission_requests_postgres, with its labelled doubles: the
approval-receipt validator, the standing-authorization lookup and the audit redactor).
"""
from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from tests.test_hunt_permission_requests_postgres import (
    DSN,
    permission_environment,
    run,
)

pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

ACTIVE = {"active_testing": True, "approval_receipt_id": "approval-fixture",
          "scope_receipt_id": "scope-fixture", "authorization_confirmed": True}
CALLS = {
    "xss.verify": {"path": "/search?q=1"},
    "templates.scan": {"path": "/"},
    "sqli.verify": {"path": "/item?id=1"},
}


@pytest.fixture
def env(monkeypatch):
    yield from permission_environment(monkeypatch)


def _action_id(hunt, key):
    return str(uuid.uuid5(uuid.UUID(str(hunt["id"])), f"hunt-capability:{key}"))


async def _live_holds(env, hunt):
    return await env.conn.fetch(
        """SELECT capability_name, action_id FROM budget_reservations
           WHERE owner_id=$1 AND status IN ('reserved','running') ORDER BY created_at""",
        str(hunt["id"]),
    )


def test_a_third_long_action_waits_for_one_to_settle_and_short_calls_still_run(env):
    hunt = run(env, env.hunt(profile="balanced", budget={"max_active_actions": 50}, policy=ACTIVE,
                             capabilities=tuple(CALLS)))
    assert run(env, env.call(hunt, "long-0001", name="xss.verify", values=CALLS["xss.verify"])) == "admitted"
    assert run(env, env.call(hunt, "long-0002", name="templates.scan", values=CALLS["templates.scan"])) == "admitted"

    used_before = run(env, env.run(hunt))["budget_used_json"]
    with pytest.raises(HTTPException) as refused:
        run(env, env.call(hunt, "long-0003", name="sqli.verify", values=CALLS["sqli.verify"]))
    assert refused.value.status_code == 429 and refused.value.headers == {"Retry-After": "60"}
    detail = refused.value.detail
    assert detail["reason_code"] == "long_actions_in_flight"
    assert [item["capability_name"] for item in detail["in_flight"]] == ["xss.verify", "templates.scan"]
    assert {item["action_id"] for item in detail["in_flight"]} == {
        _action_id(hunt, "long-0001"), _action_id(hunt, "long-0002")}
    # Nothing reserved, recorded or charged for the refused call.
    assert run(env, env.action(hunt, "long-0003")) is None
    assert len(run(env, _live_holds(env, hunt))) == 2
    assert run(env, env.run(hunt))["budget_used_json"] == used_before

    # A short call is admitted while both long actions are in flight.
    assert run(env, env.call(hunt, "short-0001")) == "admitted"

    # Once one settles, the same key is admitted.
    run(env, env.conn.execute(
        """UPDATE budget_reservations SET status='released', lease_expires_at=NULL,
                  finished_at=NOW() WHERE owner_id=$1 AND action_id=$2""",
        str(hunt["id"]), _action_id(hunt, "long-0001")))
    assert run(env, env.call(hunt, "long-0003", name="sqli.verify", values=CALLS["sqli.verify"])) == "admitted"

    # A hold whose lease ran out (the worker never started it) does not count either.
    with pytest.raises(HTTPException) as again:
        run(env, env.call(hunt, "long-0004", name="xss.verify", values=CALLS["xss.verify"]))
    assert again.value.detail["reason_code"] == "long_actions_in_flight"
    run(env, env.conn.execute(
        """UPDATE budget_reservations SET lease_expires_at=NOW() - interval '1 second'
           WHERE owner_id=$1 AND action_id=$2""",
        str(hunt["id"]), _action_id(hunt, "long-0002")))
    assert run(env, env.call(hunt, "long-0004", name="xss.verify", values=CALLS["xss.verify"])) == "admitted"


def test_another_hunts_long_actions_do_not_count_against_this_one(env):
    first = run(env, env.hunt(profile="balanced", budget={"max_active_actions": 50}, policy=ACTIVE,
                              capabilities=tuple(CALLS)))
    second = run(env, env.hunt(profile="balanced", budget={"max_active_actions": 50}, policy=ACTIVE,
                               capabilities=tuple(CALLS)))
    for key, name in (("first-0001", "xss.verify"), ("first-0002", "sqli.verify")):
        assert run(env, env.call(first, key, name=name, values=CALLS[name])) == "admitted"
    assert run(env, env.call(second, "second-0001", name="templates.scan", values=CALLS["templates.scan"])) == "admitted"
