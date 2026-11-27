"""The default-credential check's bounds at admission, on real PostgreSQL.

Admission runs through the real ``_execute_hunt_capability_lifecycle`` (the permission-request
harness, stopping at dispatch), so nothing is sent. The ledger is the module's own schema SQL.
Labelled doubles: the approval-receipt validator (no receipt rows), and the denied-login
resolver (no DNS). Verdicts are settled with the worker's own ``settle_attempt``.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from hunt import default_credentials as dc
from hunt import secret_try
from tests.test_hunt_permission_requests_postgres import DSN, permission_environment

pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

ACTIVE = {"active_testing": True, "allow_state_changing_http": False, "approval_receipt_id": str(uuid.uuid4()),
          "authorization_confirmed": True, "scope_receipt_id": "scope-fixture"}
BUDGET = {"max_active_actions": 200, "max_state_changing_requests": 0}


@pytest.fixture
def env(monkeypatch):
    async def not_denied(host, path, addresses=()):  # labelled double: no DNS for the deny list
        return secret_try.denied_destination(host, path, ())

    monkeypatch.setattr(secret_try, "denied_destination_resolved", not_denied)
    monkeypatch.setattr(dc, "PACE_SECONDS", 0.0)
    monkeypatch.delenv("SHAKERSCAN_HUNT_DEFAULT_CREDENTIALS", raising=False)
    for environment in permission_environment(monkeypatch):
        for _ in range(2):  # the startup migration's statement, twice: idempotent
            environment.loop.run_until_complete(environment.conn.execute(dc.HUNT_DEFAULT_CREDENTIALS_SCHEMA_SQL))
        yield environment


def run(env, coroutine):
    return env.loop.run_until_complete(coroutine)


def attempt(pair="dc-01", *, path="/hub/login", origin="https://app.example.test", **extra):
    values = {"method": "POST", "origin": origin, "path": path,
              "json_body": {"username": "", "password": ""},
              "request_bindings": [
                  {"default_credential": pair, "credential_field": "username", "body_pointer": "/username"},
                  {"default_credential": pair, "credential_field": "secret", "body_pointer": "/password"}]}
    values.update(extra)
    return values


async def rows(env, hunt):
    return [dict(row) for row in await env.conn.fetch(
        "SELECT * FROM hunt_default_credential_attempts WHERE hunt_run_id=$1 ORDER BY attempted_at, id", hunt["id"])]


async def refused(env, hunt, key, values):
    with pytest.raises(HTTPException) as caught:
        await env.call(hunt, key, values=values)
    return caught.value


async def settle(env, hunt, key, verdict):
    action_id = uuid.uuid5(uuid.UUID(str(hunt["id"])), f"hunt-capability:{key}")
    await dc.settle_attempt(env.pool, hunt_id=hunt["id"], action_id=action_id, verdict=verdict)


def test_an_attempt_is_admitted_recorded_and_each_pair_tried_once(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        assert await env.call(hunt, "default-cred-0001", values=attempt("dc-01")) == "admitted"
        [row] = await rows(env, hunt)
        assert row["pair_id"] == "dc-01" and row["verdict"] == "pending" and row["login_host"] == "app.example.test"
        assert row["action_id"] == uuid.uuid5(uuid.UUID(str(hunt["id"])), "hunt-capability:default-cred-0001")
        # Not charged as a state-changing write (the budget allows none).
        assert (await env.action(hunt, "default-cred-0001"))["status"] in {"running", "reserved"}
        await settle(env, hunt, "default-cred-0001", "rejected")
        again = await refused(env, hunt, "default-cred-0002", attempt("dc-01"))
        assert again.detail["reason_code"] == "default_credentials_invalid" and "already tried" in again.detail["message"]
        # An accepted pair may sign in again.
        assert await env.call(hunt, "default-cred-0003", values=attempt("dc-02")) == "admitted"
        await settle(env, hunt, "default-cred-0003", "accepted")
        assert await env.call(hunt, "default-cred-0004", values=attempt("dc-02")) == "admitted"
        assert [row["pair_id"] for row in await rows(env, hunt)] == ["dc-01", "dc-02", "dc-02"]

    run(env, scenario())


def test_at_most_twenty_attempts_on_one_login(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        for index, (pair_id, *_rest) in enumerate(dc.PAIRS):
            key = f"default-cred-{index:04d}"
            assert await env.call(hunt, key, values=attempt(pair_id)) == "admitted"
            await settle(env, hunt, key, "accepted" if pair_id == "dc-01" else "rejected")
        assert len(await rows(env, hunt)) == dc.MAX_ATTEMPTS_PER_LOGIN
        over = await refused(env, hunt, "default-cred-9999", attempt("dc-01"))
        assert over.detail["reason_code"] == "default_credentials_exhausted"
        assert len(await rows(env, hunt)) == dc.MAX_ATTEMPTS_PER_LOGIN

    run(env, scenario())


def test_a_lockout_sign_stops_the_check_on_that_login_for_every_hunt(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        assert await env.call(hunt, "default-cred-0001", values=attempt("dc-01")) == "admitted"
        await settle(env, hunt, "default-cred-0001", "locked")
        stopped = await refused(env, hunt, "default-cred-0002", attempt("dc-02"))
        assert stopped.detail["reason_code"] == "default_credentials_stopped"
        # Another login of the same Hunt is unaffected.
        assert await env.call(hunt, "default-cred-0003", values=attempt("dc-02", path="/admin/login")) == "admitted"
        # Another Hunt reaching the same login within the window is stopped too.
        other = await env.hunt(policy=ACTIVE, budget=BUDGET)
        later = await refused(env, other, "default-cred-0001", attempt("dc-03"))
        assert later.detail["reason_code"] == "default_credentials_stopped"
        for verdict in ("rate_limited",):
            third = await env.hunt(policy=ACTIVE, budget=BUDGET)
            assert await env.call(third, "default-cred-0001", values=attempt("dc-04", path="/portal/login")) == "admitted"
            await settle(env, third, "default-cred-0001", verdict)
            assert (await refused(env, third, "default-cred-0002", attempt("dc-05", path="/portal/login"))).detail[
                "reason_code"] == "default_credentials_stopped"

    run(env, scenario())


def test_attempts_are_paced_and_the_pace_refusal_records_nothing(env, monkeypatch):
    async def scenario():
        monkeypatch.setattr(dc, "PACE_SECONDS", 60.0)
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        assert await env.call(hunt, "default-cred-0001", values=attempt("dc-01")) == "admitted"
        paced = await refused(env, hunt, "default-cred-0002", attempt("dc-02"))
        assert paced.status_code == 429 and paced.detail["reason_code"] == "default_credentials_paced"
        assert paced.headers["Retry-After"].isdigit()
        assert len(await rows(env, hunt)) == 1 and await env.action(hunt, "default-cred-0002") is None

    run(env, scenario())


def test_logins_per_hunt_are_bounded(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        for index in range(dc.MAX_LOGINS_PER_HUNT):
            assert await env.call(hunt, f"default-cred-{index:04d}", values=attempt(path=f"/l{index}/login")) == "admitted"
        assert dc.MAX_LOGINS_PER_HUNT == 12
        over = await refused(env, hunt, "default-cred-0100", attempt(path="/one-more/login"))
        assert over.detail["reason_code"] == "default_credentials_exhausted"

    run(env, scenario())


def test_switched_off_passive_other_host_or_shared_logins_are_refused(env, monkeypatch):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        # Another host is refused by scope first; the check's own rule holds on its own as well.
        other = await refused(env, hunt, "default-cred-0001", attempt(origin="https://elsewhere.example.test"))
        assert other.detail["reason_code"] in {"scope_destination_blocked", "scope_other_host"}
        with pytest.raises(HTTPException) as own:
            await dc.admit_default_credentials(env.conn, run=hunt, values=attempt(origin="https://elsewhere.example.test"),
                                               policy=ACTIVE, context={"target": {"url": "https://app.example.test"}})
        assert own.value.detail["reason_code"] == "default_credentials_destination"
        monkeypatch.setenv("SHAKERSCAN_SECRET_TRY_DENY", "app.example.test/hub")
        shared = await refused(env, hunt, "default-cred-0002", attempt())
        assert shared.detail["reason_code"] == "default_credentials_destination"
        monkeypatch.delenv("SHAKERSCAN_SECRET_TRY_DENY")
        monkeypatch.setenv("SHAKERSCAN_HUNT_DEFAULT_CREDENTIALS", "false")
        off = await refused(env, hunt, "default-cred-0003", attempt())
        assert off.detail["reason_code"] == "default_credentials_disabled"
        monkeypatch.delenv("SHAKERSCAN_HUNT_DEFAULT_CREDENTIALS")
        passive = await env.hunt(budget=BUDGET)
        with pytest.raises(HTTPException):
            await env.call(passive, "default-cred-0001", values=attempt())
        assert await rows(env, hunt) == [] and await rows(env, passive) == []

    run(env, scenario())
