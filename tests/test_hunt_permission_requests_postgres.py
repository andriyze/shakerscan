"""Hunt permission requests on real PostgreSQL: refusals, parking, grants, decisions, audit.

The Hunt tables come from db/init.sql (fresh install) and the startup migration; the budget
reservation and credential tables from their own schema SQL. Admission runs through the real
``_execute_hunt_capability_lifecycle``; the test lifecycle stops at the dispatch phase (after
admission committed), so no worker or target is involved. Labelled doubles: the approval-receipt
validator (no receipt rows exist here), the standing-authorization lookup and the destination
resolver (no DNS).
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
import uuid

import pytest
from fastapi import HTTPException

from hunt import interaction_router as router
from hunt import permission_grants, permission_subjects
from hunt.action_service import HUNT_ACTION_SERVICE, HuntActionLifecycle
from hunt.budget_amendments import HuntBudgetAmendmentRequest, apply_budget_amendment
from hunt.credential_uses import HUNT_CREDENTIAL_USES_SCHEMA_SQL, admit_action_credentials
from hunt.permission_grants import decide, revoke_grant, settle_for_ended_hunt
from hunt.permission_store import (
    HUNT_PERMISSION_SCHEMA_SQL, canonical_digest, expire_due, hunt_bounds, list_events,
    load_preauthorizations, public_preauthorization, public_request, raise_request,
    reconcile_host_encoding_if_needed, request_expiry,
)
from hunt.permission_bounds import parse_bounds
from hunt.start_contract import HUNT_BUDGET_PROFILES, normalize_hunt_start_payload
from hunt.start_permissions import record_start_permissions
from runtime.credential_store import PostgresCredentialProfileStore
from runtime.credentials import public_credential_configuration
from runtime.reservation_store import BUDGET_RESERVATION_SCHEMA_SQL

DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")
ROOT = Path(__file__).resolve().parents[1]
TARGET_URL = "https://app.example.test"


class Admitted(Exception):
    """Raised by the test lifecycle at dispatch: admission committed, nothing is dispatched."""


class StopAtDispatch(HuntActionLifecycle):
    def advance(self, phase: str) -> None:
        super().advance(phase)
        if phase == "dispatching":
            raise Admitted()


def _table(ddl: str, name: str) -> str:
    return re.search(rf"CREATE TABLE {name} \(.*?\n\);", ddl, re.S)[0]


def _permission_ddl(ddl: str) -> str:
    start = ddl.index("CREATE TABLE IF NOT EXISTS hunt_preauthorizations")
    end = ddl.index("FOR EACH ROW EXECUTE FUNCTION hunt_permission_events_append_only();") + len(
        "FOR EACH ROW EXECUTE FUNCTION hunt_permission_events_append_only();")
    return ddl[start:end]


async def _schema(conn, schema: str, *, fresh: bool = True) -> None:
    await conn.execute(f'CREATE SCHEMA "{schema}"; SET search_path TO "{schema}"')
    ddl = (ROOT / "db/init.sql").read_text()
    await conn.execute("""
        CREATE TABLE targets(id UUID PRIMARY KEY, url TEXT, name TEXT, root_domain TEXT,
                             is_active BOOLEAN NOT NULL DEFAULT true,
                             metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb);
        CREATE TABLE device_targets(id UUID PRIMARY KEY, primary_locator TEXT,
                                    is_active BOOLEAN NOT NULL DEFAULT true)""")
    await conn.execute(_table(ddl, "hunt_runs"))
    if fresh:
        await conn.execute(_table(ddl, "hunt_actions"))
        await conn.execute(_table(ddl, "hunt_credential_uses"))
        await conn.execute(_permission_ddl(ddl))
    else:  # an installation from before E2: the old action status set, no permission tables
        await conn.execute(_table(ddl, "hunt_actions").replace(
            "'reserved','running','completed','blocked','cancelled','failed','partial','awaiting_permission'",
            "'reserved','running','completed','blocked','cancelled','failed','partial'",
        ))
        await conn.execute(HUNT_CREDENTIAL_USES_SCHEMA_SQL)
    for _ in range(2):  # the startup migration, twice: idempotent
        await conn.execute(HUNT_CREDENTIAL_USES_SCHEMA_SQL)
        await conn.execute(HUNT_PERMISSION_SCHEMA_SQL)
    await conn.execute(_table(ddl, "hunt_budget_amendments"))
    await conn.execute(BUDGET_RESERVATION_SCHEMA_SQL)


class Env:
    def __init__(self, pool, conn, schema):
        self.pool, self.conn, self.schema = pool, conn, schema

    async def hunt(self, *, budget=None, used=None, policy=None, status="active", profile="fast"):
        target = uuid.uuid4()
        await self.conn.execute("INSERT INTO targets(id,url,name) VALUES($1,$2,'fixture')", target, TARGET_URL)
        resolved = dict(vars(HUNT_BUDGET_PROFILES[profile]))
        for key in ("max_state_changing_requests", "max_udp_ports", "max_tcp_ports", "max_hosts",
                    "max_oob_interactions", "max_device_fragility_points", "max_active_actions"):
            resolved[key] = 0  # a passive web Hunt, as the start contract resolves it
        resolved.update(budget or {})
        allowed = ["http.request", "web.probe", "artifact.inspect"]
        saved_policy = {
            "schema_version": "hunt-policy/v2", "target_kind": "web", "active_testing": False,
            "credential_access": False, "allow_state_changing_http": False, "network_discovery": False,
            "allow_oob_interactions": False, "allow_identity_headers": False, "allow_direct_origin": False,
            "authorization_confirmed": False, "approval_receipt_id": None, "scope_receipt_id": None,
            "budget_profile": profile, "budget": resolved, "allowed_capabilities": allowed,
            **(policy or {}),
        }
        context = {
            "schema_version": "hunt-context/v2",
            "target": {"id": str(target), "kind": "web", "url": TARGET_URL, "origins": [TARGET_URL],
                       "environment": "production"},
            "authorized_target_addresses": ["203.0.113.10"], "credential_refs": [],
            "allowed_capabilities": allowed,
            "hunt_start_contract": {"resolved_budget": resolved},
        }
        ledger = {key: 0 for key in (
            "agent_actions", "active_actions", "http_requests", "tcp_ports_attempted", "browser_actions",
            "state_changing_requests", "tool_wall_seconds", "device_fragility_points", "hosts_attempted",
            "udp_ports_attempted", "oob_interactions", "candidates", "verifications")}
        ledger.update(used or {})
        row = await self.conn.fetchrow(
            """INSERT INTO hunt_runs(target_kind,target_id,objective,status,budget_profile,policy_json,
                                     budget_json,budget_used_json,context_pack,created_by)
               VALUES('web',$1,'fixture',$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7::jsonb,'fixture') RETURNING *""",
            target, status, profile, json.dumps(saved_policy), json.dumps(resolved), json.dumps(ledger),
            json.dumps(context),
        )
        return dict(row)

    async def call(self, hunt, key, name="http.request", values=None):
        """The route's own steps: the finished-Hunt gate, then the lifecycle up to dispatch."""
        values = {"method": "GET", "path": "/"} if values is None and name == "http.request" else (values or {})
        request = router.HuntCapabilityRequest(idempotency_key=key, input=values)
        await router._require_executable_hunt_or_recorded_action(str(hunt["id"]), key)
        prepared = HUNT_ACTION_SERVICE.prepare(name, values)
        lifecycle = StopAtDispatch(specification=prepared.specification)
        lifecycle.advance("validated")
        try:
            return await router._execute_hunt_capability_lifecycle(str(hunt["id"]), name, request, lifecycle)
        except Admitted:
            return "admitted"

    async def action(self, hunt, key):
        action_id = uuid.uuid5(uuid.UUID(str(hunt["id"])), f"hunt-capability:{key}")
        row = await self.conn.fetchrow("SELECT * FROM hunt_actions WHERE id=$1", action_id)
        return dict(row) if row else None

    async def run(self, hunt):
        return dict(await self.conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1", hunt["id"]))

    async def requests(self, hunt):
        return [dict(row) for row in await self.conn.fetch(
            "SELECT * FROM hunt_permission_requests WHERE hunt_run_id=$1 ORDER BY created_at", hunt["id"])]

    async def decide(self, hunt, request, decision="allow", **body):
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                return await decide(conn, hunt["id"], request["id"], {
                    "decision": decision, "scope": body.pop("scope", "hunt"),
                    "subject_digest": body.pop("subject_digest", request["subject_digest"]),
                    "choice": body.pop("choice", {}), "idempotency_key": body.pop("key", "decision-0001"),
                    "decided_by": "alice@example.test", "decision_via": "terminal_stepup",
                })


def permission_environment(monkeypatch):
    """The ``env`` fixture's body, shared with test_hunt_grant_revocation_postgres."""
    import asyncpg

    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    schema = "hunt_perm_" + uuid.uuid4().hex
    loop = asyncio.new_event_loop()

    async def setup():
        conn = await asyncpg.connect(DSN)
        await _schema(conn, schema)
        pool = await asyncpg.create_pool(DSN, min_size=1, max_size=6, server_settings={"search_path": schema})
        return Env(pool, conn, schema)

    environment = loop.run_until_complete(setup())

    async def approval(*_args, **_kwargs):  # labelled double: no approval-receipt rows here
        return {"scope_receipt_id": "scope-fixture"}

    monkeypatch.setattr(router, "_pool", lambda: environment.pool)
    # Labelled double: the audit projection's redactor lives in the composition root.
    monkeypatch.setattr(router, "_hunt_redacted_capability_input", lambda _name, values: dict(values))
    monkeypatch.setitem(router._deps, "_validate_approval_receipt_for_action", lambda: approval)
    environment.loop = loop
    yield environment

    async def teardown():
        await environment.pool.close()
        await environment.conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await environment.conn.close()

    loop.run_until_complete(teardown())
    loop.close()


@pytest.fixture
def env(monkeypatch):
    yield from permission_environment(monkeypatch)


def run(env, coro):
    return env.loop.run_until_complete(coro)


def _detail(exc):
    return exc.value.detail if isinstance(exc.value.detail, dict) else {}


# ---------------------------------------------------------------------------------------------
# Migration.

def test_fresh_install_and_upgrade_define_the_same_permission_schema_and_status_set():
    import asyncpg

    async def scenario():
        conn = await asyncpg.connect(DSN)
        fresh, upgraded = "perm_fresh_" + uuid.uuid4().hex, "perm_up_" + uuid.uuid4().hex
        try:
            await _schema(conn, fresh, fresh=True)
            await _schema(conn, upgraded, fresh=False)

            async def definition(schema):
                return {
                    "columns": [tuple(row) for row in await conn.fetch(
                        """SELECT table_name, column_name, data_type, is_nullable, column_default
                           FROM information_schema.columns WHERE table_schema=$1
                             AND table_name IN ('hunt_permission_requests','hunt_permission_grants',
                                                'hunt_permission_events','hunt_preauthorizations',
                                                'hunt_permission_baselines')
                           ORDER BY 1, 2""", schema)],
                    "constraints": sorted(
                        row["d"] for row in await conn.fetch(
                            """SELECT r.relname || ':' || c.conname || ':' ||
                                      replace(pg_get_constraintdef(c.oid), quote_ident($1)||'.', '') AS d
                               FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace
                               JOIN pg_class r ON r.oid=c.conrelid
                               WHERE n.nspname=$1 AND r.relname ~
                                 '(hunt_permission|hunt_preauthorizations|hunt_actions|hunt_credential_uses)'""",
                            schema)
                    ),
                    "indexes": sorted(row["d"] for row in await conn.fetch(
                        """SELECT replace(indexdef, quote_ident($1)||'.', '') AS d FROM pg_indexes
                           WHERE schemaname=$1 AND tablename ~ '(hunt_permission|hunt_preauthorizations)'""",
                        schema)),
                }

            assert await definition(fresh) == await definition(upgraded)
            constraint = await conn.fetchval(
                """SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_namespace n
                   ON n.oid=c.connamespace WHERE n.nspname=$1 AND c.conname='hunt_actions_status_check'""",
                upgraded)
            assert "awaiting_permission" in constraint
            # No column of the permission tables can hold a secret or evidence.
            columns = {row[1] for row in (await definition(fresh))["columns"]}
            assert not {"secret", "headers", "cookies", "evidence", "body", "justification"} & columns
        finally:
            await conn.execute(f'DROP SCHEMA IF EXISTS "{fresh}" CASCADE; DROP SCHEMA IF EXISTS "{upgraded}" CASCADE')
            await conn.close()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------------------------
# Budget: the replay bug, the grant, and its equivalence with an amendment.

def test_budget_refusal_parks_the_action_and_a_grant_readmits_the_same_key_through_full_admission(env):
    hunt = run(env, env.hunt(budget={"max_capability_calls": 1}, used={"agent_actions": 1}))
    with pytest.raises(HTTPException) as refused:
        run(env, env.call(hunt, "budget-key-0001"))
    detail = _detail(refused)
    # Before E2 this was a failed row with error budget_exhausted:agent_actions, replayed forever.
    assert refused.value.status_code == 409 and detail["code"] == "permission_required"
    assert detail["reason_code"] == "budget_exhausted" and detail["error"] == "budget_exhausted:agent_actions"
    assert detail["permission_request"]["kind"] == "budget.raise"
    parked = run(env, env.action(hunt, "budget-key-0001"))
    assert parked["status"] == "awaiting_permission"
    assert json.loads(parked["result_summary"])["permission_request_id"] == detail["permission_request"]["id"]
    assert run(env, env.conn.fetchval("SELECT COUNT(*) FROM budget_reservations")) == 0
    stopped = run(env, env.run(hunt))
    assert stopped["status"] == "budget_exhausted" and stopped["stop_reason"] == "budget_exhausted:agent_actions"

    # Retry while pending: the same answer, nothing changes.
    with pytest.raises(HTTPException) as again:
        run(env, env.call(hunt, "budget-key-0001"))
    assert _detail(again)["permission_request"]["id"] == detail["permission_request"]["id"]
    (request,) = run(env, env.requests(hunt))
    assert request["status"] == "pending" and request["kind"] == "budget.raise"
    assert json.loads(request["subject_json"]) == {
        "dimension": "max_capability_calls", "ledger_dimension": "agent_actions", "limit": 1}

    decided = run(env, env.decide(hunt, request))
    assert decided["request"]["status"] == "granted" and decided["grant"]["kind"] == "budget.raise"
    amendment = run(env, env.conn.fetchrow("SELECT * FROM hunt_budget_amendments WHERE hunt_run_id=$1", hunt["id"]))
    assert json.loads(amendment["limits_after"])["max_capability_calls"] == 2
    assert amendment["status_before"] == "budget_exhausted" and amendment["status_after"] == "awaiting_planner"

    # The same key, the same input: re-admitted under the same action id, with a reservation.
    assert run(env, env.call(hunt, "budget-key-0001")) == "admitted"
    action = run(env, env.action(hunt, "budget-key-0001"))
    assert action["id"] == parked["id"] and action["status"] == "reserved"
    reservation = run(env, env.conn.fetchrow("SELECT * FROM budget_reservations"))
    assert reservation["action_id"] == str(parked["id"]) and reservation["status"] == "reserved"
    events = [item["event"] for item in run(env, list_events(env.conn, hunt["id"]))]
    assert events == ["requested", "decided", "used"]


def test_a_budget_grant_is_exactly_the_amendment_a_person_would_make(env):
    granted = run(env, env.hunt(budget={"max_http_requests": 1}, used={"http_requests": 1}))
    manual = run(env, env.hunt(budget={"max_http_requests": 1}, used={"http_requests": 1}))
    with pytest.raises(HTTPException):
        run(env, env.call(granted, "equivalence-0001"))
    with pytest.raises(HTTPException):
        run(env, env.call(manual, "equivalence-0001"))
    (request,) = run(env, env.requests(granted))
    run(env, env.decide(granted, request, choice={"total": 7}))

    async def amend():
        async with env.pool.acquire() as conn:
            async with conn.transaction():
                return await apply_budget_amendment(conn, manual["id"], HuntBudgetAmendmentRequest(
                    limits={"max_http_requests": 7}, expected_revision=0, idempotency_key="manual-raise",
                    operator_confirmed=True, resume=True))

    run(env, amend())
    left, right = run(env, env.run(granted)), run(env, env.run(manual))
    for column in ("budget_json", "budget_used_json", "status", "stop_reason", "budget_revision"):
        assert left[column] == right[column], column
    a = run(env, env.conn.fetchrow("SELECT * FROM hunt_budget_amendments WHERE hunt_run_id=$1", granted["id"]))
    b = run(env, env.conn.fetchrow("SELECT * FROM hunt_budget_amendments WHERE hunt_run_id=$1", manual["id"]))
    for column in ("revision", "limits_before", "limits_after", "status_before", "status_after"):
        assert a[column] == b[column], column
    assert a["request_key_sha256"] != b["request_key_sha256"]  # key permission:<request id>


def test_other_actions_continue_while_one_waits_and_the_hunt_clock_runs(env):
    # 3 HTTP requests left: a redirect-following GET reserves 1 + MAX_REDIRECT_HOPS and does not fit.
    hunt = run(env, env.hunt(budget={"max_http_requests": 5}, used={"http_requests": 2}))
    with pytest.raises(HTTPException) as refused:
        run(env, env.call(hunt, "big-0001", values={"method": "GET", "path": "/", "follow_redirects": True}))
    assert _detail(refused)["reason_code"] == "budget_insufficient_for_action"
    assert run(env, env.run(hunt))["status"] == "active"  # not exhausted: the Hunt is unchanged
    assert run(env, env.call(hunt, "small-0001")) == "admitted"
    assert run(env, env.action(hunt, "small-0001"))["status"] == "reserved"
    assert run(env, env.action(hunt, "big-0001"))["status"] == "awaiting_permission"


# ---------------------------------------------------------------------------------------------
# Dedupe, expiry, decisions.

def test_refusals_of_one_subject_share_one_pending_request_and_one_grant_unblocks_both(env):
    # Not exhausted (the Hunt stays active), so a second key reaches admission too.
    hunt = run(env, env.hunt(budget={"max_http_requests": 5}, used={"http_requests": 2}))
    big = {"method": "GET", "path": "/", "follow_redirects": True}
    for key in ("dedupe-0001", "dedupe-0002"):
        with pytest.raises(HTTPException):
            run(env, env.call(hunt, key, values=big))
    (request,) = run(env, env.requests(hunt))
    ids = {json.loads(run(env, env.action(hunt, key))["result_summary"])["permission_request_id"]
           for key in ("dedupe-0001", "dedupe-0002")}
    assert ids == {str(request["id"])}
    run(env, env.decide(hunt, request, choice={"total": 20}))
    assert run(env, env.call(hunt, "dedupe-0001", values=big)) == "admitted"
    assert run(env, env.call(hunt, "dedupe-0002", values=big)) == "admitted"


def test_an_expired_request_settles_the_parked_action_blocked_and_it_replays_blocked(env):
    hunt = run(env, env.hunt(budget={"max_capability_calls": 1}, used={"agent_actions": 1}))
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "expire-0001"))
    run(env, env.conn.execute(
        "UPDATE hunt_permission_requests SET created_at=NOW()-interval '2 days', expires_at=NOW()-interval '1 second'"))
    first = run(env, env.call(hunt, "expire-0001"))
    assert first["idempotent_replay"] is True and first["status"] == "blocked"
    summary = json.loads(run(env, env.action(hunt, "expire-0001"))["result_summary"])
    assert summary["reason_code"] == "permission_expired"
    (request,) = run(env, env.requests(hunt))
    assert request["status"] == "expired"
    assert run(env, env.call(hunt, "expire-0001"))["status"] == "blocked"  # replays as such
    assert [item["event"] for item in run(env, list_events(env.conn, hunt["id"]))] == ["requested", "expired"]


def test_request_expiry_is_24_hours_or_the_hunt_duration_deadline_whichever_is_first():
    now = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
    long_run = {"created_at": now, "budget_json": {"max_duration_seconds": 14_400 * 10}}
    assert request_expiry(long_run, now) == now + timedelta(hours=24)
    short_run = {"created_at": now - timedelta(minutes=5), "budget_json": {"max_duration_seconds": 900}}
    assert request_expiry(short_run, now) == now + timedelta(minutes=10)
    ended = {"created_at": now - timedelta(hours=1), "budget_json": {"max_duration_seconds": 900}}
    assert request_expiry(ended, now) is None  # the refusal stays plain


def test_decisions_are_replay_safe_refuse_a_stale_digest_and_never_change_once_made(env):
    hunt = run(env, env.hunt(budget={"max_capability_calls": 1}, used={"agent_actions": 1}))
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "decide-0001"))
    (request,) = run(env, env.requests(hunt))
    with pytest.raises(HTTPException) as stale:
        run(env, env.decide(hunt, request, subject_digest="0" * 64))
    assert stale.value.status_code == 409 and stale.value.detail["error"] == "permission_subject_changed"
    denied = run(env, env.decide(hunt, request, decision="deny"))
    assert denied["request"]["status"] == "denied" and denied["replayed"] is False
    again = run(env, env.decide(hunt, request, decision="deny", key="decision-0002"))
    assert again["replayed"] is True
    with pytest.raises(HTTPException) as flipped:
        run(env, env.decide(hunt, request, decision="allow", key="decision-0003"))
    assert flipped.value.status_code == 409
    assert run(env, env.call(hunt, "decide-0001"))["status"] == "blocked"
    assert json.loads(run(env, env.action(hunt, "decide-0001"))["result_summary"])["reason_code"] == "permission_denied"
    assert run(env, env.conn.fetchval("SELECT COUNT(*) FROM hunt_budget_amendments")) == 0


def test_after_a_denial_the_same_subject_is_not_asked_again_until_the_cooldown_ends(env):
    """D46: after a denial the agent raised a fresh request for the same subject 20 s later under
    a new key (A3: 7344d366 denied, then 360d5f1c). Within the cooldown the refusal now says the
    person said no and raises nothing; afterwards the subject may be asked again."""
    hunt = run(env, env.hunt())
    post = {"method": "POST", "path": "/api/v1/chat"}  # the live A3 action: a state-changing POST
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "deny-first-0001", values=post))
    (request,) = run(env, env.requests(hunt))
    run(env, env.decide(hunt, request, decision="deny"))
    with pytest.raises(HTTPException) as again:
        run(env, env.call(hunt, "deny-second-0002", values=post))
    assert len(run(env, env.requests(hunt))) == 1, "no new request for the person"
    detail = _detail(again)
    assert again.value.status_code == 403 and detail["reason_code"] == "permission_denied"
    assert str(request["id"]) in detail["message"] and "not asked again before" in detail["message"]
    assert "code" not in detail, "no permission_required: nothing is pending"
    assert run(env, env.action(hunt, "deny-second-0002"))["status"] == "blocked"
    # Once the cooldown has passed, the same subject is a question again.
    from hunt.permission_store import DENIAL_COOLDOWN

    run(env, env.conn.execute(
        "UPDATE hunt_permission_requests SET decided_at=NOW()-$2::interval WHERE id=$1",
        request["id"], DENIAL_COOLDOWN + timedelta(seconds=1)))
    with pytest.raises(HTTPException) as later:
        run(env, env.call(hunt, "deny-third-0003", values=post))
    assert _detail(later)["code"] == "permission_required"
    assert [item["status"] for item in run(env, env.requests(hunt))] == ["denied", "pending"]


def test_racing_decisions_lock_the_row_and_exactly_one_applies(env):
    hunt = run(env, env.hunt(budget={"max_capability_calls": 1}, used={"agent_actions": 1}))
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "race-0001"))
    (request,) = run(env, env.requests(hunt))

    async def race():
        return await asyncio.gather(
            env.decide(hunt, request, decision="allow", key="racer-allow"),
            env.decide(hunt, request, decision="deny", key="racer-deny"),
            return_exceptions=True,
        )

    results = run(env, race())
    applied = [item for item in results if isinstance(item, dict)]
    refused = [item for item in results if isinstance(item, HTTPException)]
    assert len(applied) == 1 and len(refused) == 1 and refused[0].status_code == 409
    events = [item for item in run(env, list_events(env.conn, hunt["id"])) if item["event"] == "decided"]
    assert len(events) == 1


def test_a_hunt_that_ends_withdraws_its_requests_and_a_later_approval_grants_nothing(env):
    hunt = run(env, env.hunt(budget={"max_capability_calls": 1}, used={"agent_actions": 1}))
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "ended-0001"))

    async def cancel():
        async with env.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("UPDATE hunt_runs SET status='cancelled', completed_at=NOW() WHERE id=$1", hunt["id"])
                await settle_for_ended_hunt(conn, hunt["id"], actor="hunt", source="hunt_cancelled")

    run(env, cancel())
    (request,) = run(env, env.requests(hunt))
    assert request["status"] == "withdrawn"
    assert run(env, env.action(hunt, "ended-0001"))["status"] == "blocked"
    with pytest.raises(HTTPException) as late:
        run(env, env.decide(hunt, request))
    assert late.value.detail["error"] == "permission_withdrawn"
    assert run(env, env.conn.fetchval("SELECT COUNT(*) FROM hunt_permission_grants")) == 0


def test_a_parked_action_never_retried_is_labelled_by_its_requests_outcome_when_the_hunt_ends(env):
    """D42: every parked action settled ``permission_withdrawn`` at the end, even when its request
    was denied or had expired (live: cda6999c, 65e6b4b6, 99f3fbe6 denied; 360d5f1c expired)."""
    from hunt.permission_admission import settle_refusal
    from hunt.permission_reasons import HuntRefusal

    hunt = run(env, env.hunt(budget={"max_capability_calls": 1}, used={"agent_actions": 1}))
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "end-granted-0001"))  # budget.raise, granted and never retried
    (budget_request,) = run(env, env.requests(hunt))
    run(env, env.decide(hunt, budget_request))
    parked = {}
    for label, capability, flag in (("denied", "xss.verify", "active-testing"),
                                    ("expired", "http.request", "state-changing"),
                                    ("pending", "web.probe", "tcp-discovery")):
        action_id = uuid.uuid4()
        with pytest.raises(HTTPException):
            run(env, settle_refusal(env.pool, hunt_id=hunt["id"], action_id=action_id, name=capability,
                                    input_summary={}, input_digest="d" * 64, refusal=HuntRefusal(
                                        "capability_requires_active_testing", "x",
                                        subject={"capability": capability, "flag": flag})))
        parked[label] = action_id
    requests = {json.loads(item["subject_json"]).get("capability"): item for item in run(env, env.requests(hunt))}
    run(env, env.decide(hunt, requests["xss.verify"], decision="deny", key="decision-deny-0001"))
    run(env, env.conn.execute(
        """UPDATE hunt_permission_requests SET created_at=NOW()-interval '2 days',
                  expires_at=NOW()-interval '1 second' WHERE id=$1""", requests["http.request"]["id"]))

    async def finish():
        async with env.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("UPDATE hunt_runs SET status='completed', completed_at=NOW() WHERE id=$1", hunt["id"])
                await settle_for_ended_hunt(conn, hunt["id"], actor="hunt", source="hunt_finished")

    run(env, finish())

    async def summary(action_id):
        row = await env.conn.fetchrow("SELECT status, result_summary FROM hunt_actions WHERE id=$1", action_id)
        assert row["status"] == "blocked"
        return json.loads(row["result_summary"])

    assert run(env, summary(parked["denied"]))["reason_code"] == "permission_denied"
    assert "denied" in run(env, summary(parked["denied"]))["message"]
    assert run(env, summary(parked["expired"]))["reason_code"] == "permission_expired"
    granted = run(env, env.action(hunt, "end-granted-0001"))
    assert granted["status"] == "blocked"
    assert json.loads(granted["result_summary"])["reason_code"] == "permission_unused"
    assert run(env, summary(parked["pending"]))["reason_code"] == "permission_withdrawn"
    statuses = {json.loads(item["subject_json"]).get("capability"): item["status"] for item in run(env, env.requests(hunt))}
    assert statuses == {None: "granted", "xss.verify": "denied", "http.request": "expired", "web.probe": "withdrawn"}


def test_a_request_outcome_without_an_ending_never_nulls_the_parked_actions_summary(env, monkeypatch):
    """D42 SQL: ``result_summary || (SELECT ...)`` is NULL when no ending matches the request's
    outcome, and the NOT NULL column then failed the whole finishing transaction. An outcome the
    endings do not name (here: the granted one, removed) leaves the summary as it was."""
    from hunt import permission_grants

    monkeypatch.setattr(permission_grants, "PARKED_ENDINGS", {
        status: ending for status, ending in permission_grants.PARKED_ENDINGS.items() if status != "granted"})
    hunt = run(env, env.hunt(budget={"max_capability_calls": 1}, used={"agent_actions": 1}))
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "end-unnamed-0001"))  # budget.raise, granted and never retried
    (request,) = run(env, env.requests(hunt))
    run(env, env.decide(hunt, request))
    before = json.loads(run(env, env.action(hunt, "end-unnamed-0001"))["result_summary"])

    async def finish():
        async with env.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("UPDATE hunt_runs SET status='completed', completed_at=NOW() WHERE id=$1", hunt["id"])
                await settle_for_ended_hunt(conn, hunt["id"], actor="hunt", source="hunt_finished")

    run(env, finish())
    action = run(env, env.action(hunt, "end-unnamed-0001"))
    assert action["status"] == "blocked"
    assert json.loads(action["result_summary"]) == before


# ---------------------------------------------------------------------------------------------
# Kinds and hard limits.

def test_a_withheld_capability_raises_capability_enable_and_the_grant_binds_standing_authority(env, monkeypatch):
    hunt = run(env, env.hunt())
    with pytest.raises(HTTPException) as refused:
        run(env, env.call(hunt, "xss-0001", name="xss.verify", values={"path": "/?q=1"}))
    detail = _detail(refused)
    # D31: not "Capability is not allowed by this Hunt policy" but what is missing.
    assert detail["reason_code"] == "capability_requires_active_testing"
    assert detail["permission_request"]["kind"] == "capability.enable"
    (request,) = run(env, env.requests(hunt))
    assert json.loads(request["subject_json"]) == {"capability": "xss.verify", "flag": "active-testing"}

    async def no_standing(_conn, _target):  # labelled double: the target was never authorized
        return None

    monkeypatch.setattr(permission_grants, "standing_authorization", no_standing)
    with pytest.raises(HTTPException) as unauthorized:
        run(env, env.decide(hunt, request))
    assert unauthorized.value.detail["error"] == "target_authorization_required"
    assert run(env, env.requests(hunt))[0]["status"] == "pending"

    approval = str(uuid.uuid4())

    async def standing(_conn, _target):  # labelled double: the target's standing authorization
        return {"approval_receipt_id": approval, "scope_receipt_id": "scope-fixture"}

    monkeypatch.setattr(permission_grants, "standing_authorization", standing)
    granted = run(env, env.decide(hunt, request))
    policy = json.loads(run(env, env.run(hunt))["policy_json"])
    assert policy["active_testing"] is True and "xss.verify" in policy["allowed_capabilities"]
    assert policy["approval_receipt_id"] == approval
    assert json.loads(run(env, env.run(hunt))["budget_json"])["max_active_actions"] == 4
    with pytest.raises(HTTPException) as remember:
        run(env, env.decide(hunt, request, scope="target", key="decision-remember"))
    assert remember.value.status_code == 409  # already granted; capability flags have no remember
    revoked = run(env, _revoke(env, hunt, granted["grant"]["id"]))
    assert revoked["grant"]["revoked_at"]
    assert json.loads(run(env, env.run(hunt))["policy_json"])["active_testing"] is False


async def _revoke(env, hunt, grant_id):
    async with env.pool.acquire() as conn:
        async with conn.transaction():
            return await revoke_grant(conn, hunt["id"], grant_id, revoked_by="alice@example.test")


def test_hard_limits_never_become_requests(env):
    hunt = run(env, env.hunt())
    # A loopback destination: hard limit, recorded, no request.
    with pytest.raises(HTTPException) as loopback:
        run(env, env.call(hunt, "hard-0001", values={"method": "GET", "path": "/", "origin": "http://127.0.0.1:8080"}))
    assert _detail(loopback)["reason_code"] == "scope_destination_blocked"
    # Another host with a credential: a credential never leaves the target.
    # An unregistered or wrong-kind capability, and an inactive target.
    with pytest.raises(HTTPException) as kind:
        run(env, env.call(hunt, "hard-0002", name="device.inspect", values={}))
    assert kind.value.status_code in {403, 404, 422}
    run(env, env.conn.execute("UPDATE targets SET is_active=false"))
    with pytest.raises(HTTPException) as inactive:
        run(env, env.call(hunt, "hard-0003"))
    assert _detail(inactive)["reason_code"] == "target_inactive"
    assert run(env, env.requests(hunt)) == []
    # D25/D35: refusals are recorded on the Hunt as blocked actions with their code.
    recorded = {
        json.loads(row["result_summary"])["reason_code"]
        for row in run(env, env.conn.fetch("SELECT result_summary FROM hunt_actions WHERE status='blocked'"))
    }
    assert {"scope_destination_blocked", "target_inactive"} <= recorded


def test_another_service_port_raises_target_authorize_and_the_grant_adds_only_that_origin(env, monkeypatch):
    hunt = run(env, env.hunt())
    values = {"method": "GET", "path": "/", "origin": "https://app.example.test:8443"}
    with pytest.raises(HTTPException) as refused:
        run(env, env.call(hunt, "port-0001", values=values))
    assert _detail(refused)["reason_code"] == "scope_other_service_port"
    (request,) = run(env, env.requests(hunt))
    subject = json.loads(request["subject_json"])
    assert subject["host"] == "app.example.test" and subject["port"] == 8443 and subject["same_host"] is True

    remembered = []

    async def authorize_target(_conn, target_id, *, approved_by):  # labelled double
        remembered.append((str(target_id), approved_by))
        return {"approval_receipt_id": "standing-1"}

    import target_authorization
    monkeypatch.setattr(target_authorization, "authorize_target", authorize_target)
    granted = run(env, env.decide(hunt, request, scope="target"))
    assert granted["grant"]["persisted_ref"] == "approval_receipt:standing-1"
    assert remembered == [(str(hunt["target_id"]), "alice@example.test")]
    assert run(env, env.call(hunt, "port-0001", values=values)) == "admitted"
    # Only that origin: another port is still refused.
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "port-0002", values={**values, "origin": "https://app.example.test:9443"}))


def test_another_host_is_resolved_and_scope_checked_before_a_request_is_raised(env, monkeypatch):
    async def resolver(url, environment):  # labelled double: no DNS in tests
        return ["93.184.216.34"]

    monkeypatch.setattr(permission_subjects, "resolve_destination_addresses", resolver)
    hunt = run(env, env.hunt())
    values = {"method": "GET", "path": "/", "origin": "https://api.example.test"}
    with pytest.raises(HTTPException) as refused:
        run(env, env.call(hunt, "host-0001", values=values))
    assert _detail(refused)["reason_code"] == "scope_other_host"
    (request,) = run(env, env.requests(hunt))
    assert json.loads(request["subject_json"])["addresses"] == ["93.184.216.34"]
    run(env, env.decide(hunt, request))
    assert run(env, env.call(hunt, "host-0001", values=values)) == "admitted"
    with pytest.raises(HTTPException) as credential:
        run(env, env.call(hunt, "host-0002", values={**values, "as_principal": "primary"}))
    assert credential.value.status_code in {403, 422}


@pytest.mark.parametrize("spelling", [
    "https://\uff45\uff56\uff49\uff4c.example.test",      # full-width "evil"
    "https://EVIL.Example.Test.",                        # case and a trailing dot
    "https://evil.example.test:443",                     # the explicit default port
    "https://e\u200bvil.example.test",                  # a zero-width space IDNA maps away
    "https://\uff25\uff36\uff29\uff2c\uff0eexample.test",  # full-width capitals and dot
])
def test_a_denied_destination_is_not_asked_again_under_another_spelling(env, monkeypatch, spelling):
    """D46 keyed the cooldown on the raw lowercased host, so after a person denied
    https://evil.example.test the agent could ask again with a full-width or mixed spelling of
    the same host. The subject, the grant and the cooldown now share the IDNA ASCII form."""
    async def resolver(url, environment):  # labelled double: no DNS in tests
        return ["93.184.216.34"]

    monkeypatch.setattr(permission_subjects, "resolve_destination_addresses", resolver)
    hunt = run(env, env.hunt())
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "idna-0001", values={"method": "GET", "path": "/", "origin": "https://evil.example.test"}))
    (request,) = run(env, env.requests(hunt))
    assert json.loads(request["subject_json"])["host"] == "evil.example.test"
    run(env, env.decide(hunt, request, decision="deny"))
    with pytest.raises(HTTPException) as again:
        run(env, env.call(hunt, "idna-0002", values={"method": "GET", "path": "/", "origin": spelling}))
    assert _detail(again)["reason_code"] == "permission_denied", spelling
    assert len(run(env, env.requests(hunt))) == 1, "no new request for the person"


def test_a_granted_destination_matches_its_other_spellings_and_shows_ascii(env, monkeypatch):
    """The request raised for a full-width spelling names the ASCII host on the approval
    screen, and the grant admits every spelling of that host."""
    async def resolver(url, environment):  # labelled double: no DNS in tests
        return ["93.184.216.34"]

    monkeypatch.setattr(permission_subjects, "resolve_destination_addresses", resolver)
    hunt = run(env, env.hunt())
    full_width = "https://\uff41\uff50\uff49.example.test"
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "idna-grant-0001", values={"method": "GET", "path": "/", "origin": full_width}))
    (request,) = run(env, env.requests(hunt))
    assert json.loads(request["subject_json"])["host"] == "api.example.test"
    from hunt.permission_store import public_request

    shown = json.dumps(public_request(request), ensure_ascii=False)
    assert "api.example.test" in shown and "\uff41" not in shown
    run(env, env.decide(hunt, request))
    for key, origin in (("idna-grant-0001", full_width), ("idna-grant-0002", "https://API.example.test.")):
        assert run(env, env.call(hunt, key, values={"method": "GET", "path": "/", "origin": origin})) == "admitted"


# ---------------------------------------------------------------------------------------------
# Pre-authorization.

def test_a_refusal_inside_the_start_bounds_is_granted_in_the_same_transaction(env):
    hunt = run(env, env.hunt(budget={"max_capability_calls": 2}, used={"agent_actions": 2}))

    async def preauthorize():
        contract = normalize_hunt_start_payload({
            "target_id": str(hunt["target_id"]), "target_kind": "web", "policy": {},
            "allow": ["budget.raise:2x"],
            "allow_asserted_by": {"person": "alice@example.test", "proof": "stepup"},
        })
        async with env.pool.acquire() as conn:
            await record_start_permissions(conn, hunt, contract, [])

    run(env, preauthorize())
    assert run(env, env.call(hunt, "preauth-0001")) == "admitted"
    (request,) = run(env, env.requests(hunt))
    assert request["status"] == "granted" and request["decision_via"] == "preauthorization"
    assert request["decided_by"] == "alice@example.test"
    grant = run(env, env.conn.fetchrow("SELECT * FROM hunt_permission_grants"))
    assert grant["preauthorization_id"] is not None
    budget = json.loads(run(env, env.run(hunt))["budget_json"])
    assert budget["max_capability_calls"] == 4  # 2x the Hunt's start limit of 2
    events = [(item["event"], item["actor"]) for item in run(env, list_events(env.conn, hunt["id"]))]
    assert events == [
        ("preauthorized", "alice@example.test"), ("requested", "agent"),
        ("auto_granted", "alice@example.test"), ("used", "agent"),
    ]


def test_bounds_from_the_mcp_start_tool_become_one_pending_request_for_the_person(env):
    hunt = run(env, env.hunt(budget={"max_capability_calls": 1}, used={"agent_actions": 1}))

    async def proposed():
        contract = normalize_hunt_start_payload({
            "target_id": str(hunt["target_id"]), "target_kind": "web", "policy": {},
            "proposed_allow": ["budget.raise:2x", "capability:state-changing"],
        })
        async with env.pool.acquire() as conn:
            await record_start_permissions(conn, hunt, contract, [])

    run(env, proposed())
    (request,) = run(env, env.requests(hunt))
    assert request["kind"] == "preauthorization" and request["status"] == "pending"
    assert run(env, env.conn.fetchval("SELECT COUNT(*) FROM hunt_preauthorizations")) == 0
    # Not yet approved: a budget refusal parks instead of auto-granting.
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "proposal-0001"))
    run(env, env.decide(hunt, request))
    preauth = run(env, env.conn.fetchrow("SELECT * FROM hunt_preauthorizations"))
    assert preauth["created_by"] == "alice@example.test" and preauth["proof"] == "request_approval"
    # The parked action's retry now falls inside the approved bounds.
    assert run(env, env.call(hunt, "proposal-0001")) == "admitted"


def test_the_start_answer_names_the_pending_proposal_and_its_approve_command(env):
    """E3: the agent learns at start which `shakerscan approve` to hand the person."""
    hunt = run(env, env.hunt(budget={"max_capability_calls": 1}, used={"agent_actions": 0}))

    async def started():
        contract = normalize_hunt_start_payload({
            "target_id": str(hunt["target_id"]), "target_kind": "web", "policy": {},
            "proposed_allow": ["budget.raise:2x"],
        })
        async with env.pool.acquire() as conn:
            return await record_start_permissions(conn, hunt, contract, [])

    answer = run(env, started())
    (pending,) = answer["pending_permission_requests"]
    assert pending["kind"] == "preauthorization"
    assert pending["approve_command"] == f"shakerscan approve {pending['id']}"

    async def without_bounds():
        contract = normalize_hunt_start_payload({"target_id": str(hunt["target_id"]), "target_kind": "web", "policy": {}})
        async with env.pool.acquire() as conn:
            return await record_start_permissions(conn, hunt, contract, [])

    assert run(env, without_bounds()) == {}


def test_a_legacy_idna2003_bound_fails_closed_and_is_offered_back_in_one_step(env, monkeypatch):
    """R3 (external release audit, 2026-10-09). v2.8.0 stored ``target.authorize:straße.example``
    as ``strasse.example`` (IDNA 2003), so a destination request for that other ASCII host was
    granted automatically. The legacy row now withholds that host bound, keeps the row's other
    bounds, and raises one re-approval request; approving it covers the intended host only."""
    async def resolver(url, environment):  # labelled double: no DNS in tests
        return ["93.184.216.34"]

    monkeypatch.setattr(permission_subjects, "resolve_destination_addresses", resolver)
    hunt = run(env, env.hunt(budget={"max_capability_calls": 2}, used={"agent_actions": 2}))
    allow = ["target.authorize:straße.example", "budget.raise:2x"]
    legacy = {"budget_multiplier": 2.0, "budget_totals": {}, "credential_targets": [],
              "target_patterns": ["strasse.example"], "capability_flags": [],
              "ssh_host_trust_first_contact": False}  # Bounds.public() exactly as v2.8.0 wrote it
    run(env, env.conn.execute(
        """UPDATE hunt_runs SET context_pack = jsonb_set(context_pack, '{hunt_start_contract,allow}', $2::jsonb)
           WHERE id=$1""", hunt["id"], json.dumps(allow)))
    run(env, env.conn.execute(
        """INSERT INTO hunt_preauthorizations(hunt_run_id, bounds_json, bounds_digest, created_by, proof)
           VALUES ($1,$2::jsonb,$3,'alice@example.test','stepup')""",
        hunt["id"], json.dumps(legacy), canonical_digest(legacy)))

    # The budget bound in the same row still stands.
    assert run(env, env.call(hunt, "legacy-budget-0001")) == "admitted"
    # The other ASCII host is no longer granted automatically.
    run(env, env.conn.execute(
        "UPDATE hunt_runs SET budget_json = jsonb_set(budget_json, '{max_capability_calls}', '100') WHERE id=$1",
        hunt["id"]))
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "legacy-dest-0001",
                          values={"method": "GET", "path": "/", "origin": "https://strasse.example"}))
    requests = {row["kind"]: row for row in run(env, env.requests(hunt))}
    destination = requests["target.authorize"]
    assert destination["status"] == "pending" and destination["decision_via"] is None
    offer = requests["preauthorization"]
    assert offer["status"] == "pending" and offer["reason_code"] == "preauthorization_reapproval"
    shown = public_request(offer)
    assert shown["approve_command"] == f"shakerscan approve {offer['id']}"
    assert "covers xn--strae-oqa.example (Unicode: straße.example)" in shown["explanation"]
    assert "strasse.example" in shown["explanation"] and "other pre-authorized bounds" in shown["effect"]
    (listed,) = [public_preauthorization(row) for row in run(env, load_preauthorizations(env.conn, hunt["id"]))]
    assert listed["host_canonicalization"] == "idna2003-legacy"
    assert listed["reapproval_required"][0]["canonical"] == "xn--strae-oqa.example"

    # One step: the person approves the offer; it is not raised again afterwards.
    run(env, env.decide(hunt, offer, key="decision-reapprove"))
    bounds, rows = run(env, hunt_bounds(env.conn, hunt["id"]))
    assert bounds.covers_target(host="xn--strae-oqa.example", port=443)
    assert not bounds.covers_target(host="strasse.example", port=443)
    assert bounds.budget_multiplier == 2.0 and len(rows) == 2
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "legacy-dest-0002",
                          values={"method": "GET", "path": "/", "origin": "https://strasse.example"}))
    assert [row["kind"] for row in run(env, env.requests(hunt))].count("preauthorization") == 1
    # The old row has nothing left to re-approve, and says which row covers it now.
    listed = {item["host_canonicalization"]: item for item in
              (public_preauthorization(row) for row in run(env, load_preauthorizations(env.conn, hunt["id"])))}
    assert listed["idna2003-legacy"]["reapproval_required"] == []
    assert listed["idna2003-legacy"]["reapproved_by"] == listed["idna2008-uts46"]["id"]


def _seed_legacy_row(env, hunt, allow, row):
    run(env, env.conn.execute(
        """UPDATE hunt_runs SET context_pack = jsonb_set(context_pack, '{hunt_start_contract,allow}', $2::jsonb)
           WHERE id=$1""", hunt["id"], json.dumps(allow)))
    run(env, env.conn.execute(
        """INSERT INTO hunt_preauthorizations(hunt_run_id, bounds_json, bounds_digest, created_by, proof)
           VALUES ($1,$2::jsonb,$3,'alice@example.test','stepup')""",
        hunt["id"], json.dumps(row), canonical_digest(row)))


def test_a_legacy_row_is_offered_back_when_read_before_any_request(env):
    """R3 review: the withheld bounds and their re-approval request appear together, on the first
    read of the Hunt's pre-authorizations, not only after an action is refused."""
    hunt = run(env, env.hunt())
    _seed_legacy_row(env, hunt, ["target.authorize:straße.example"], {
        "budget_multiplier": None, "budget_totals": {}, "credential_targets": [],
        "target_patterns": ["strasse.example"], "capability_flags": [], "ssh_host_trust_first_contact": False})
    assert run(env, env.requests(hunt)) == []
    run(env, reconcile_host_encoding_if_needed(env.conn, hunt["id"]))
    run(env, reconcile_host_encoding_if_needed(env.conn, hunt["id"]))  # idempotent
    (offer,) = run(env, env.requests(hunt))
    assert offer["reason_code"] == "preauthorization_reapproval" and offer["status"] == "pending"


def test_a_legacy_proposal_is_replaced_by_the_same_bounds_for_the_hosts_they_name(env):
    """R3 review: a proposal digested under IDNA 2003 was refused with 409 telling the person to
    approve a request that was never raised. It is now withdrawn and raised again with its IDNA
    2008/UTS #46 digest when read, so approving stays one terminal step."""
    hunt = run(env, env.hunt())
    allow = ["target.authorize:straße.example", "budget.raise:2x"]
    legacy = {"budget_multiplier": 2.0, "budget_totals": {}, "credential_targets": [],
              "target_patterns": ["strasse.example"], "capability_flags": [], "ssh_host_trust_first_contact": False}

    async def proposed():
        async with env.pool.acquire() as conn:
            async with conn.transaction():
                locked = dict(await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", hunt["id"]))
                request, _ = await raise_request(
                    conn, run=locked, kind="preauthorization", reason_code="preauthorization_proposed",
                    subject={"allow": allow, "bounds_digest": canonical_digest(legacy)},
                    actor="agent", source="proposed_allow")
                return request

    old = run(env, proposed())
    # Deciding it directly (no read first) is refused with an accurate, actionable message.
    with pytest.raises(HTTPException) as refused:
        run(env, env.decide(hunt, old, key="decision-legacy-1"))
    assert _detail(refused)["error"] == "preauthorization_reapproval_required"
    assert "xn--strae-oqa.example" in _detail(refused)["message"]
    assert "shakerscan approve" in _detail(refused)["message"]

    run(env, reconcile_host_encoding_if_needed(env.conn, hunt["id"]))
    by_id = {str(row["id"]): row for row in run(env, env.requests(hunt))}
    old_row = by_id.pop(str(old["id"]))
    (fresh,) = by_id.values()
    assert old_row["status"] == "withdrawn" and fresh["status"] == "pending"
    assert json.loads(fresh["subject_json"])["bounds_digest"] == parse_bounds(allow).digest()
    shown_old = public_request(old_row)
    assert shown_old["superseded_by"] == str(fresh["id"])
    assert shown_old["approve_command"] == f"shakerscan approve {fresh['id']}"
    assert "covers xn--strae-oqa.example (Unicode: straße.example)" in public_request(fresh)["explanation"]
    with pytest.raises(HTTPException) as again:
        run(env, env.decide(hunt, old_row, key="decision-legacy-2"))
    assert f"shakerscan approve {fresh['id']}" in _detail(again)["message"]

    run(env, env.decide(hunt, fresh, key="decision-fresh"))
    bounds, _rows = run(env, hunt_bounds(env.conn, hunt["id"]))
    assert bounds.covers_target(host="xn--strae-oqa.example", port=443)
    assert not bounds.covers_target(host="strasse.example", port=443)
    run(env, reconcile_host_encoding_if_needed(env.conn, hunt["id"]))
    assert len(run(env, env.requests(hunt))) == 2, "nothing is raised again"


def test_bound_grammar_refuses_wildcards_and_normalizes_idna():
    assert parse_bounds(["target.authorize:Bücher.example:443"]).target_patterns[0].host == "xn--bcher-kva.example"
    for bad in ("target.authorize:*", "target.authorize:*.com", "budget.raise:50x", "capability:everything",
                "ssh.exec:ls", "target.authorize:10.0.0.1"):
        with pytest.raises(ValueError):
            parse_bounds([bad])


# ---------------------------------------------------------------------------------------------
# Credentials: Hunt-only use and remember.

async def _credential_profile(conn, *, home):
    store = PostgresCredentialProfileStore()
    now = datetime.now(timezone.utc)
    profile_id = uuid.uuid4()
    await store.create_profile(
        conn, profile_id=profile_id, target_kind="web", target_id=home, name="carol",
        auth_kind="authorization_header", principal_slot="primary", principal_label="carol",
        configuration=public_credential_configuration({"auth_kind": "authorization_header"}),
        encrypted_secret="enc:fernet:fixture", encrypted_metadata="enc:fernet:metadata",
        expires_at=now + timedelta(days=1), allowed_capabilities=["http.request"],
        created_by="fixture", now=now - timedelta(minutes=1),
    )
    return profile_id


def test_a_hunt_only_credential_grant_admits_without_a_binding_and_remember_creates_the_grant(env):
    run(env, PostgresCredentialProfileStore().ensure_schema(env.conn))
    hunt = run(env, env.hunt())
    other = uuid.uuid4()
    run(env, env.conn.execute("INSERT INTO targets(id,url,name) VALUES($1,'https://other.example.test','o')", other))
    profile_id = run(env, _credential_profile(env.conn, home=other))
    context = {"credential_refs": [{
        "source": "credential_profiles", "principal_slot": "primary", "profile_id": str(profile_id),
        "profile_version": 1, "allowed_capabilities": ["http.request"],
    }]}
    stored = run(env, env.run(hunt))

    async def admit():
        async with env.pool.acquire() as conn:
            return await admit_action_credentials(
                conn, run=stored, capability="http.request",
                capability_input={"method": "GET", "path": "/", "as_principal": "primary"}, context=context)

    with pytest.raises(Exception) as refused:
        run(env, admit())
    assert getattr(refused.value, "code", None) == "credential_not_attached"

    async def raise_request():
        from hunt.permission_reasons import HuntRefusal
        from hunt.permission_admission import settle_refusal
        refusal = HuntRefusal("credential_not_attached", "not attached", subject={
            "slot": "primary", "profile_id": str(profile_id)})
        return await settle_refusal(env.pool, hunt_id=hunt["id"], action_id=uuid.uuid4(),
                                    name="http.request", input_summary={}, input_digest="d" * 64, refusal=refusal)

    with pytest.raises(HTTPException) as parked:
        run(env, raise_request())
    assert _detail(parked)["permission_request"]["kind"] == "credential.use"
    (request,) = run(env, env.requests(hunt))
    subject = json.loads(request["subject_json"])
    assert subject["home_target_id"] == str(other) and subject["profile_version"] == 1
    granted = run(env, env.decide(hunt, request))
    uses = run(env, admit())
    assert [use.source for use in uses] == [f"live_grant:{granted['grant']['id']}"]
    loaded = run(env, PostgresCredentialProfileStore().load_for_worker(
        env.conn, profile_id=profile_id, target_kind="web", target_id=hunt["target_id"],
        capability="http.request", hunt_run_id=hunt["id"]))
    assert loaded.encrypted_secret == "enc:fernet:fixture"
    assert run(env, env.conn.fetchval(
        "SELECT COUNT(*) FROM credential_profile_bindings WHERE binding_id=$1", str(hunt["target_id"]))) == 0
    run(env, _revoke(env, hunt, granted["grant"]["id"]))
    with pytest.raises(Exception):
        run(env, admit())

    # Remember: the normal credential grant, attributed to the request.
    second = run(env, env.hunt())
    second_stored = run(env, env.run(second))

    async def raise_second():
        from hunt.permission_reasons import HuntRefusal
        from hunt.permission_admission import settle_refusal
        return await settle_refusal(env.pool, hunt_id=second["id"], action_id=uuid.uuid4(),
                                    name="http.request", input_summary={}, input_digest="d" * 64,
                                    refusal=HuntRefusal("credential_not_attached", "x", subject={
                                        "slot": "primary", "profile_id": str(profile_id)}))

    with pytest.raises(HTTPException):
        run(env, raise_second())
    (second_request,) = run(env, env.requests(second))
    remembered = run(env, env.decide(second, second_request, scope="target"))
    binding = run(env, env.conn.fetchrow(
        "SELECT * FROM credential_profile_bindings WHERE binding_id=$1", str(second_stored["target_id"])))
    assert binding is not None and remembered["grant"]["persisted_ref"].startswith("credential_grant:")


def test_a_credential_request_names_the_credential_and_its_home_target_from_their_rows(env):
    """D47: the person reads the profile's name and kind and the home target's name and host,
    read from those rows when the request is raised; no secret is read or shown."""
    from hunt.permission_store import public_request

    run(env, PostgresCredentialProfileStore().ensure_schema(env.conn))
    hunt = run(env, env.hunt())
    other = uuid.uuid4()
    run(env, env.conn.execute(
        "INSERT INTO targets(id,url,name) VALUES($1,'https://juice.example.test','Juice Shop')", other))
    profile_id = run(env, _credential_profile(env.conn, home=other))

    async def raise_request():
        from hunt.permission_reasons import HuntRefusal
        from hunt.permission_admission import settle_refusal
        return await settle_refusal(env.pool, hunt_id=hunt["id"], action_id=uuid.uuid4(),
                                    name="http.request", input_summary={}, input_digest="d" * 64,
                                    refusal=HuntRefusal("credential_not_attached", "x", subject={
                                        "slot": "primary", "profile_id": str(profile_id)}))

    with pytest.raises(HTTPException) as parked:
        run(env, raise_request())
    (request,) = run(env, env.requests(hunt))
    shown = public_request(request)
    assert shown["title"] == "Use credential 'carol' (authorization_header, v1) in this Hunt"
    assert "belongs to target 'Juice Shop' (juice.example.test)" in shown["explanation"]
    assert _detail(parked)["permission_request"]["title"] == shown["title"]
    assert "enc:fernet" not in json.dumps(shown) and "enc:fernet" not in str(request["display_json"])


# ---------------------------------------------------------------------------------------------
# Audit.

def test_permission_events_are_append_only_and_go_with_the_hunt(env):
    import asyncpg

    hunt = run(env, env.hunt(budget={"max_capability_calls": 1}, used={"agent_actions": 1}))
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "audit-0001"))
    with pytest.raises(asyncpg.RaiseError):
        run(env, env.conn.execute("UPDATE hunt_permission_events SET actor='someone-else'"))
    with pytest.raises(asyncpg.RaiseError):
        run(env, env.conn.execute("DELETE FROM hunt_permission_events"))
    run(env, expire_due(env.conn, hunt["id"]))
    run(env, env.conn.execute("DELETE FROM hunt_runs WHERE id=$1", hunt["id"]))
    assert run(env, env.conn.fetchval("SELECT COUNT(*) FROM hunt_permission_events")) == 0


def test_the_routes_list_long_poll_decide_and_revoke(env):
    import httpx
    from fastapi import FastAPI

    from hunt import permission_router

    hunt = run(env, env.hunt(budget={"max_http_requests": 5}, used={"http_requests": 2}))
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "routes-0001", values={"method": "GET", "path": "/", "follow_redirects": True}))
    app = FastAPI()
    permission_router.configure_permission_router(lambda: env.pool)
    app.include_router(permission_router.router)

    async def exchange():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://fixture") as client:
            base = f"/hunts/{hunt['id']}"
            listed = (await client.get(f"{base}/permission-requests?status=pending")).json()["requests"]
            (request,) = listed
            assert request["title"] == "Raise max_http_requests for this Hunt"
            assert request["approve_command"] == f"shakerscan approve {request['id']}"
            waited = (await client.get(f"{base}/permission-requests/{request['id']}?wait_seconds=1")).json()
            assert waited["status"] == "pending" and waited["waited"] is True
            decided = await client.post(f"{base}/permission-requests/{request['id']}/decision", json={
                "decision": "allow", "subject_digest": request["subject_digest"], "choice": {"total": 20},
                "idempotency_key": "route-decision-1", "decided_by": "alice@example.test",
                "decision_via": "local_confirm",
            })
            assert decided.status_code == 200 and decided.json()["request"]["status"] == "granted"
            replay = await client.post(f"{base}/permission-requests/{request['id']}/decision", json={
                "decision": "allow", "subject_digest": request["subject_digest"], "choice": {"total": 20},
                "idempotency_key": "route-decision-1",
            })
            assert replay.status_code == 200 and replay.json()["replayed"] is True
            grants = (await client.get(f"{base}/permission-grants")).json()["grants"]
            revoke = await client.post(f"{base}/permission-grants/{grants[0]['id']}/revoke", json={})
            assert revoke.status_code == 409  # a budget raise is an amendment, not revocable
            events = (await client.get(f"{base}/permission-events")).json()["events"]
            assert [item["event"] for item in events] == ["requested", "decided"]
            assert (await client.post(f"{base}/permission-requests", json={})).status_code == 405

    run(env, exchange())
