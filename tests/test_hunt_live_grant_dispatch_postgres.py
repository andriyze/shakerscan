"""D39 on real PostgreSQL: a live-granted destination runs through admission, dispatch and the worker.

Live (plan-hunt-opencode-acceptance-673, D39): a ``target.authorize`` request for another host was
approved in the terminal, the same-key retry was re-admitted, and the worker refused it at
dispatch ("Hunt action authority rejected at dispatch: scope_invalid"); the action then sat
``reserved`` for about two minutes and blocked Hunt finish. The worker checked the granted
destination's host against the Hunt's own scope receipt, which names only the Hunt's host. The
pre-authorized path only looked healthy because that Hunt had no scope receipt bound.

These tests build a database from db/init.sql plus the installed startup migration, record a real
standing authorization, and drive the production route (``execute_hunt_capability``): admission,
the permission request, the person's decision, the same-key retry, the production enqueue and the
production worker (``process_canonical_http_capability_job``) on the same database.

Labelled doubles, and only these: Redis (an in-memory dictionary; the queue hands the job straight
to the worker), the destination DNS lookup (a fixed public address), and the socket (an httpx
MockTransport that records the pinned request and answers 200; no traffic leaves the test).
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

TARGET_URL = "https://app.example.com"
DESTINATION = "http://dest.example.net"
DESTINATION_ADDRESS = "93.184.216.34"
LEDGER = (
    "agent_actions", "active_actions", "http_requests", "tcp_ports_attempted", "browser_actions",
    "state_changing_requests", "tool_wall_seconds", "device_fragility_points", "hosts_attempted",
    "udp_ports_attempted", "oob_interactions", "candidates", "verifications",
)


class FakeRedis:
    """Labelled double: the in-memory part of Redis the enqueue, the worker and metrics use."""

    def __init__(self) -> None:
        self.values: dict[str, object] = {}

    def set(self, key, value, ex=None):
        self.values[key] = value.encode() if isinstance(value, str) else value
        return True

    def get(self, key):
        return self.values.get(key)

    def delete(self, *keys):
        return sum(self.values.pop(key, None) is not None for key in keys)

    def exists(self, *keys):
        return sum(key in self.values for key in keys)

    def expire(self, *_args, **_kwargs):
        return True

    def hset(self, key, field=None, value=None, mapping=None):
        bucket = self.values.setdefault(key, {})
        bucket.update(mapping or {field: value})
        return 1

    def hget(self, key, field):
        return (self.values.get(key) or {}).get(field)

    def hgetall(self, key):
        return dict(self.values.get(key) or {})

    def hincrby(self, key, field, amount=1):
        bucket = self.values.setdefault(key, {})
        bucket[field] = int(bucket.get(field) or 0) + amount
        return bucket[field]

    def sadd(self, key, *members):
        self.values.setdefault(key, set()).update(members)
        return len(members)

    def srem(self, key, *members):
        bucket = self.values.setdefault(key, set())
        bucket.difference_update(members)
        return len(members)

    def smembers(self, key):
        return set(self.values.get(key) or set())


async def _database():
    import asyncpg

    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    admin = await asyncpg.connect(DSN)
    name = "hunt_live_grant_" + uuid.uuid4().hex
    await admin.execute(f'CREATE DATABASE "{name}"')
    conn = await asyncpg.connect(DSN, database=name)
    await conn.execute((ROOT / "db/init.sql").read_text())
    await conn.close()
    pool = await asyncpg.create_pool(DSN, database=name, min_size=2, max_size=8)
    from retest_contract import run_schema_migrations  # the installed startup migration

    await run_schema_migrations(pool)

    async def drop():
        await pool.close()
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.close()

    return pool, drop


async def _hunt(pool, *, preauthorize: bool = False, bounds=("target.authorize:dest.example.net",),
                budget_overrides=None, used_overrides=None):
    """A passive web Hunt whose approval and scope receipts are the target's standing ones,
    as a ``capability.enable`` grant binds them (the live Hunts 36833868 and 4e48d91b)."""
    from hunt.permission_bounds import parse_bounds
    from hunt.permission_store import record_preauthorization
    from hunt.start_contract import HUNT_BUDGET_PROFILES
    from target_authorization import authorize_target

    async with pool.acquire() as conn:
        target = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", TARGET_URL)
        standing = await authorize_target(conn, target, approved_by="alice@example.test")
        budget = {**dict(vars(HUNT_BUDGET_PROFILES["fast"])), **dict(budget_overrides or {})}
        allowed = ["http.request", "web.probe"]
        policy = {
            "schema_version": "hunt-policy/v2", "target_kind": "web", "active_testing": False,
            "credential_access": False, "allow_state_changing_http": False, "network_discovery": False,
            "allow_oob_interactions": False, "allow_identity_headers": False, "allow_direct_origin": False,
            "authorization_confirmed": True, "approval_receipt_id": str(standing["approval_receipt_id"]),
            "scope_receipt_id": str(standing["scope_receipt_id"]), "budget_profile": "fast",
            "budget": budget, "allowed_capabilities": allowed,
        }
        context = {
            "schema_version": "hunt-context/v2",
            "target": {"id": str(target), "kind": "web", "url": TARGET_URL, "origins": [TARGET_URL],
                       "environment": "production"},
            "authorized_target_addresses": ["203.0.113.10"], "credential_refs": [],
            "allowed_capabilities": allowed, "hunt_start_contract": {"resolved_budget": budget},
        }
        row = await conn.fetchrow(
            """INSERT INTO hunt_runs(target_kind,target_id,objective,status,budget_profile,policy_json,
                                     budget_json,budget_used_json,context_pack,created_by,approval_receipt_id)
               VALUES('web',$1,'D39 live grant','active','fast',$2::jsonb,$3::jsonb,$4::jsonb,$5::jsonb,
                      'fixture',$6) RETURNING *""",
            target, json.dumps(policy), json.dumps(budget),
            json.dumps({**{key: 0 for key in LEDGER}, **dict(used_overrides or {})}),
            json.dumps(context), uuid.UUID(str(standing["approval_receipt_id"])),
        )
        if preauthorize:
            async with conn.transaction():
                await record_preauthorization(
                    conn, hunt_id=row["id"], bounds=parse_bounds(list(bounds)),
                    created_by="alice@example.test", proof="launch_stepup",
                )
    return dict(row), standing


@pytest.fixture
def stack(monkeypatch):
    """The production route, enqueue and worker on one database; the doubles named above."""
    import httpx
    import worker
    from hunt import interaction_router as router
    from hunt import permission_subjects

    loop = asyncio.new_event_loop()
    pool, drop = loop.run_until_complete(_database())
    redis = FakeRedis()
    wire: list[httpx.Request] = []
    before_worker: list = []

    def answer(request: httpx.Request) -> httpx.Response:
        wire.append(request)
        return httpx.Response(200, text="User-agent: *\nDisallow:\n", headers={"Content-Type": "text/plain"})

    real_client = httpx.AsyncClient

    def client(*args, **kwargs):  # labelled double: the socket; nothing leaves the test
        kwargs["transport"] = httpx.MockTransport(answer)
        return real_client(*args, **kwargs)

    workers: list[asyncio.Task] = []

    def enqueue(_redis, _queue, payload):
        async def run():
            for hook in before_worker:
                await hook(payload)
            await worker.process_canonical_http_capability_job(payload)

        workers.append(asyncio.get_running_loop().create_task(run()))

    answers = [DESTINATION_ADDRESS]

    async def destination(_url, _environment):  # labelled double: DNS answers a public address
        return list(answers)

    monkeypatch.setattr(httpx, "AsyncClient", client)
    monkeypatch.setattr(router, "_pool", lambda: pool)
    monkeypatch.setattr(router, "get_redis", lambda: redis)
    monkeypatch.setattr(router, "enqueue_job", enqueue)
    monkeypatch.setattr(router, "_hunt_redacted_capability_input", lambda _name, values: dict(values))
    monkeypatch.setitem(router._deps, "AGENT_TOOL_QUEUE_NAME", lambda: "agent-tools-fixture")
    monkeypatch.setattr(permission_subjects, "resolve_destination_addresses", destination)
    monkeypatch.setattr(worker, "db_pool", pool)
    monkeypatch.setattr(worker, "get_redis", lambda: redis)

    class Stack:
        pass

    environment = Stack()
    environment.pool, environment.loop, environment.wire = pool, loop, wire
    environment.before_worker, environment.workers = before_worker, workers
    environment.router, environment.answers = router, answers
    yield environment
    loop.run_until_complete(drop())
    loop.close()


async def _call(stack, hunt, key):
    from fastapi import HTTPException

    request = stack.router.HuntCapabilityRequest(
        idempotency_key=key, input={"method": "GET", "path": "/robots.txt", "origin": DESTINATION},
    )
    try:
        return await stack.router.execute_hunt_capability(str(hunt["id"]), "http.request", request)
    except HTTPException as exc:
        return exc
    finally:
        if stack.workers:
            await asyncio.gather(*stack.workers)


async def _decide(pool, hunt, request_id, decision="allow"):
    from hunt.permission_grants import decide

    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow("SELECT subject_digest FROM hunt_permission_requests WHERE id=$1",
                                      uuid.UUID(request_id))
            return await decide(conn, hunt["id"], uuid.UUID(request_id), {
                "decision": decision, "scope": "hunt", "subject_digest": row["subject_digest"], "choice": {},
                "idempotency_key": "approval:apv_0001:" + request_id, "decided_by": "alice@example.test",
                "decision_via": "terminal_stepup",
            })


async def _action(pool, hunt, key):
    action_id = uuid.uuid5(uuid.UUID(str(hunt["id"])), f"hunt-capability:{key}")
    async with pool.acquire() as conn:
        action = await conn.fetchrow("SELECT * FROM hunt_actions WHERE id=$1", action_id)
        reservation = await conn.fetchrow(
            "SELECT * FROM budget_reservations WHERE owner_kind='hunt' AND owner_id=$1 AND action_id=$2",
            str(hunt["id"]), str(action_id))
        run = await conn.fetchrow("SELECT budget_used_json FROM hunt_runs WHERE id=$1", hunt["id"])
    used = run["budget_used_json"]
    return (dict(action) if action else None, dict(reservation) if reservation else None,
            json.loads(used) if isinstance(used, str) else dict(used))


def _summary(action):
    value = action["result_summary"]
    return json.loads(value) if isinstance(value, str) else dict(value or {})


def test_a_destination_a_person_allowed_in_the_terminal_runs_through_the_worker(stack):
    async def scenario():
        hunt, _standing = await _hunt(stack.pool)
        refused = await _call(stack, hunt, "d39-live-grant-01")
        assert getattr(refused, "status_code", None) == 409, refused
        assert refused.detail["code"] == "permission_required"
        assert refused.detail["reason_code"] == "scope_other_host"
        request_id = refused.detail["permission_request"]["id"]
        assert stack.wire == [], "nothing is sent before the person decides"

        decided = await _decide(stack.pool, hunt, request_id)
        assert decided["request"]["status"] == "granted"
        assert decided["request"]["decision_via"] == "terminal_stepup"

        result = await _call(stack, hunt, "d39-live-grant-01")
        assert not isinstance(result, Exception), getattr(result, "detail", result)
        assert result["action_result"]["status"] == "success", result["result"]
        action, reservation, _used = await _action(stack.pool, hunt, "d39-live-grant-01")
        assert action["status"] == "completed", _summary(action)
        assert reservation["status"] == "committed"
        # The request went to the address resolved and scope-checked when the person allowed it,
        # with the destination's own Host header.
        assert len(stack.wire) == 1
        assert stack.wire[0].url.host == DESTINATION_ADDRESS
        assert stack.wire[0].headers["host"] == "dest.example.net"
        async with stack.pool.acquire() as conn:
            events = [row["event"] for row in await conn.fetch(
                "SELECT event FROM hunt_permission_events WHERE request_id=$1 ORDER BY created_at",
                uuid.UUID(request_id))]
        assert events == ["requested", "decided", "used"]

    stack.loop.run_until_complete(scenario())


def test_a_pre_authorized_destination_runs_the_same_way(stack):
    async def scenario():
        hunt, _standing = await _hunt(stack.pool, preauthorize=True)
        result = await _call(stack, hunt, "d39-preauthorized-01")
        assert not isinstance(result, Exception), getattr(result, "detail", result)
        assert result["action_result"]["status"] == "success", result["result"]
        action, reservation, _used = await _action(stack.pool, hunt, "d39-preauthorized-01")
        assert action["status"] == "completed" and reservation["status"] == "committed"
        assert [request.url.host for request in stack.wire] == [DESTINATION_ADDRESS]

    stack.loop.run_until_complete(scenario())


def test_a_granted_destination_that_now_resolves_privately_is_refused_as_a_hard_limit(stack):
    async def scenario():
        hunt, _standing = await _hunt(stack.pool)
        refused = await _call(stack, hunt, "d39-rebound-01")
        await _decide(stack.pool, hunt, refused.detail["permission_request"]["id"])
        stack.answers[:] = [DESTINATION_ADDRESS, "10.0.0.7"]
        again = await _call(stack, hunt, "d39-rebound-01")
        assert getattr(again, "status_code", None) == 403, again
        assert again.detail["reason_code"] == "scope_destination_blocked"
        assert "public addresses" in again.detail["message"]
        action, reservation, _used = await _action(stack.pool, hunt, "d39-rebound-01")
        assert action["status"] == "blocked" and reservation is None
        assert stack.wire == []

    stack.loop.run_until_complete(scenario())


@pytest.mark.parametrize("revoked", ["grant", "standing_authorization"])
def test_authority_revoked_after_admission_is_refused_at_dispatch_and_releases_its_hold_at_once(stack, revoked):
    """Admission reserved the action; before the worker ran it, the person revoked the grant or
    the target's standing authorization. The worker refuses it, and the refusal settles the
    action and releases the reservation immediately: it used to stay ``reserved`` until stale
    recovery (about two minutes), and finishing the Hunt was refused meanwhile."""
    async def scenario():
        hunt, _standing = await _hunt(stack.pool)
        refused = await _call(stack, hunt, "d39-revoked-01")
        request_id = refused.detail["permission_request"]["id"]
        decided = await _decide(stack.pool, hunt, request_id)

        async def revoke(_payload):
            from hunt.permission_grants import revoke_grant
            from target_authorization import revoke_target_authorization

            async with stack.pool.acquire() as conn:
                async with conn.transaction():
                    if revoked == "grant":
                        await revoke_grant(conn, hunt["id"], uuid.UUID(decided["grant"]["id"]),
                                           revoked_by="alice@example.test")
                    else:
                        await revoke_target_authorization(conn, hunt["target_id"], revoked_by="alice@example.test",
                                                          reason="D39 fixture")

        stack.before_worker.append(revoke)
        answer = await _call(stack, hunt, "d39-revoked-01")
        action, reservation, used = await _action(stack.pool, hunt, "d39-revoked-01")
        assert stack.wire == [], "a refused dispatch sends nothing"
        assert action["status"] == "blocked", (action["status"], _summary(action))
        summary = _summary(action)
        assert summary["reason_code"] == "dispatch_authority_rejected"
        assert summary["refusal_stage"] == "dispatch" and summary["execution_started"] is False
        assert summary["message"].startswith("Hunt action authority rejected at dispatch")
        if revoked == "standing_authorization":
            assert summary["message"].endswith("authorization_revoked")
        assert reservation["status"] == "released"
        assert all(int(used.get(key) or 0) == 0 for key in ("http_requests", "agent_actions")), used
        assert answer["action_result"]["status"] == "blocked", answer["result"]
        async with stack.pool.acquire() as conn:
            assert await conn.fetchval(
                "SELECT count(*) FROM hunt_actions WHERE hunt_run_id=$1 AND status IN ('reserved','running')",
                hunt["id"]) == 0, "nothing is left reserved to block finishing the Hunt"

    stack.loop.run_until_complete(scenario())


def test_a_denied_destination_is_not_asked_again_when_its_host_resolves_differently(stack):
    """D46 cooldown under DNS rotation: a CDN or round-robin host answers other addresses on the
    next lookup. The resolved addresses are part of the request's subject, so the cooldown keyed
    on the subject digest raised a fresh request after the person said no."""
    async def scenario():
        hunt, _standing = await _hunt(stack.pool)
        refused = await _call(stack, hunt, "d46-rotation-01")
        request_id = refused.detail["permission_request"]["id"]
        denied = await _decide(stack.pool, hunt, request_id, decision="deny")
        assert denied["request"]["status"] == "denied"
        stack.answers[:] = ["93.184.216.35", "93.184.216.36"]  # the host rotated its A records
        again = await _call(stack, hunt, "d46-rotation-02")
        assert getattr(again, "status_code", None) == 403, again
        assert again.detail["reason_code"] == "permission_denied", again.detail
        assert request_id in again.detail["message"]
        async with stack.pool.acquire() as conn:
            assert await conn.fetchval(
                "SELECT count(*) FROM hunt_permission_requests WHERE hunt_run_id=$1", hunt["id"]) == 1
        # Another port on that host is another question.
        from fastapi import HTTPException

        other = stack.router.HuntCapabilityRequest(
            idempotency_key="d46-rotation-03",
            input={"method": "GET", "path": "/robots.txt", "origin": "http://dest.example.net:8080"},
        )
        with pytest.raises(HTTPException) as asked:
            await stack.router.execute_hunt_capability(str(hunt["id"]), "http.request", other)
        assert asked.value.detail["code"] == "permission_required"
        assert stack.wire == []

    stack.loop.run_until_complete(scenario())


def test_the_denial_cooldown_keys_on_the_question_not_the_resolved_subject():
    """Unit: what stays the same question for each kind."""
    from hunt.permission_store import cooldown_identity, subject_digest

    first = {"target_id": "t", "host": "dest.example.net", "port": 80, "scheme": "http",
             "origin": "http://dest.example.net:80", "same_host": False,
             "addresses": ["93.184.216.34"], "scope_verdict": "allowed"}
    rotated = {**first, "addresses": ["93.184.216.35"], "scope_verdict": "allowed_with_warnings"}
    assert subject_digest("target.authorize", first) != subject_digest("target.authorize", rotated)
    assert cooldown_identity("target.authorize", first) == cooldown_identity("target.authorize", rotated)
    for changed in ({"port": 8080}, {"scheme": "https"}, {"host": "other.example.net"}):
        assert cooldown_identity("target.authorize", first) != cooldown_identity("target.authorize", {**first, **changed})
    credential = {"profile_id": "p1", "profile_version": 2, "home_target_id": "h", "home_host": "a.test",
                  "slot": "user_a", "consuming_target_id": "c"}
    assert cooldown_identity("credential.use", credential) == cooldown_identity(
        "credential.use", {**credential, "slot": "user_b"})
    assert cooldown_identity("credential.use", credential) != cooldown_identity(
        "credential.use", {**credential, "profile_id": "p2"})
    budget = {"dimension": "max_http_requests", "limit": 500}
    assert cooldown_identity("budget.raise", budget) != cooldown_identity("budget.raise", {**budget, "limit": 900})


def test_the_dispatch_recheck_matches_the_grant_on_scheme_host_and_port_and_its_live_row(stack):
    """The dispatch recheck matched a grant on host and pinned addresses only, so another scheme
    or port on a granted host was checked as the granted origin. It now matches the origin the
    grant names, and a grant whose row is revoked or gone is refused at dispatch."""
    from capabilities.http import granted_destination, granted_destination_target
    from hunt.dispatch_authority import HuntDispatchRejected, dispatch_scope_binding
    from hunt.target_binding import web_hunt_target

    async def scenario():
        hunt, _standing = await _hunt(stack.pool)
        refused = await _call(stack, hunt, "d39-match-01")
        decided = await _decide(stack.pool, hunt, refused.detail["permission_request"]["id"])
        async with stack.pool.acquire() as conn:
            run = dict(await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1", hunt["id"]))
        policy = json.loads(run["policy_json"]) if isinstance(run["policy_json"], str) else dict(run["policy_json"])
        context = json.loads(run["context_pack"]) if isinstance(run["context_pack"], str) else dict(run["context_pack"])
        own, _ = web_hunt_target(run, context, policy)
        granted = granted_destination(policy, DESTINATION)
        assert granted is not None

        def binding(origin):
            return granted_destination_target(own, granted, origin)

        async with stack.pool.acquire() as conn:
            matched = await dispatch_scope_binding(conn, run=run, target=binding(DESTINATION), target_url=TARGET_URL)
            assert matched.canonical_host == "app.example.com", "the granted origin is checked on its grant"
            for other in ("https://dest.example.net", "http://dest.example.net:8080"):
                unchanged = await dispatch_scope_binding(conn, run=run, target=binding(other), target_url=TARGET_URL)
                assert unchanged.canonical_host == "dest.example.net", other  # left to the receipt check

            # The row decides liveness: a revoked grant (policy snapshot still lists it) ...
            await conn.execute("UPDATE hunt_permission_grants SET revoked_at=NOW() WHERE id=$1",
                               uuid.UUID(decided["grant"]["id"]))
            with pytest.raises(HuntDispatchRejected, match="no longer live"):
                await dispatch_scope_binding(conn, run=run, target=binding(DESTINATION), target_url=TARGET_URL)
            # ... and a grant row that is gone.
            await conn.execute("DELETE FROM hunt_permission_grants WHERE id=$1", uuid.UUID(decided["grant"]["id"]))
            with pytest.raises(HuntDispatchRejected, match="no longer live"):
                await dispatch_scope_binding(conn, run=run, target=binding(DESTINATION), target_url=TARGET_URL)

    stack.loop.run_until_complete(scenario())


def test_a_scanner_aimed_at_an_authorized_destination_is_refused_before_anything_is_reserved(stack):
    """A scanner runs only against the Hunt's own host (the worker's
    validate_scanner_execution_target). On a granted destination it used to be admitted, reserved
    and charged in full, and then fail in the worker with no traffic sent."""
    from fastapi import HTTPException

    async def scenario():
        hunt, _standing = await _hunt(stack.pool, preauthorize=True)
        enqueued: list = []
        stack.router.enqueue_job = lambda _redis, _queue, payload: enqueued.append(payload)
        request = stack.router.HuntCapabilityRequest(
            idempotency_key="d39-scanner-01", input={"origin": DESTINATION},
        )
        with pytest.raises(HTTPException) as refused:
            await stack.router.execute_hunt_capability(str(hunt["id"]), "web.probe", request)
        assert refused.value.status_code == 422, refused.value.detail
        assert refused.value.detail["reason_code"] == "scope_scanner_other_host"
        assert enqueued == [] and stack.wire == []
        action_id = uuid.uuid5(uuid.UUID(str(hunt["id"])), "hunt-capability:d39-scanner-01")
        async with stack.pool.acquire() as conn:
            assert await conn.fetchval(
                "SELECT count(*) FROM budget_reservations WHERE owner_kind='hunt' AND owner_id=$1",
                str(hunt["id"])) == 0, "nothing was reserved"
            assert await conn.fetchval(
                "SELECT count(*) FROM hunt_permission_requests WHERE hunt_run_id=$1", hunt["id"]) == 0
            assert await conn.fetchval("SELECT status FROM hunt_actions WHERE id=$1", action_id) == "blocked"

    stack.loop.run_until_complete(scenario())


def test_pre_authorized_destination_capability_and_budget_admit_within_the_attempt_budget(stack, monkeypatch):
    """Every pre-authorized grant costs one admission pass, and the granted destination's DNS
    recheck cost one more. A call needing a destination, a capability and a budget raise, all
    inside the start bounds, used five passes of MAX_ADMISSION_ATTEMPTS = 4 and was answered
    "Hunt admission did not settle". The recheck is not an admission attempt."""
    async def scenario():
        hunt, standing = await _hunt(
            stack.pool, preauthorize=True,
            bounds=("target.authorize:dest.example.net", "capability:state-changing", "budget.raise:2x"),
            budget_overrides={"max_state_changing_requests": 5},
        )

        async def approval(*_args, **_kwargs):  # labelled double: the per-call active approval
            return {"scope_receipt_id": str(standing["scope_receipt_id"])}

        monkeypatch.setitem(stack.router._deps, "_validate_approval_receipt_for_action", lambda: approval)
        async with stack.pool.acquire() as conn:  # the call budget is spent: a raise is needed
            budget = json.loads(await conn.fetchval("SELECT budget_json FROM hunt_runs WHERE id=$1", hunt["id"]))
            await conn.execute(
                """UPDATE hunt_runs SET budget_used_json = budget_used_json || jsonb_build_object('agent_actions', $2::int)
                   WHERE id=$1""", hunt["id"], int(budget["max_capability_calls"]))
        from fastapi import HTTPException

        request = stack.router.HuntCapabilityRequest(
            idempotency_key="d39-attempts-01",
            input={"method": "POST", "path": "/robots.txt", "origin": DESTINATION},
        )
        try:
            result = await stack.router.execute_hunt_capability(str(hunt["id"]), "http.request", request)
        except HTTPException as exc:
            result = exc
        finally:
            if stack.workers:
                await asyncio.gather(*stack.workers)
        assert not isinstance(result, Exception), getattr(result, "detail", result)
        async with stack.pool.acquire() as conn:
            kinds = sorted(row["kind"] for row in await conn.fetch(
                "SELECT kind FROM hunt_permission_requests WHERE hunt_run_id=$1 AND status='granted'", hunt["id"]))
        assert kinds == ["budget.raise", "capability.enable", "target.authorize"], kinds

    stack.loop.run_until_complete(scenario())


def test_a_granted_destination_is_held_to_the_hard_limits_at_dispatch():
    """Unit: the dispatch re-check of a granted destination's pinned addresses and scope."""
    from hunt.dispatch_authority import destination_hard_limit

    granted = {"scheme": "http", "host": "dest.example.net", "port": 80, "addresses": [DESTINATION_ADDRESS]}
    assert destination_hard_limit(granted, "production") is None
    for address in ("10.0.0.7", "127.0.0.1", "169.254.169.254", "192.0.2.10", "::1"):
        assert destination_hard_limit({**granted, "addresses": [DESTINATION_ADDRESS, address]}, "production"), address
    assert destination_hard_limit({**granted, "addresses": []}, "production")
    # The host's own scope evaluation still applies (a metadata address literal is blocked).
    assert "scope is blocked" in destination_hard_limit({**granted, "host": "169.254.169.254"}, "production")


def test_a_write_admitted_before_its_grant_was_revoked_is_refused_at_dispatch(stack, monkeypatch):
    """R1 (external release audit, 2026-10-09): the worker re-reads the Hunt's rebuilt authority.
    A state-changing request admitted under a live grant, whose grant the person revoked before
    the worker ran, is refused at dispatch and sends nothing."""
    from fastapi import HTTPException
    from hunt import permission_grants

    async def standing_lookup(conn, target_id):  # the real standing authorization row
        from target_authorization import current_target_authorization
        return await current_target_authorization(conn, target_id)

    monkeypatch.setattr(permission_grants, "standing_authorization", standing_lookup)

    async def approval(*_args, **_kwargs):  # labelled double: the composition root's receipt validator
        return {"scope_receipt_id": _standing["scope_receipt_id"]}

    monkeypatch.setitem(stack.router._deps, "_validate_approval_receipt_for_action", lambda: approval)

    _standing: dict = {}

    async def write(hunt, key):
        request = stack.router.HuntCapabilityRequest(
            idempotency_key=key, input={"method": "POST", "path": "/api/items", "origin": TARGET_URL},
        )
        try:
            return await stack.router.execute_hunt_capability(str(hunt["id"]), "http.request", request)
        except HTTPException as exc:
            return exc
        finally:
            if stack.workers:
                await asyncio.gather(*stack.workers)

    async def scenario():
        nonlocal _standing
        hunt, _standing = await _hunt(stack.pool, budget_overrides={
            "max_state_changing_requests": 5, "max_active_actions": 5})
        refused = await write(hunt, "r1-write-01")
        assert getattr(refused, "status_code", None) == 409, refused
        assert refused.detail["permission_request"]["kind"] == "capability.enable"
        decided = await _decide(stack.pool, hunt, refused.detail["permission_request"]["id"])

        async def revoke(_payload):
            from hunt.permission_grants import revoke_grant

            async with stack.pool.acquire() as conn, conn.transaction():
                await revoke_grant(conn, hunt["id"], uuid.UUID(decided["grant"]["id"]),
                                   revoked_by="alice@example.test")

        stack.before_worker.append(revoke)
        answer = await write(hunt, "r1-write-01")
        action, reservation, _used = await _action(stack.pool, hunt, "r1-write-01")
        assert stack.wire == [], "a refused dispatch sends nothing"
        assert action["status"] == "blocked", (action["status"], _summary(action))
        summary = _summary(action)
        assert summary["reason_code"] == "dispatch_authority_rejected"
        assert summary["refusal_stage"] == "dispatch" and summary["execution_started"] is False
        assert "allow_state_changing_http" in summary["message"]
        assert reservation["status"] == "released"  # the hold is released at once, not by stale recovery
        assert answer["action_result"]["status"] == "blocked", answer["result"]

    stack.loop.run_until_complete(scenario())
