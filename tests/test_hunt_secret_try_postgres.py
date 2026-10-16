"""Discovered secrets on another target's login and the per-Hunt "agent may see" setting (2.11),
on real PostgreSQL.

Admission runs through the real ``_execute_hunt_capability_lifecycle`` (the permission-request
harness of test_hunt_permission_requests_postgres: labelled doubles for the approval-receipt
validator, no DNS, no worker); the worker's resolution through the real
``discovered_secrets.resolve_for_hunt``. No request leaves the test: every target is a local
fixture name. Values are synthetic.
"""
from __future__ import annotations

import asyncio
import json
import uuid

import pytest
from fastapi import HTTPException

from hunt import discovered_secrets as store
from hunt import interaction_router as router
from hunt import secret_try
from hunt.action_service import HUNT_ACTION_SERVICE, HuntActionLifecycle
from hunt.permission_grants import GrantRefused, revoke_grant
from hunt.permission_store import HUNT_PERMISSION_SCHEMA_SQL, list_events, public_request
from tests.test_hunt_permission_requests_postgres import DSN, permission_environment

pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

VALUE = "synthetic-found-password-91c2e7"
LOGIN = {"method": "POST", "path": "/login", "json_body": {"user": "admin", "password": ""},
         "request_bindings": [{"secret_ref": "", "body_pointer": "/password"}]}
ACTIVE = {"active_testing": True, "allow_state_changing_http": True, "mutation_allowed": True,
          "approval_receipt_id": str(uuid.uuid4()), "authorization_confirmed": True}


@pytest.fixture
def env(monkeypatch):
    from cryptography.fernet import Fernet
    import secret_store
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_fernet", None)
    monkeypatch.setattr(secret_store, "_loaded", False)
    from arsenal_routes import router as arsenal

    receipts: list = []

    async def record_tool_receipt(_conn, request):  # labelled double: no tool_receipts table here
        receipts.append(request.model_dump(mode="json"))
        return {"tool_receipt": {"id": str(uuid.uuid4())}}

    monkeypatch.setitem(arsenal._deps, "_record_tool_receipt", lambda: record_tool_receipt)
    monkeypatch.setitem(arsenal._deps, "_redact_agent_payload", lambda: (lambda value: value))
    for environment in permission_environment(monkeypatch):
        environment.loop.run_until_complete(environment.conn.execute(store.DISCOVERED_SECRETS_SCHEMA_SQL))
        environment.receipts = receipts
        yield environment


def run(env, coroutine):
    return env.loop.run_until_complete(coroutine)


async def _found_on_other_target(env, value=VALUE, label="DB_PASSWORD"):
    """A secret found on another target (S): its reference."""
    other = uuid.uuid4()
    await env.conn.execute("INSERT INTO targets(id,url,name) VALUES($1,'https://other.example.test','other')", other)
    await store.record_discovered(env.conn, target_id=other, values=[(value, label)],
                                  source={"kind": "scan_finding", "id": "f1"})
    return other, (await store.list_for_target(env.conn, other))[0]["ref"]


def _login(ref, **changes):
    values = json.loads(json.dumps(LOGIN))
    values["request_bindings"][0]["secret_ref"] = ref
    values.update(changes)
    return values


async def _action_row(env, hunt, key):
    action_id = uuid.uuid5(uuid.UUID(str(hunt["id"])), f"hunt-capability:{key}")
    return action_id, await env.conn.fetchrow("SELECT * FROM hunt_actions WHERE id=$1", action_id)


async def _everything(env, hunt) -> str:
    """Every row the Hunt and its permission audit hold, as text."""
    rows = []
    for table in ("hunt_runs", "hunt_actions", "hunt_permission_requests", "hunt_permission_grants",
                  "hunt_permission_events", "discovered_secret_uses"):
        column = "id" if table == "hunt_runs" else "hunt_run_id"
        rows += [dict(row) for row in await env.conn.fetch(f"SELECT * FROM {table} WHERE {column}=$1", hunt["id"])]
    return json.dumps(rows, default=str)


def _destination(path="/login", method="POST"):
    return secret_try.destination_of({"path": path, "method": method}, "https://app.example.test")


def test_another_targets_secret_waits_for_a_person_and_is_tried_only_on_that_login(env):
    async def scenario():
        _other, ref = await _found_on_other_target(env)
        hunt = await env.hunt(policy=ACTIVE, budget={"max_state_changing_requests": 10, "max_active_actions": 10})
        with pytest.raises(HTTPException) as parked:
            await env.call(hunt, "try-0001", values=_login(ref))
        detail = parked.value.detail
        assert parked.value.status_code == 409 and detail["code"] == "permission_required"
        assert detail["reason_code"] == "secret_other_target"
        assert detail["permission_request"]["kind"] == "secret.try"
        [request] = await env.requests(hunt)
        subject = json.loads(request["subject_json"])
        assert subject == {
            "secret_id": ref.removeprefix("secret://"), "found_on_target_id": str(_other),
            "consuming_target_id": str(hunt["target_id"]), "origin": "https://app.example.test:443",
            "host": "app.example.test", "path": "/login", "method": "POST",
        }
        shown = public_request(request)
        assert "DB_PASSWORD" in shown["explanation"] and shown["scopes"] == ["hunt"]
        _action_id, action = await _action_row(env, hunt, "try-0001")
        assert action["status"] == "awaiting_permission"
        # Nothing was sent and no value is anywhere in the Hunt's rows.
        assert await env.conn.fetchval("SELECT count(*) FROM discovered_secret_uses") == 0
        assert VALUE not in await _everything(env, hunt)

        await env.decide(hunt, request, choice={"attempts": 2})
        assert await env.call(hunt, "try-0001", values=_login(ref)) == "admitted"

        action_id, _ = await _action_row(env, hunt, "try-0001")
        uses: list = []
        sent = await store.resolve_for_hunt(
            env.conn, reference=ref, target_id=hunt["target_id"], hunt_run_id=hunt["id"],
            action_id=action_id, destination_host="app.example.test", destination=_destination(), use_ids=uses)
        assert sent == VALUE
        await store.record_use_outcome(env.conn, uses, "http_401")
        # Another login of the same target, or another method, is not what the person allowed.
        for other in (_destination(path="/admin/login"), _destination(method="PUT")):
            with pytest.raises(store.DiscoveredSecretError) as refused:
                await store.resolve_for_hunt(
                    env.conn, reference=ref, target_id=hunt["target_id"], hunt_run_id=hunt["id"],
                    action_id=action_id, destination=other)
            assert refused.value.reason == store.SECRET_TARGET_MISMATCH
        await store.resolve_for_hunt(
            env.conn, reference=ref, target_id=hunt["target_id"], hunt_run_id=hunt["id"],
            action_id=action_id, destination_host="app.example.test", destination=_destination())
        with pytest.raises(store.DiscoveredSecretError) as spent:
            await store.resolve_for_hunt(
                env.conn, reference=ref, target_id=hunt["target_id"], hunt_run_id=hunt["id"],
                action_id=action_id, destination_host="app.example.test", destination=_destination())
        assert spent.value.reason == secret_try.SECRET_TRY_EXHAUSTED and VALUE not in str(spent.value)

        # Audited: two attempts on the grant, with the answer, on the Hunt record; never the value.
        uses = await store.read_hunt_uses(env.conn, hunt["id"])
        assert len(uses) == 2 and all(item["permission_grant_id"] for item in uses)
        assert uses[0]["outcome"] == "http_401" and uses[0]["destination_host"] == "app.example.test"
        assert VALUE not in json.dumps(uses) and VALUE not in await _everything(env, hunt)
        events = [item["event"] for item in await list_events(env.conn, hunt["id"])]
        assert events[:3] == ["requested", "decided", "used"]

        # Spent: the agent asks again under a new key, and a person decides again.
        with pytest.raises(HTTPException) as again:
            await env.call(hunt, "try-0002", values=_login(ref))
        assert again.value.detail["reason_code"] == "secret_try_attempts_exhausted"
        assert again.value.detail["permission_request"]["kind"] == "secret.try"
    run(env, scenario())


def test_start_bounds_never_grant_a_try_and_a_denial_sends_nothing(env):
    async def scenario():
        from hunt.permission_bounds import parse_bounds
        from hunt.permission_store import record_preauthorization
        _other, ref = await _found_on_other_target(env)
        hunt = await env.hunt(policy=ACTIVE, budget={"max_state_changing_requests": 10, "max_active_actions": 10})
        await record_preauthorization(
            env.conn, hunt_id=hunt["id"], created_by="alice@example.test", proof="local",
            bounds=parse_bounds(["budget.raise:4x", "target.authorize:*.example.test",
                                 f"credential.use:{_other}", "capability:state-changing"]))
        with pytest.raises(HTTPException) as parked:
            await env.call(hunt, "deny-0001", values=_login(ref))
        assert parked.value.detail["code"] == "permission_required"
        [request] = await env.requests(hunt)
        assert request["status"] == "pending"
        await env.decide(hunt, request, decision="deny")
        assert (await env.call(hunt, "deny-0001", values=_login(ref)))["status"] == "blocked"
        _action_id, action = await _action_row(env, hunt, "deny-0001")
        assert action["status"] == "blocked"
        assert json.loads(action["result_summary"])["reason_code"] == "permission_denied"
        # Asked again under a new key within the cooldown: refused, not asked again.
        with pytest.raises(HTTPException) as denied:
            await env.call(hunt, "deny-0002", values=_login(ref))
        assert denied.value.detail["reason_code"] == "permission_denied"
        assert len(await env.requests(hunt)) == 1
        # The worker refuses as well: there is no grant.
        with pytest.raises(store.DiscoveredSecretError):
            await store.resolve_for_hunt(
                env.conn, reference=ref, target_id=hunt["target_id"], hunt_run_id=hunt["id"],
                action_id=_action_id, destination=_destination())
        assert await env.conn.fetchval("SELECT count(*) FROM discovered_secret_uses") == 0
    run(env, scenario())


def test_the_shared_hub_login_never_receives_a_secret_and_is_never_asked_about(env, monkeypatch):
    async def scenario():
        _other, ref = await _found_on_other_target(env)
        hunt = await env.hunt(policy=ACTIVE, budget={"max_state_changing_requests": 10, "max_active_actions": 10})
        for path in ("/hub/login", "/HUB/login", "/%68ub/login", "/static/../hub/login", "//hub/login"):
            values = _login(ref, origin="https://honey.shakerscan.com", path=path)
            assert secret_try.denied_destination("honey.shakerscan.com", path)
            with pytest.raises(HTTPException) as refused:
                await secret_try.admit_secret_references(
                    env.conn, run=hunt, values=values, fallback_origin="https://app.example.test")
            assert refused.value.detail["reason_code"] == "secret_try_destination_denied"
            with pytest.raises(store.DiscoveredSecretError) as worker:
                await store.resolve_for_hunt(
                    env.conn, reference=ref, target_id=_other, hunt_run_id=hunt["id"],
                    action_id=uuid.uuid4(), destination=secret_try.destination_of(values, None))
            assert worker.value.reason == secret_try.SECRET_TRY_DESTINATION_DENIED
        assert not secret_try.denied_destination("honey.shakerscan.com", "/hubris")
        assert not secret_try.denied_destination("app.example.test", "/hub/login")
        # An installation adds its own shared logins.
        monkeypatch.setenv("SHAKERSCAN_SECRET_TRY_DENY", "app.example.test/sso")
        assert secret_try.denied_destination("app.example.test", "/sso/start")
        assert await env.conn.fetchval("SELECT count(*) FROM hunt_permission_requests") == 0
        assert await env.conn.fetchval("SELECT count(*) FROM discovered_secret_uses") == 0
    run(env, scenario())


def test_attempts_are_rate_limited_per_host_and_claimed_once_under_concurrency(env):
    async def scenario():
        _other, ref = await _found_on_other_target(env)
        hunt = await env.hunt(policy=ACTIVE, budget={"max_state_changing_requests": 10, "max_active_actions": 10})
        with pytest.raises(HTTPException):
            await env.call(hunt, "rate-0001", values=_login(ref))
        [request] = await env.requests(hunt)
        await env.decide(hunt, request, choice={"attempts": 10})
        action_id, _ = await _action_row(env, hunt, "rate-0001")

        async def attempt():
            async with env.pool.acquire() as conn:
                return await store.resolve_for_hunt(
                    conn, reference=ref, target_id=hunt["target_id"], hunt_run_id=hunt["id"],
                    action_id=action_id, destination_host="app.example.test", destination=_destination())

        outcomes = await asyncio.gather(*(attempt() for _ in range(6)), return_exceptions=True)
        sent = [item for item in outcomes if item == VALUE]
        refused = [item for item in outcomes if isinstance(item, store.DiscoveredSecretError)]
        assert len(sent) == secret_try.WINDOW_MAX
        assert {item.reason for item in refused} == {secret_try.SECRET_TRY_RATE_LIMITED}
        assert await env.conn.fetchval("SELECT count(*) FROM discovered_secret_uses") == secret_try.WINDOW_MAX
        # Admission says so too, before anything is reserved.
        with pytest.raises(HTTPException) as limited:
            await env.call(hunt, "rate-0002", values=_login(ref))
        assert limited.value.status_code == 429
        assert limited.value.detail["reason_code"] == "secret_try_rate_limited"
    run(env, scenario())


def test_a_revoked_grant_or_a_revoked_secret_stops_the_tries(env):
    async def scenario():
        other, ref = await _found_on_other_target(env)
        hunt = await env.hunt(policy=ACTIVE, budget={"max_state_changing_requests": 10, "max_active_actions": 10})
        with pytest.raises(HTTPException):
            await env.call(hunt, "revoke-0001", values=_login(ref))
        [request] = await env.requests(hunt)
        with pytest.raises(GrantRefused):
            await env.decide(hunt, request, choice={"attempts": 11})
        decided = await env.decide(hunt, request, key="decision-0002")
        grant_id = decided["request"]["grant_id"]
        async with env.pool.acquire() as conn:
            async with conn.transaction():
                await revoke_grant(conn, hunt["id"], grant_id, revoked_by="alice@example.test")
        with pytest.raises(store.DiscoveredSecretError) as revoked:
            await store.resolve_for_hunt(
                env.conn, reference=ref, target_id=hunt["target_id"], hunt_run_id=hunt["id"],
                action_id=uuid.uuid4(), destination=_destination())
        assert revoked.value.reason == store.SECRET_TARGET_MISMATCH
        # A secret the operator revoked cannot be granted for a try.
        with pytest.raises(HTTPException):
            await env.call(hunt, "revoke-0002", values=_login(ref))
        pending = [item for item in await env.requests(hunt) if item["status"] == "pending"][0]
        await store.set_state(env.conn, target_id=other, secret_id=ref.removeprefix("secret://"),
                              state="revoked_by_operator", actor="operator:test")
        with pytest.raises(GrantRefused) as inactive:
            await env.decide(hunt, pending, key="decision-0003")
        assert inactive.value.detail["error"] == "secret_not_active"
    run(env, scenario())


def test_the_hunts_own_secrets_need_no_try_permission(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget={"max_state_changing_requests": 10, "max_active_actions": 10})
        await store.record_discovered(env.conn, target_id=hunt["target_id"], values=[(VALUE, "password")],
                                      source={"kind": "hunt_action", "id": "a1"})
        ref = (await store.list_for_target(env.conn, hunt["target_id"]))[0]["ref"]
        assert await env.call(hunt, "own-0001", values=_login(ref)) == "admitted"
        assert await env.requests(hunt) == []
    run(env, scenario())


def test_the_kind_constraint_is_widened_once_and_a_restart_takes_no_table_lock(env):
    async def scenario():
        conn = env.conn
        old = "'target.authorize','credential.use','capability.enable','budget.raise','ssh.exec','ssh.host_trust','preauthorization'"
        for table in ("hunt_permission_requests", "hunt_permission_grants"):
            await conn.execute(f"ALTER TABLE {table} DROP CONSTRAINT {table}_kind_check")
            await conn.execute(f"ALTER TABLE {table} ADD CONSTRAINT {table}_kind_check CHECK (kind IN ({old}))")
        await conn.execute("ALTER TABLE discovered_secret_uses DROP COLUMN permission_grant_id, DROP COLUMN outcome")
        # The upgrade: the constraint and the columns are brought up to date.
        await conn.execute(HUNT_PERMISSION_SCHEMA_SQL)
        await conn.execute(store.DISCOVERED_SECRETS_SCHEMA_SQL)
        for table in ("hunt_permission_requests", "hunt_permission_grants"):
            definition = await conn.fetchval(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname=$1", f"{table}_kind_check")
            assert "secret.try" in definition
        assert await conn.fetchval(
            """SELECT count(*) FROM information_schema.columns WHERE table_name='discovered_secret_uses'
               AND column_name IN ('permission_grant_id','outcome') AND table_schema=current_schema()""") == 2
        # A steady-state restart: the same SQL in one transaction holds no AccessExclusiveLock.
        async with conn.transaction():
            await conn.execute(HUNT_PERMISSION_SCHEMA_SQL)
            await conn.execute(store.DISCOVERED_SECRETS_SCHEMA_SQL)
            locked = await conn.fetch(
                """SELECT c.relname FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
                   WHERE l.pid=pg_backend_pid() AND l.mode='AccessExclusiveLock'
                     AND c.relname IN ('hunt_permission_requests','hunt_permission_grants',
                                       'discovered_secret_uses','discovered_secrets','hunt_actions')""")
        assert locked == []
    run(env, scenario())


# ---------------------------------------------------------------------------------------------
# "Agent may see found secrets": a person's choice at start, off by default.

async def _inspect(env, hunt, key):
    """secrets.inspect through the whole lifecycle (inline capability: no worker involved)."""
    values: dict = {}
    request = router.HuntCapabilityRequest(idempotency_key=key, input=values)
    prepared = HUNT_ACTION_SERVICE.prepare("secrets.inspect", values)
    lifecycle = HuntActionLifecycle(specification=prepared.specification)
    lifecycle.advance("validated")
    return await router._execute_hunt_capability_lifecycle(str(hunt["id"]), "secrets.inspect", request, lifecycle)


async def _hunt_with_secret(env, *, visible: bool):
    policy = {**ACTIVE, "allowed_capabilities": ["http.request", "secrets.inspect"]}
    if visible:
        policy.update(secret_values_visible=True, secret_visibility_set_by="alice@example.test",
                      secret_visibility_proof="local")
    hunt = await env.hunt(policy=policy)
    context = json.loads(hunt["context_pack"]) if isinstance(hunt["context_pack"], str) else dict(hunt["context_pack"])
    context["allowed_capabilities"] = policy["allowed_capabilities"]
    await env.conn.execute("UPDATE hunt_runs SET context_pack=$2::jsonb WHERE id=$1", hunt["id"], json.dumps(context))
    await store.record_discovered(env.conn, target_id=hunt["target_id"], values=[(VALUE, "DB_PASSWORD")],
                                  source={"kind": "hunt_action", "id": "a1"})
    return await env.run(hunt)


def test_by_default_the_agent_never_sees_a_value_anywhere(env):
    async def scenario():
        hunt = await _hunt_with_secret(env, visible=False)
        answer = await _inspect(env, hunt, "inspect-0001")
        assert answer["result"]["secret_values_visible"] is False
        assert answer["result"]["count"] == 1 and "value" not in answer["result"]["secrets"][0]
        assert VALUE not in json.dumps(answer, default=str)
        assert env.receipts and VALUE not in json.dumps(env.receipts)
        # Briefing counts, the knowledge store's record of uses, every Hunt row: no value.
        assert VALUE not in json.dumps(await store.briefing_counts(env.conn, hunt["target_id"]))
        assert VALUE not in json.dumps(await store.read_hunt_uses(env.conn, hunt["id"]))
        assert VALUE not in await _everything(env, hunt)
        assert await env.conn.fetchval("SELECT count(*) FROM discovered_secret_uses") == 0
    run(env, scenario())


def test_when_the_person_allowed_it_the_value_is_in_the_live_answer_only_and_recorded(env):
    async def scenario():
        hunt = await _hunt_with_secret(env, visible=True)
        answer = await _inspect(env, hunt, "inspect-0002")
        [shown] = answer["result"]["secrets"]
        assert shown["value"] == VALUE and answer["result"]["secret_values_visible"] is True
        assert answer["result"]["values_in_this_answer_only"] is True
        # Stored action, receipt and ledger never hold it; the disclosure is audited.
        assert VALUE not in await _everything(env, hunt)
        assert env.receipts and VALUE not in json.dumps(env.receipts)
        [use] = await store.read_hunt_uses(env.conn, hunt["id"])
        assert use["disclosed_to_agent"] is True and use["ref"] == shown["ref"]
        listed = (await store.list_for_target(env.conn, hunt["target_id"]))[0]
        assert listed["reveals"] == 1 and listed["uses"] == 0
        # The retry store keeps the answer without the value.
        from public_api_contract import _without_agent_values
        body = json.dumps(answer, default=str).encode()
        kept = _without_agent_values(json.loads(body), body)
        assert VALUE not in kept.decode() and json.loads(kept)["result"]["secret_values_visible"] is False
        # Another target's secret that was never granted is not shown, even when visible.
        other, other_ref = await _found_on_other_target(env, value="synthetic-other-value-55d1")
        assert await store.values_for_agent(
            env.conn, hunt_run_id=hunt["id"], target_id=hunt["target_id"], action_id=None,
            refs=[other_ref]) == {}
    run(env, scenario())


def test_inspect_lists_related_targets_secrets_as_metadata_a_try_can_name(env):
    async def scenario():
        hunt = await _hunt_with_secret(env, visible=True)
        await env.conn.execute("UPDATE targets SET root_domain='example.test' WHERE id=$1", hunt["target_id"])
        other, ref = await _found_on_other_target(env, value="synthetic-related-value-0a7b")
        await env.conn.execute("UPDATE targets SET root_domain='example.test' WHERE id=$1", other)
        unrelated, _ = await _found_on_other_target(env, value="synthetic-unrelated-value-31f0")
        await env.conn.execute("UPDATE targets SET root_domain='elsewhere.test' WHERE id=$1", unrelated)
        answer = await _inspect(env, hunt, "inspect-0003")
        related = answer["result"]["related_target_secrets"]
        assert [item["ref"] for item in related] == [ref] and related[0]["found_on"] == str(other)
        # Even with values visible, another target's value is never in the answer.
        text = json.dumps(answer, default=str)
        assert "synthetic-related-value-0a7b" not in text and "synthetic-unrelated-value-31f0" not in text
    run(env, scenario())
