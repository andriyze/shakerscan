"""Saved logins by reference (login.use) on real PostgreSQL: attach, admit, count, revoke, view.

Admission runs through the real ``_execute_hunt_capability_lifecycle`` (the permission-request
harness of test_hunt_permission_requests_postgres, stopping at dispatch). The credential profile
is real (``PostgresCredentialProfileStore``) and its secret really encrypted; the login URL is
read through the real ``WorkerCredentialResolver``. Labelled doubles: the approval-receipt
validators (no receipt rows exist here). No request leaves the test. Values are synthetic.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import uuid

import pytest
from fastapi import HTTPException

from hunt import saved_logins
from hunt.permission_bounds import parse_bounds
from hunt.permission_grants import GrantRefused, revoke_grant
from hunt.permission_store import public_request, record_preauthorization
from hunt.start_contract import HuntStartContractError, normalize_hunt_start_payload
from hunt.start_permissions import record_start_permissions, validate_start_saved_logins
from runtime import credential_resolver
from runtime.credential_store import PostgresCredentialProfileStore
from runtime.credentials import build_credential_secret, parse_credential_secret, public_credential_configuration
from tests.test_hunt_permission_requests_postgres import DSN, TARGET_URL, permission_environment

pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

SECRET = "synthetic-saved-login-secret-5e1d9a"
USERNAME = "synthetic-hub-operator"
LOGIN_URL = "https://app.example.test:443/hub/login"
SCOPE = "scope-fixture"
# An active Hunt WITHOUT state-changing permission: the saved login is its only write.
ACTIVE = {"active_testing": True, "allow_state_changing_http": False, "approval_receipt_id": str(uuid.uuid4()),
          "authorization_confirmed": True, "scope_receipt_id": SCOPE}
BUDGET = {"max_active_actions": 20, "max_state_changing_requests": 0}


@pytest.fixture
def env(monkeypatch):
    from cryptography.fernet import Fernet
    import secret_store
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_fernet", None)
    monkeypatch.setattr(secret_store, "_loaded", False)

    async def authority(_conn, *, owner_kind, owner_id, target, approval_receipt_id, scope_receipt_id, action_name):
        # Labelled double: no approval_receipts rows exist in this schema; the real check is
        # exercised by test_credential_resolver and the worker test.
        assert action_name == "hunt.capability:http.request" and scope_receipt_id == SCOPE
        return credential_resolver.CredentialResolutionAuthority(
            owner_kind=owner_kind, owner_id=owner_id, credential_access_allowed=True,
            approval_validated=True, approval_receipt_id=str(approval_receipt_id), scope_receipt_id=scope_receipt_id)

    monkeypatch.setattr(credential_resolver, "validate_worker_credential_authority", authority)
    for environment in permission_environment(monkeypatch):
        environment.loop.run_until_complete(PostgresCredentialProfileStore().ensure_schema(environment.conn))
        yield environment


def run(env, coroutine):
    return env.loop.run_until_complete(coroutine)


async def _profile(env, target_id, *, kind="form_login", capabilities=("http.request",), endpoint=LOGIN_URL):
    import secret_store
    now = datetime.now(timezone.utc)
    secret = build_credential_secret(
        kind, secret=SECRET, username=USERNAME,
        **({"endpoint_url": endpoint} if kind in {"form_login", "json_login"} else {}))
    profile_id = uuid.uuid4()
    await PostgresCredentialProfileStore().create_profile(
        env.conn, profile_id=profile_id, target_kind="web", target_id=target_id, name=f"hub operator {profile_id.hex[:8]}",
        auth_kind=kind, principal_slot="primary", principal_label="Hub operator",
        configuration=public_credential_configuration(parse_credential_secret(kind, secret)),
        encrypted_secret=secret_store.encrypt_secret(secret),
        encrypted_metadata=secret_store.encrypt_secret(json.dumps({"schema_version": "credential-private-metadata/v1"})),
        expires_at=now + timedelta(days=1), allowed_capabilities=list(capabilities),
        created_by="fixture", now=now - timedelta(minutes=1),
    )
    return str(profile_id)


def _login(profile_id, path="/hub/login", **changes):
    values = {"method": "POST", "origin": "https://app.example.test", "path": path,
              "form_body": {"username": "", "password": ""},
              "request_bindings": [
                  {"saved_login": profile_id, "credential_field": "username", "body_pointer": "/username"},
                  {"saved_login": profile_id, "credential_field": "secret", "body_pointer": "/password"}],
              "capture": [{"name": "session", "header": "Set-Cookie"}]}
    values.update(changes)
    return values


async def _everything(env, hunt) -> str:
    rows = []
    for table in ("hunt_runs", "hunt_actions", "hunt_permission_requests", "hunt_permission_grants",
                  "hunt_permission_events", "hunt_credential_uses", "hunt_preauthorizations"):
        column = "id" if table == "hunt_runs" else "hunt_run_id"
        rows += [dict(row) for row in await env.conn.fetch(f"SELECT * FROM {table} WHERE {column}=$1", hunt["id"])]
    return json.dumps(rows, default=str)


def test_an_unattached_saved_login_waits_for_a_person_then_signs_in_only_on_its_login(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        profile_id = await _profile(env, hunt["target_id"])
        # The planner sees it as available (reference and label only) before it is attached.
        view = await saved_logins.hunt_view(env.conn, await env.run(hunt))
        assert view["attached"] == [] and view["available"] == [{
            "saved_login": profile_id, "profile_version": 1, "principal_label": "Hub operator",
            "auth_kind": "form_login", "attached": False, "secret_values_visible": False}]
        with pytest.raises(HTTPException) as parked:
            await env.call(hunt, "login-0001", values=_login(profile_id))
        detail = parked.value.detail
        assert parked.value.status_code == 409 and detail["code"] == "permission_required"
        assert detail["reason_code"] == "saved_login_not_attached"
        assert detail["permission_request"]["kind"] == "login.use"
        [request] = await env.requests(hunt)
        assert json.loads(request["subject_json"]) == {
            "profile_id": profile_id, "profile_version": 1, "auth_kind": "form_login",
            "consuming_target_id": str(hunt["target_id"])}
        shown = public_request(request)
        assert "Hub operator" in shown["title"] and shown["scopes"] == ["hunt"]
        assert "never sees its username or secret" in shown["explanation"]
        assert (await env.action(hunt, "login-0001"))["status"] == "awaiting_permission"

        decided = await env.decide(hunt, request, choice={"logins": 2})
        grant = decided["grant"]
        assert grant["kind"] == "login.use"
        effect = grant["effect"] if "effect" in grant else json.loads(
            (await env.conn.fetchrow("SELECT effect_json FROM hunt_permission_grants WHERE id=$1",
                                     uuid.UUID(grant["id"])))["effect_json"])
        assert effect == {"profile_id": profile_id, "profile_version": 1, "login_url": LOGIN_URL, "max_logins": 2}

        # The same key and input is re-admitted; the state-changing budget (0) is not charged.
        assert await env.call(hunt, "login-0001", values=_login(profile_id)) == "admitted"
        uses = await env.conn.fetch("SELECT * FROM hunt_credential_uses WHERE hunt_run_id=$1", hunt["id"])
        assert [(str(row["profile_id"]), row["slot"], row["source"]) for row in uses] == [
            (profile_id, "login", f"live_grant:{grant['id']}")]
        used = json.loads((await env.run(hunt))["budget_used_json"])
        assert used.get("state_changing_requests", 0) == 0 and used["active_actions"] == 1

        # Another path, another origin: refused, nothing recorded; the login URL is named.
        for key, values in (("login-0002", _login(profile_id, path="/hub/admin")),
                            ("login-0003", _login(profile_id, origin="https://app.example.test:8443"))):
            with pytest.raises(HTTPException) as other:
                await env.call(hunt, key, values=values)
            assert other.value.detail["reason_code"] == "saved_login_destination", other.value.detail
            assert LOGIN_URL in other.value.detail["message"]
        # A login request carries nothing else: no other credential, withheld value or secret.
        mixed = _login(profile_id)
        mixed["request_bindings"].append({"withheld_ref": f"withheld://hunt/{uuid.uuid4()}/1", "body_pointer": "/x"})
        mixed["form_body"]["x"] = ""
        with pytest.raises(HTTPException) as refused:
            await env.call(hunt, "login-0004", values=mixed)
        assert refused.value.detail["reason_code"] == "saved_login_invalid"
        # Not a write the attachment covers: an ordinary POST still needs state-changing permission.
        with pytest.raises(HTTPException) as write:
            await env.call(hunt, "write-0001", values={"method": "POST", "path": "/hub/orders", "json_body": {"a": 1}})
        assert write.value.detail["reason_code"] in {"state_changing_http_not_allowed", "capability_requires_state_changing_http"}
        assert len(await env.conn.fetch("SELECT 1 FROM hunt_credential_uses WHERE hunt_run_id=$1", hunt["id"])) == 1

        # The second login is allowed, the third asks a person again, never automatically.
        assert await env.call(hunt, "login-0005", values=_login(profile_id)) == "admitted"
        await record_preauthorization(env.conn, hunt_id=hunt["id"], bounds=parse_bounds([f"login.use:{profile_id}"]),
                                      created_by="alice@example.test", proof="local")
        with pytest.raises(HTTPException) as more:
            await env.call(hunt, "login-0006", values=_login(profile_id))
        assert more.value.detail["reason_code"] == "saved_login_logins_exhausted"
        pending = [item for item in await env.requests(hunt) if item["status"] == "pending" and item["kind"] == "login.use"]
        assert [item["reason_code"] for item in pending] == ["saved_login_logins_exhausted"]
        assert "used every login" in public_request(pending[0])["explanation"]

        view = await saved_logins.hunt_view(env.conn, await env.run(hunt))
        assert view["available"] == [] and len(view["attached"]) == 1
        attached = view["attached"][0]
        assert {key: attached[key] for key in ("saved_login", "login_url", "logins_allowed", "logins_used", "logins_left", "usable")} == {
            "saved_login": profile_id, "login_url": LOGIN_URL, "logins_allowed": 2, "logins_used": 2,
            "logins_left": 0, "usable": True}
        # No value anywhere in the Hunt's rows, its view or its requests.
        text = await _everything(env, hunt) + json.dumps(view) + json.dumps([public_request(r) for r in await env.requests(hunt)])
        assert SECRET not in text and USERNAME not in text

    run(env, scenario())


def test_a_launch_bound_attaches_the_first_time_only_and_a_revoked_grant_stops_the_next_login(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        profile_id = await _profile(env, hunt["target_id"])
        other = await _profile(env, hunt["target_id"])
        await record_preauthorization(env.conn, hunt_id=hunt["id"], bounds=parse_bounds([f"login.use:{profile_id}"]),
                                      created_by="alice@example.test", proof="local")
        # Covered by the person's launch bound: granted as it arises, same call admitted.
        assert await env.call(hunt, "login-0001", values=_login(profile_id)) == "admitted"
        [request] = await env.requests(hunt)
        assert request["status"] == "granted" and request["decision_via"] == "preauthorization"
        # Another saved login the bound does not name waits for a person.
        with pytest.raises(HTTPException) as parked:
            await env.call(hunt, "login-0002", values=_login(other))
        assert parked.value.detail["code"] == "permission_required"

        grant = await env.conn.fetchrow("SELECT * FROM hunt_permission_grants WHERE hunt_run_id=$1 AND kind='login.use'", hunt["id"])
        async with env.pool.acquire() as conn:
            async with conn.transaction():
                await revoke_grant(conn, hunt["id"], grant["id"], revoked_by="alice@example.test")
        assert await saved_logins.live_login_grants(env.conn, hunt["id"], profile_id) == []
        # The start bound no longer answers for a revoked grant: a person decides again.
        with pytest.raises(HTTPException) as again:
            await env.call(hunt, "login-0003", values=_login(profile_id))
        assert again.value.detail["code"] == "permission_required"

    run(env, scenario())


def test_a_profile_that_is_not_a_saved_login_is_refused_without_a_request(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        bearer = await _profile(env, hunt["target_id"], kind="authorization_header")
        no_http = await _profile(env, hunt["target_id"], capabilities=("auth.session.establish",))
        elsewhere_target = uuid.uuid4()
        await env.conn.execute("INSERT INTO targets(id,url,name) VALUES($1,'https://other.example.test','o')", elsewhere_target)
        elsewhere = await _profile(env, elsewhere_target)
        for number, profile_id in enumerate((bearer, no_http, elsewhere)):
            with pytest.raises(HTTPException) as refused:
                await env.call(hunt, f"login-000{number}", values=_login(profile_id))
            assert refused.value.detail["reason_code"] == "saved_login_unavailable"
        assert await env.requests(hunt) == []

    run(env, scenario())


def test_a_grant_cannot_be_applied_to_a_rotated_or_detached_saved_login(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        profile_id = await _profile(env, hunt["target_id"])
        with pytest.raises(HTTPException):
            await env.call(hunt, "login-0001", values=_login(profile_id))
        [request] = await env.requests(hunt)
        await env.conn.execute("UPDATE credential_profiles SET is_active=false WHERE id=$1", uuid.UUID(profile_id))
        with pytest.raises(GrantRefused) as refused:
            await env.decide(hunt, request)
        assert refused.value.detail["error"] == "saved_login_unavailable"
        assert await saved_logins.live_login_grants(env.conn, hunt["id"]) == []

    run(env, scenario())


def test_a_person_attaches_saved_logins_at_start_with_their_login_count(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        profile_id = await _profile(env, hunt["target_id"])
        contract = normalize_hunt_start_payload({
            "target_id": str(hunt["target_id"]), "target_kind": "web", "goal": "fixture",
            "policy": {"active_testing": True, "authorization_confirmed": True,
                       "approval_receipt_id": ACTIVE["approval_receipt_id"], "scope_receipt_id": SCOPE},
            "saved_logins": [{"profile_id": profile_id, "max_logins": 5}],
        })
        assert contract.public_dict()["saved_logins"] == [{"profile_id": profile_id, "max_logins": 5}]
        stored = await env.run(hunt)
        await validate_start_saved_logins(env.conn, contract, stored)
        await record_start_permissions(env.conn, stored, contract, [])
        [grant] = await saved_logins.live_login_grants(env.conn, hunt["id"])
        assert grant["max_logins"] == 5 and grant["login_url"] == LOGIN_URL
        assert grant["source"].startswith("preauthorized:")
        assert await env.call(hunt, "login-0001", values=_login(profile_id)) == "admitted"
        events = [row["event"] for row in await env.conn.fetch(
            "SELECT event FROM hunt_permission_events WHERE hunt_run_id=$1 ORDER BY created_at", hunt["id"])]
        assert events[:3] == ["preauthorized", "requested", "auto_granted"]
        # A profile that is not a saved login of the target refuses the start before it exists.
        bearer = await _profile(env, hunt["target_id"], kind="authorization_header")
        refused_contract = normalize_hunt_start_payload({
            "target_id": str(hunt["target_id"]), "target_kind": "web", "goal": "fixture",
            "policy": {"active_testing": True, "authorization_confirmed": True,
                       "approval_receipt_id": ACTIVE["approval_receipt_id"], "scope_receipt_id": SCOPE},
            "saved_logins": [{"profile_id": bearer}]})
        with pytest.raises(HTTPException) as refused:
            await validate_start_saved_logins(env.conn, refused_contract, stored)
        assert refused.value.detail["reason_code"] == "saved_login_unavailable"

    run(env, scenario())


@pytest.mark.parametrize("payload,message", [
    ({"saved_logins": [{"profile_id": "not-a-uuid"}]}, "profile id"),
    ({"saved_logins": [{"profile_id": str(uuid.UUID(int=1)), "max_logins": 11}]}, "1 to 10"),
    ({"saved_logins": [{"profile_id": str(uuid.UUID(int=1))}] * 2}, "distinct"),
    ({"saved_logins": [{"profile_id": str(uuid.UUID(int=1)), "secret": "x"}]}, "profile_id, max_logins"),
    ({"saved_logins": [{"profile_id": str(uuid.UUID(int=n))} for n in range(1, 6)]}, "at most 4"),
    ({"saved_logins": [{"profile_id": str(uuid.UUID(int=1))}], "policy": {}}, "active_testing"),
])
def test_start_saved_logins_shape_is_refused_by_name(payload, message):
    body = {"target_id": str(uuid.UUID(int=9)), "target_kind": "web", "goal": "fixture",
            "policy": {"active_testing": True, "authorization_confirmed": True,
                       "approval_receipt_id": str(uuid.UUID(int=7))}, **payload}
    with pytest.raises(HuntStartContractError) as refused:
        normalize_hunt_start_payload(body)
    assert message in str(refused.value)


def test_a_launch_bound_names_profile_ids_and_keeps_older_digests():
    from hunt.permission_bounds import BoundError
    bounds = parse_bounds([f"login.use:{uuid.UUID(int=5)}", "capability:state-changing"])
    assert bounds.covers_saved_login(str(uuid.UUID(int=5))) and not bounds.covers_saved_login(str(uuid.UUID(int=6)))
    # Bounds without saved logins keep the digest they were recorded with before 2.12.
    assert "saved_logins" not in parse_bounds(["capability:state-changing"]).public()
    with pytest.raises(BoundError):
        parse_bounds(["login.use:admin"])
