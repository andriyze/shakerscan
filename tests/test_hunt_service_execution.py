"""Service-coordinate regressions across real transports, storage, and API routes.

All network traffic is loopback, all identity material synthetic. Relational API
and credential-store tests exercise production code with documented DB doubles;
PostgreSQL migration/persistence acceptance lives in test_hunt_service_postgres.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
import json
from types import SimpleNamespace
import uuid

import pytest

from capabilities.auth import TargetBoundSessionCredential, establish_target_bound_http_session
from capabilities.http import execute_bound_http_request, resolve_hunt_http_origin
from hunt.service_binding import collection_target, endpoint_target
from runtime.models import TargetBinding
from runtime.pinned_http_replay import PinnedAiohttpReplayTransport
from runtime.request_replay_executor import execute_replay_plan
from scanner_tools.request_replay import ReplayAuthorization, build_replay_plan
from tests.test_hunt_operator_execution import target_server, PASSWORD, COOKIE

POLICY = {"active_testing": True, "network_discovery": False,
          "approval_receipt_id": "receipt", "scope_receipt_id": "scope"}
TARGET = str(uuid.UUID(int=42))


def run_context(kind, origin="https://fixture.test"):
    run = {"id": str(uuid.UUID(int=43)), "target_kind": kind,
           "target_id": TARGET if kind != "device" else None,
           "device_target_id": TARGET if kind == "device" else None}
    target = {"locator": "fixture.test"} if kind == "device" else {"url": origin, "origins": [origin]}
    return run, {"target": target, "authorized_target_addresses": ["127.0.0.1"]}


@pytest.mark.parametrize("kind", ["web", "api", "network", "device"])
@pytest.mark.parametrize("defect", ["http", "self_signed", "expired", "hostname"])
def test_login_and_reserved_collection_replay_reach_selected_service(tmp_path, kind, defect):
    """Start from the registered default origin, not a pre-expanded test binding."""
    from hunt.target_binding import web_hunt_target

    async def scenario():
        async with target_server(tmp_path, defect) as (_, origin, calls):
            run, context = run_context(kind)
            base, _ = web_hunt_target(run, context, POLICY)
            selected, endpoint = endpoint_target(base, origin + "/login", POLICY)
            session = await establish_target_bound_http_session(TargetBoundSessionCredential(
                lane="primary", auth_kind="form_login", endpoint_url=endpoint,
                binding_digest="a" * 64, username="fixture-user", secret=PASSWORD,
            ), target=selected)
            assert session.established, session.execution_result()
            result = await execute_bound_http_request(origin, {"method": "GET", "path": "/private"},
                target=selected, trusted_headers=session.headers())
            assert result["ok"] and result["response"]["status"] == 200
            replay_target = collection_target(run, context, POLICY, [origin])
            plan = build_replay_plan([{
                "id": "synthetic-read", "method": "GET", "url": origin + "/private",
                "headers": session.headers(), "body": b"", "body_mode": "none",
                "auth_type": "cookie", "has_sensitive_material": True,
                "unresolved_variables": [], "error": None,
            }], allowed_origins=list(replay_target.allowed_origins), authorization=ReplayAuthorization())
            outcome = await execute_replay_plan(plan, target=replay_target, owner_kind="hunt",
                owner_id=run["id"], worker_id="test-worker", limits={"http_requests": 10},
                consumed={}, transport=PinnedAiohttpReplayTransport())
            assert outcome.status == "succeeded", outcome.receipt.public_dict()
            assert outcome.reservation.actual["http_requests"] == 1
            assert [call[0] for call in calls] == ["GET", "POST", "GET", "GET"]
            assert all(call[2]["Host"] == origin.split("://")[1] for call in calls)
            assert all(COOKIE not in json.dumps(value) for value in (session.execution_result(), outcome.receipt.public_dict()))
            assert selected.allowed_addresses == base.allowed_addresses
            assert replay_target.target_id == base.target_id
    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["web", "device"])
@pytest.mark.parametrize("origin", ["https://other.test:8443", "http://fixture.test:0", "https://fixture.test:65536",
                                    "http://user@fixture.test:8080", "file://fixture.test", "http://fixture.test:8080/path"])
def test_service_selection_still_rejects_changed_assets_or_invalid_origins(kind, origin):
    run, context = run_context(kind)
    with pytest.raises(ValueError):
        collection_target(run, context, POLICY, [origin])


@pytest.mark.parametrize("kind", ["web", "device", "network"])
def test_hunt_session_store_survives_service_selection_not_asset_changes(monkeypatch, kind):
    from api.runtime import auth_session_store as store
    from tests.test_auth_session_store import SessionConn, target, NOW, OWNER_ID, PROFILE_ID, ACTION_ID, SESSION_ID
    monkeypatch.setattr(store, "encrypt_secret", lambda s: "enc:fernet:" + s)
    monkeypatch.setattr(store, "decrypt_secret", lambda s: s.removeprefix("enc:fernet:"))

    async def scenario():
        conn = SessionConn()
        base = replace(target(), target_kind=kind)
        selected = resolve_hunt_http_origin(base, "https://app.example.test:8443", POLICY)
        metadata = await store.PostgresAuthSessionStore().create(conn,
            owner_kind="hunt", owner_id=OWNER_ID, target=selected, profile_id=PROFILE_ID,
            profile_version=3, principal_slot="primary", principal_label="synthetic", auth_kind="json_login",
            compatible_capabilities=["http.request", "auth.session.refresh"], headers={"Cookie": "session=synthetic"},
            established_at=NOW, expires_at=NOW+timedelta(hours=1), refresh_after=NOW+timedelta(minutes=50),
            evidence_receipt_digest="a"*64, source_action_id=ACTION_ID, session_ref=SESSION_ID,
            service_origin="https://app.example.test:8443")
        assert metadata.service_origin.endswith(":8443")
        for binding in (base, selected, resolve_hunt_http_origin(base, "https://app.example.test:9443", POLICY)):
            session = await store.PostgresAuthSessionStore().load_for_worker(conn, session_ref=SESSION_ID,
                owner_kind="hunt", owner_id=OWNER_ID, target=binding, capability="http.request", now=NOW)
            assert session.headers() == {"Cookie": "session=synthetic"}
            session.close()
        for changed in (replace(base, allowed_addresses=("192.0.2.11",)),
                        replace(base, canonical_host="other.test"), replace(base, scope_receipt_id="other-scope"),
                        replace(base, target_id=str(uuid.UUID(int=99)))):
            with pytest.raises(store.AuthSessionStoreError):
                await store.PostgresAuthSessionStore().load_for_worker(conn, session_ref=SESSION_ID,
                    owner_kind="hunt", owner_id=OWNER_ID, target=changed, capability="http.request", now=NOW)
    asyncio.run(scenario())


def test_real_device_authorization_routes_persist_device_owned_proposal():
    from tests.test_hunt_authorization_api import (
        RelationalPool, make_service, HUNT, TARGET as DEVICE, CAPTURE, BASELINE,
        OWNER_SESSION, ACTOR_SESSION, ORIGIN, proof_url,
    )
    from api.hunt.authorization_router import router, authorization_service
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    pool = RelationalPool(); pool.seed()
    service_origin = ORIGIN + ":8443"
    context = {"target": {"locator": "fixture.example.test"}, "authorized_target_addresses": ["192.0.2.1"]}
    pool.db.execute("UPDATE hunt_runs SET target_kind='device',target_id=NULL,device_target_id=?,context_pack=?,policy_json=? WHERE id=?",
                    (DEVICE, json.dumps(context), json.dumps(POLICY), HUNT))
    pool.db.execute("UPDATE auth_sessions SET target_kind='device' WHERE owner_id=?", (HUNT,))
    pool.db.execute("UPDATE http_transactions SET url=replace(url,?,?) WHERE hunt_run_id=?", (ORIGIN, service_origin, HUNT))
    for row in pool.db.execute("SELECT id,input_summary FROM hunt_actions WHERE hunt_run_id=?", (HUNT,)).fetchall():
        body = json.loads(row["input_summary"]); body["input"]["origin"] = service_origin
        pool.db.execute("UPDATE hunt_actions SET input_summary=? WHERE id=?", (json.dumps(body), row["id"]))
    service, _ = make_service(pool)
    app = FastAPI(); app.include_router(router); app.dependency_overrides[authorization_service] = lambda: service
    with TestClient(app) as client:
        # The real API, service and repository execute, not _target_context alone.
        response = client.post(f"/hunts/{HUNT}/authorization-investigations", json={
            "capture_id": CAPTURE, "baseline_capture_id": BASELINE,
            "primary_session_ref": OWNER_SESSION, "secondary_session_ref": ACTOR_SESSION,
        })
        assert response.status_code == 200, response.text
        result = response.json()
        rows = pool.db.execute("SELECT target_id,device_target_id FROM application_graph_nodes").fetchall()
        assert rows and all(row["target_id"] is None and row["device_target_id"] == DEVICE for row in rows)
        saved = json.loads(pool.db.execute("SELECT attributes FROM application_graph_nodes LIMIT 1").fetchone()[0])
        assert saved["target_id"] == DEVICE
    pool.db.close()


@pytest.mark.parametrize("kind", ["web", "device"])
@pytest.mark.parametrize("explicit", [False, True])
def test_browser_login_executes_saved_service_not_registration_port(monkeypatch, kind, explicit):
    from contextlib import asynccontextmanager
    from dataclasses import asdict
    from capabilities.browser_login_action import BrowserLoginAdapter, BrowserLoginMaterial
    from capabilities.browser_login import BrowserLoginValues
    from capabilities.browser_login_worker import prepare_hunt_browser_action
    from tests import test_browser_login_check as fixture
    from tests.test_browser_login_action import (TARGET as BROWSER_TARGET, POLICY as BROWSER_POLICY,
        CONTEXT, CONFIG, BrowserFixture, Sender, CAP, REF)
    service = "https://login-fixture.test:9443"
    workflow = replace(fixture.SPEC, origin=service, login_url=service+"/login",
                       submit_url=service+"/session", check_url=service+"/account")
    monkeypatch.setattr(fixture, "SPEC", workflow)
    config = {**CONFIG, "workflow": asdict(workflow), "checks": [{"url": service+"/help", "visible_selector": "#help"}]}
    base = replace(BROWSER_TARGET, target_kind=kind, allowed_origins=("http://login-fixture.test",))
    args = {"as_principal": "primary", **({"origin": service} if explicit else {})}
    prepared = prepare_hunt_browser_action(CAP, target=base, base_url="http://login-fixture.test",
                                          args=args, context=CONTEXT, policy=asdict(BROWSER_POLICY))
    browser, sender = BrowserFixture(), Sender()
    async def noop(): pass
    @asynccontextmanager
    async def material():
        yield BrowserLoginMaterial(config, BrowserLoginValues(fixture.VALUES.username, fixture.SECRET), noop)
    @asynccontextmanager
    async def factory():
        yield browser
    async def scenario():
        result = await BrowserLoginAdapter(prepared, credential_loader=material, policy=BROWSER_POLICY,
                                           browser_factory=factory, sender=sender).execute(heartbeat=noop, cancelled=lambda: False)
        assert result.status == "success", result
        assert sender.requests and all(r.url.startswith(service+"/") for r in sender.requests)
        assert sum(r.method == "POST" for r in sender.requests) == 1
    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["web", "network", "device"])
def test_browser_credential_worker_uses_correct_live_inventory(monkeypatch, kind):
    from dataclasses import asdict
    from tests.test_browser_login_worker import setup, Conn
    from tests.test_browser_login_action import TARGET as T, POLICY as P, CONTEXT, ORIGIN, CAP, OWNER_ID
    from capabilities.browser_login_worker import browser_login_material, prepare_hunt_browser_action

    original = Conn.fetchrow
    async def fetch(self, query, *args):
        if "FROM device_targets" in query:
            return {"url": "login-fixture.test", "is_active": True}
        return await original(self, query, *args)
    monkeypatch.setattr(Conn, "fetchrow", fetch)
    async def scenario():
        conn, pool, decrypted = await setup(monkeypatch, "hunt")
        conn.profile["target_kind"] = kind
        conn.context["target"] = {"locator": "login-fixture.test"} if kind == "device" else {"url": ORIGIN}
        prepared = prepare_hunt_browser_action(CAP, target=replace(T, target_kind=kind), base_url=ORIGIN,
                                               args={"as_principal": "primary"}, context=CONTEXT, policy=asdict(P))
        async with browser_login_material(pool, prepared=prepared, owner_kind="hunt", owner_id=OWNER_ID, policy=P) as loaded:
            assert loaded.values.password
            await loaded.revalidate()
        assert len(decrypted) == 2
    asyncio.run(scenario())


def test_native_device_adapter_inherits_hunt_limits_past_forty_requests():
    from hunt.device_policy import DeviceHuntPolicyState
    import device_agent
    policy = DeviceHuntPolicyState.initial(safety_profile="authenticated_active", fragility_limit=100, request_limit=75, scan_limit=8)
    state = policy.adapter_state(credential_refs=[], collection_refs=[])
    assert state["scan_budget_limit"] == 8
    for index in range(75):
        assert device_agent.reserve_device_http_attempt(state, now_monotonic=10+index*2) == index+1
    with pytest.raises(device_agent.DeviceHttpAttemptRejected):
        device_agent.reserve_device_http_attempt(state, now_monotonic=200)


def test_tls_planner_accepts_service_origin_without_scan_internal_counts():
    from runtime.capability_registry import CAPABILITY_REGISTRY
    assert CAPABILITY_REGISTRY.validate_hunt_input("tls.inspect", {"origin": "https://fixture.test:9443"}) == {"origin": "https://fixture.test:9443"}
