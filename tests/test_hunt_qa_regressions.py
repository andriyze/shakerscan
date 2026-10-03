"""Behavioral regressions reproduced while manually driving release Hunts."""
from __future__ import annotations
import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timezone
import json
from types import SimpleNamespace
import uuid
import pytest

from hunt import http_principal, worker_failure
from hunt.action_service import HuntActionService, LIFECYCLE_PHASES
from hunt.endpoint_knowledge import crawl_worklist, enrich_crawl_endpoints
from hunt.run_service import public_hunt_action
from runtime.budget_reservations import DurableBudgetReservation
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.auth_session_store import AuthSessionStoreError
from runtime.credential_resolver import CredentialResolutionError
from runtime import ai_settings_secrets, ai_template_secrets
import secret_store
import agent_tools


@pytest.fixture
def encryption(monkeypatch):
    from cryptography.fernet import Fernet
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_loaded", False)
    monkeypatch.setattr(secret_store, "_fernet", None)


def test_reviewed_hunt_pack_admits_at_its_server_owned_ceiling():
    ceiling = agent_tools.canonical_hunt_scanner_budget("templates.scan")
    selected = agent_tools.canonical_hunt_scanner_options("templates.scan", {})
    assert ceiling["http_requests"] == selected["template_request_cost_upper_bound"] == 7
    assert ceiling["http_requests"] < 500
    assert agent_tools.canonical_hunt_scanner_budget("sqli.verify") == dict(CAPABILITY_REGISTRY.require("sqli.verify").budget_cost)
    with pytest.raises(Exception):
        agent_tools.canonical_hunt_scanner_options("templates.scan", {"template_request_cost_upper_bound": 1})


def test_conservative_scanner_charge_is_never_called_exact():
    result = public_hunt_action({"id": uuid.uuid4(), "status": "completed", "receipt_id": uuid.uuid4(),
        "result_summary": {"budget_accounting": {"reservation_id": str(uuid.uuid4()),
            "settlement_status": "succeeded", "charge_basis": "conservative_enforced_ceiling",
            "reserved": {"http_requests": 7}, "actual": {"http_requests": 7}}}})
    assert result["result"]["budget_accounting"]["basis"] == "conservative_settlement"


def test_failed_worker_lifecycle_does_not_claim_success_or_settlement():
    async def operation(lifecycle):
        for phase in LIFECYCLE_PHASES[1:-2]:
            lifecycle.advance(phase)
        lifecycle.mark_failure(RuntimeError("settlement unavailable"))
        return {"action_result": {"status": "failed"}}
    result = asyncio.run(HuntActionService().execute("http.request", {"method":"GET", "path": "/"}, operation))
    assert result["lifecycle"]["outcome"] == "failed"
    assert "settled" not in [item["phase"] for item in result["lifecycle"]["phases"]]


def test_crawl_knowledge_filters_services_and_remains_unexamined(monkeypatch):
    records = [{"kind": "discovered_route", "url": value, "method": "GET"} for value in [
        "http://app.test:8081/api/search?q=redacted", "http://app.test:8081/main.js",
        "http://other.test:8081/admin", "http://app.test:8082/admin", "http://u:p@app.test:8081/",
        "http://app.test:8081/api/search?q=redacted"]]
    assert crawl_worklist(records, origin="http://app.test:8081") == ["GET /api/search?q=redacted", "GET /main.js"]
    calls = []
    async def upsert(conn, target_id, worklist, **kwargs):
        calls.append((target_id, worklist, kwargs)); return len(worklist)
    monkeypatch.setattr("hunt.endpoint_knowledge.asm_inventory.upsert_endpoints", upsert)
    count = asyncio.run(enrich_crawl_endpoints(None, target=SimpleNamespace(target_kind="web", target_id="owned"),
        origin="http://app.test:8081", capability="web.crawl", input={}, records=records))
    assert count == 2 and calls[0][2] == {"source": "hunt_discovery", "auth_state": "anonymous"}
    assert asyncio.run(enrich_crawl_endpoints(None, target=SimpleNamespace(target_kind="network"),
        origin="host://app.test", capability="web.crawl", input={}, records=records)) == 0


class Redis:
    def __init__(self, values): self.values = dict(values)
    def hgetall(self, _name): return dict(self.values)
    def eval(self, _script, _count, _name, field, old, new):
        if self.values[field] == old: self.values[field] = new


def test_provider_key_encrypts_and_legacy_backfill_keeps_runtime_value(encryption):
    protected = ai_settings_secrets.protect_settings({"ai_api_key": "canary-provider-secret", "ai_model": "fixture"})
    assert "canary-provider-secret" not in json.dumps(protected)
    redis = Redis(protected)
    assert ai_settings_secrets.load_settings(redis, "settings:ai")["ai_api_key"] == "canary-provider-secret"
    legacy = Redis({"ai_api_key": "legacy-canary"})
    assert ai_settings_secrets.load_settings(legacy, "settings:ai")["ai_api_key"] == "legacy-canary"
    assert legacy.values["ai_api_key"].startswith("enc:fernet:")
    # A concurrent operator write must win the migration CAS.
    def concurrent(_script, _count, _name, field, old, new): legacy.values[field] = protected[field]
    legacy.values["ai_api_key"] = "legacy-canary"
    legacy.eval = concurrent
    ai_settings_secrets.load_settings(legacy, "settings:ai")
    assert legacy.values["ai_api_key"] == protected["ai_api_key"]


def test_entire_body_template_is_encrypted_and_masked_edit_keeps_secret(encryption):
    template = {"model": "fixture", "input": "{{prompt}}", "nested": [{"api_key": "body-canary"}],
        "arbitrary_field": "also-encrypted-canary"}
    stored = ai_template_secrets.protect(template)
    assert "body-canary" not in json.dumps(stored) and "also-encrypted-canary" not in json.dumps(stored)
    shown = ai_template_secrets.public(stored)
    assert shown["nested"][0]["api_key"] == "***"
    shown["model"] = "edited-model"
    edited = ai_template_secrets.protect(shown, stored)
    assert ai_template_secrets.reveal(edited)["nested"][0]["api_key"] == "body-canary"
    assert ai_template_secrets.reveal(edited)["model"] == "edited-model"
    with pytest.raises(ValueError): ai_template_secrets.protect({"input": "{{prompt}}", "api_key": "***"})


def test_body_template_and_provider_secret_writes_fail_closed(monkeypatch):
    monkeypatch.setattr(secret_store, "_loaded", True)
    monkeypatch.setattr(secret_store, "_fernet", None)
    with pytest.raises(secret_store.SecretStoreUnavailable): ai_template_secrets.protect({"input": "{{prompt}}"})
    with pytest.raises(secret_store.SecretStoreUnavailable): ai_settings_secrets.protect_settings({"ai_api_key": "canary"})


@pytest.mark.parametrize("invalid", [False, True])
def test_selected_interactive_principal_reuses_only_a_revalidated_session(monkeypatch, invalid):
    profile = str(uuid.uuid4()); target = SimpleNamespace(target_id=str(uuid.uuid4()))
    context = {"credential_refs": [{"source": "credential_profiles", "profile_id": profile,
        "profile_version": 2, "principal_slot": "primary", "allowed_capabilities": ["http.request"]}]}
    @asynccontextmanager
    async def resolve(*args, **kwargs):
        yield SimpleNamespace(profile=SimpleNamespace(current_version=2, principal_slot="primary", auth_kind="json_login"))
    monkeypatch.setattr(http_principal, "WorkerCredentialResolver", lambda: SimpleNamespace(resolve=resolve))
    session = SimpleNamespace(headers=lambda: {"Authorization": "Bearer fixture-session"})
    class Connection:
        async def fetch(self, query, *args):
            assert args[1] == uuid.UUID(target.target_id) and args[2] == uuid.UUID(profile) and args[3:]==(2,"primary")
            return [{"id": uuid.uuid4()}]
    class Store:
        async def load_for_worker(self, conn, **kwargs):
            assert kwargs["target"] is target and kwargs["selected_origins"] == ("http://app.test:8081",)
            if invalid: raise AuthSessionStoreError("revoked")
            return session
    async def run():
        async with AsyncExitStack() as stack:
            return await http_principal.resolve_http_principal(Connection(), context=context, target=target,
                authority=object(), hunt_id=uuid.uuid4(), principal="primary", origin="http://app.test:8081",
                stack=stack, session_store=Store())
    if invalid:
        with pytest.raises(CredentialResolutionError, match="No compatible current login"): asyncio.run(run())
    else:
        assert asyncio.run(run()) == ({"Authorization": "Bearer fixture-session"}, session)


@pytest.mark.parametrize("started", [False, True])
def test_worker_failure_preserves_cause_and_atomically_settles_lease(monkeypatch, started):
    owner, action_id = str(uuid.uuid4()), str(uuid.uuid4())
    amounts = {"agent_actions": 1, "active_actions": 1, "http_requests": 1, "tool_wall_seconds": 60}
    requested = DurableBudgetReservation.request(owner_kind="hunt", owner_id=owner, capability_name="http.request",
        amounts=amounts, reservation_id=str(uuid.uuid4()))
    reserved, held = requested.reserve_against(limits={k:v*10 for k,v in amounts.items()}, consumed={k:0 for k in amounts}, lease_seconds=90)
    record = reserved.start(worker_id="fixture-worker", lease_seconds=90)
    persisted = SimpleNamespace(record=record, action_id=action_id, action_digest="a"*64)
    writes = []
    class Connection:
        @asynccontextmanager
        async def transaction(self): yield self
        async def fetchrow(self, query, *args): return {"id": uuid.UUID(owner), "budget_used_json": held}
        async def execute(self, query, *args): writes.append((query,args)); return "UPDATE 1"
    class Pool:
        @asynccontextmanager
        async def acquire(self): yield Connection()
    class Store:
        async def load(self, *args, **kwargs): return persisted
        async def persist_terminal(self, conn, **kwargs):
            assert kwargs["receipt"].errors == ("contract:no current login",)
            assert kwargs["terminal"].terminal
            writes.append(("terminal", kwargs))
    async def no_device(*args, **kwargs): pass
    monkeypatch.setattr(worker_failure,"settle_device_traffic",no_device)
    result = asyncio.run(worker_failure.settle_worker_failure(Pool(), Store(), persisted,
        result={"status":"failed","error":"contract:no current login","durable_budget_settled":False},
        target=SimpleNamespace(target_id=str(uuid.uuid4()),target_kind="web",scope_receipt_id=None),
        policy=SimpleNamespace(approval_receipt_id=None),spec=CAPABILITY_REGISTRY.require("http.request"),execution_started=started))
    assert result["durable_budget_settled"] and result["receipt_id"] and result["error"]=="contract:no current login"
    assert result["budget_consumed"]["http_requests"] == int(started)
    assert result["budget_consumed"]["active_actions"] == int(started)
    assert any("UPDATE hunt_actions" in query for query,_ in writes)
