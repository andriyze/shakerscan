"""Behavioral admission, preparation and settlement across device worker placements."""
import asyncio
import json
import sys
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "api"), str(ROOT / "scanner")]

from hunt.device_policy import DeviceHuntPolicyState
from hunt.device_traffic import (
    require_device_admission, reserve_device_traffic, settle_device_traffic,
    require_worker_device_policy,
)
from hunt.target_binding import web_hunt_target
from capabilities.inline import HttpRequestExecutionAdapter
from capabilities.browser import browser_capability_adapter, BrowserCapabilityInputError
from capabilities.browser_login_worker import prepare_hunt_browser_action
from capabilities.network import network_capability_adapter, CapabilityInputError
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy
from tests.test_hunt_authz_verification_limit import AdmissionStore, admission, Lifecycle, HUNT


class DeviceStore(AdmissionStore):
    def __init__(self, **state):
        super().__init__()
        self.busy = False
        self.daily = 0
        self.run.update(target_kind="device", target_id=None, device_target_id=uuid.UUID(int=2))
        self.run["context_pack"] = {
            "target": {"locator": "192.0.2.10"},
            "authorized_target_addresses": ["192.0.2.10"],
            "device_policy_state": DeviceHuntPolicyState(**state).public_dict(),
        }
        self.run["budget_json"].update(max_device_fragility_points=40, max_hosts=4,
                                      max_tcp_ports=40, max_browser_actions=40)
        self.run["policy_json"].update(active_testing=True, network_discovery=True,
                                       approval_receipt_id="receipt")

    async def fetchrow(self, sql, *args):
        if "FROM device_targets" in sql:
            return {"primary_locator": "192.0.2.10", "is_active": True}
        return await super().fetchrow(sql, *args)

    async def fetchval(self, sql, *args):
        if "SELECT EXISTS" in sql:
            return self.busy
        if "FROM device_agent_actions" in sql:
            return 0
        if "JOIN hunt_runs" in sql:
            return self.daily
        raise AssertionError(sql)

    async def execute(self, sql, *args):
        if "pg_advisory_xact_lock" in sql:
            return "SELECT 1"
        if "UPDATE hunt_runs SET context_pack" in sql:
            self.run["context_pack"] = json.loads(args[1])
            return "UPDATE 1"
        return await super().execute(sql, *args)


async def admit(store, name="http.request", values=None, key="device-attempt-1"):
    fn = admission(store)
    fn.__globals__.update(
        reserve_device_traffic=reserve_device_traffic,
        require_device_admission=require_device_admission,
        web_hunt_target=web_hunt_target,
        network_capability_adapter=network_capability_adapter,
        prepare_hunt_browser_action=prepare_hunt_browser_action,
        CapabilityInputError=CapabilityInputError,
        BrowserCapabilityInputError=BrowserCapabilityInputError,
        ScanPolicy=ScanPolicy,
        _hunt_public=lambda *a, **kw: {"capabilities": [{"name": name}]},
    )
    lifecycle = Lifecycle(name)
    lifecycle.specification = CAPABILITY_REGISTRY.require(name)
    lifecycle.placement = lifecycle.specification.hunt_executor
    return await fn(str(HUNT), name, SimpleNamespace(input=values or {}, idempotency_key=key), lifecycle)


@pytest.mark.parametrize("name,values", [
    ("http.request", {"path": "/"}),
    ("browser.navigate", {"path": "/", "max_requests": 2}),
    ("ports.discover", {"ports": [80]}),
])
def test_real_admission_rejects_frozen_device_for_every_worker_placement(name, values):
    store = DeviceStore(traffic_frozen=True)
    with pytest.raises(HTTPException, match="frozen"):
        asyncio.run(admit(store, name, values))
    assert not store.actions


@pytest.mark.parametrize("name,values", [
    ("http.request", {"path": "/"}),
    ("browser.navigate", {"path": "/", "max_requests": 2}),
    ("ports.discover", {"ports": [80]}),
])
def test_real_admission_accepts_device_and_reserves_fragility(name, values):
    store = DeviceStore()
    asyncio.run(admit(store, name, values))
    assert store.actions
    assert store.run["budget_used_json"]["device_fragility_points"] > 0


@pytest.mark.parametrize("busy,daily,message", [(True, 0, "in flight"), (False, 10000, "Daily fragility")])
def test_ordinary_http_obeys_shared_device_limits(busy, daily, message):
    store = DeviceStore()
    store.busy, store.daily = busy, daily
    with pytest.raises(HTTPException, match=message):
        asyncio.run(admit(store))
    assert not store.actions


def test_http_completion_retains_fragility_and_updates_pacing_and_request_limit():
    async def scenario():
        store = DeviceStore(request_limit=2)
        requested = {"agent_actions": 1, "http_requests": 1, "tool_wall_seconds": 15}
        spec = CAPABILITY_REGISTRY.require("http.request")
        reserve_device_traffic(store.run, spec, requested)
        async def operation():
            return {"ok": True, "request": {"method": "GET"}, "response": {"status": 200}}
        result = await HttpRequestExecutionAdapter(
            specification=spec, operation=operation, requested_budget=requested,
            redacted_execution={},
        ).execute(heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False)
        actual = dict(result.actual_budget)
        await settle_device_traffic(store, store.run, requested, actual, status="completed")
        assert actual["device_fragility_points"] == 1
        state = store.run["context_pack"]["device_policy_state"]
        assert state["requests_used"] == state["fragility_used"] == 1
        assert state["last_request_at"]
        with pytest.raises(HTTPException, match="pacing"):
            await admit(store)
        state = store.run["context_pack"]["device_policy_state"]
        state["last_request_at"] = None
        state["requests_used"] = 2
        with pytest.raises(HTTPException, match="request limit"):
            await admit(store)
    asyncio.run(scenario())


def test_failure_freezes_device_and_dispatch_rechecks_freeze():
    async def scenario():
        store = DeviceStore()
        for _ in range(2):
            await settle_device_traffic(store, store.run, {"device_fragility_points": 3},
                                        {"http_requests": 1}, status="failed")
        state = store.run["context_pack"]["device_policy_state"]
        assert state["traffic_frozen"] and state["fragility_used"] == 2
        with pytest.raises(ValueError, match="frozen"):
            require_worker_device_policy(store.run)
    asyncio.run(scenario())


def test_nonexecuting_action_does_not_charge_or_advance_pacing():
    async def scenario():
        store = DeviceStore()
        actual = {"agent_actions": 1}
        await settle_device_traffic(store, store.run, {"device_fragility_points": 2}, actual, status="blocked")
        assert actual["device_fragility_points"] == 0
        assert not store.run["context_pack"]["device_policy_state"]["last_request_at"]
    asyncio.run(scenario())


def test_shared_binding_prepares_device_browser_with_exact_origin_and_identity():
    store = DeviceStore()
    target, url = web_hunt_target(store.run, store.run["context_pack"], store.run["policy_json"])
    prepared = browser_capability_adapter("browser.navigate").prepare(
        target=target, base_url=url, args={"path": "/", "max_requests": 2},
    )
    assert prepared.target.target_id == str(store.run["device_target_id"])
    assert target.allowed_origins == ("http://192.0.2.10",)
    with pytest.raises(BrowserCapabilityInputError):
        browser_capability_adapter("browser.navigate").prepare(
            target=replace(target, allowed_origins=()), base_url=url, args={"path": "/"},
        )
