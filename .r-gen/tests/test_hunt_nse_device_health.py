"""Exercise the production network settlement call, not a fake NSE health label."""
from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from hunt.device_traffic import settle_device_traffic, require_worker_device_policy
from tests.test_hunt_device_traffic import DeviceStore, admit


def network_settlement(store, *, capability="service.nse_check", status="partial"):
    # Execute the actual call site unchanged with real policy reconciliation and
    # database I/O doubled. A missing NSE override must fail these regressions.
    tree = ast.parse((Path(__file__).resolve().parents[1] / "api/worker.py").read_text())
    worker = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef)
                  and n.name == "process_canonical_network_capability_job")
    calls = [n for n in ast.walk(worker) if isinstance(n, ast.Await)
             and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
             and n.value.func.id == "settle_device_traffic"]
    assert len(calls) == 1
    module = ast.parse("async def settle():\n    pass\n")
    module.body[0].body = [ast.Expr(value=calls[0])]
    actual = {"http_requests": 1, "tcp_ports_attempted": 1}
    namespace = dict(settle_device_traffic=settle_device_traffic, conn=store, locked=store.run,
                     latest=SimpleNamespace(record=SimpleNamespace(requested={"device_fragility_points": 4})),
                     actual=actual, action_status=status, capability_name=capability)
    exec(compile(ast.fix_missing_locations(module), "<production-network-settlement>", "exec"), namespace)
    return namespace["settle"](), actual


@pytest.mark.parametrize("status", ["partial", "failed", "cancelled", "completed"])
def test_nse_coverage_does_not_invent_device_failure_or_clear_previous_failure(status):
    async def run():
        store = DeviceStore(consecutive_health_failures=1, minimum_request_interval_ms=0)
        for _ in range(3):
            call, actual = network_settlement(store, status=status)
            await call
            assert actual["device_fragility_points"] == 1
        state = store.run["context_pack"]["device_policy_state"]
        assert state["consecutive_health_failures"] == 1
        assert not state["traffic_frozen"]
        assert state["requests_used"] == state["fragility_used"] == 3
        assert state["last_request_at"]
        require_worker_device_policy(store.run)
        await admit(store, "http.request", {"path": "/"})
        assert store.actions  # A partial NSE check did not lock out the operator.
    asyncio.run(run())


@pytest.mark.parametrize("reason", ["operator_pause", "health_degradation", "policy_violation"])
def test_nse_completion_preserves_existing_freeze_and_reason(reason):
    async def run():
        store = DeviceStore(traffic_frozen=True, freeze_reason=reason, consecutive_health_failures=2)
        for _ in range(2):
            call, _ = network_settlement(store, status="completed")
            await call
        state = store.run["context_pack"]["device_policy_state"]
        assert state["traffic_frozen"] and state["freeze_reason"] == reason
        assert state["consecutive_health_failures"] == 2
        with pytest.raises(ValueError, match="frozen"):
            require_worker_device_policy(store.run)
    asyncio.run(run())


def test_other_network_health_behavior_remains_intact():
    async def run():
        store = DeviceStore()
        for _ in range(2):
            call, _ = network_settlement(store, capability="ports.discover", status="failed")
            await call
        assert store.run["context_pack"]["device_policy_state"]["traffic_frozen"]
        assert store.run["context_pack"]["device_policy_state"]["consecutive_health_failures"] == 2
    asyncio.run(run())
