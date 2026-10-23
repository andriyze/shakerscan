"""A network action is charged what the commands that started attempted; device fragility counts
every connection.

Ports and hosts are charged once per Hunt (hunt/distinct_accounting.py), but a device's fragility
ceiling, its per-Hunt request limit and its daily allowance bound how hard the device is pushed,
so they count every connection: a re-sweep of ports a Hunt already attempted, or the ten
handshakes of a ``tls.inspect``, still cost a fragility point per connection. Before 2.11.1's
fix both settled one point (a 100-port re-sweep held 100 and settled 1).

A run stopped part way (cancelled after its first address) is charged the new hosts and ports of
the commands that started, not the hold spread evenly over its commands, and a command that never
started records nothing as attempted.

Command output and database rows are labelled fixtures; admission, the worker's reconstruction,
the network adapter, the executor's clamp and the device settlement are production code.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from capabilities.inline import TlsInspectionExecutionAdapter
from capabilities.network import NetworkExecutionAdapter, network_capability_adapter
from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from hunt.device_traffic import reserve_device_traffic, settle_device_traffic
from hunt.distinct_accounting import bound_distinct_usage, distinct_charge, record_attempted_usage
from hunt.port_accounting import CONTEXT_KEY, tls_port_usage
from hunt.target_binding import web_hunt_target
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy, TargetBinding
from tests.test_hunt_device_traffic import DeviceStore, admit
from tests.test_hunt_safety_ceilings import Updates

ROOT = Path(__file__).resolve().parents[1]
DEVICE = "192.0.2.10"
A, B = "192.0.2.10", "192.0.2.11"
POLICY = ScanPolicy(active_testing=True, network_discovery=True, approval_receipt_id="receipt")


class Ran:
    """A scripted scanner process (fixture): it exits cleanly, or is cancelled, with no output."""

    def __init__(self, cancelled=False):
        self.returncode, self.stdout, self.timed_out, self.partial = 0, "", False, False
        self.stdout_truncated, self.cancelled = False, cancelled


def _runner(cancel_after=None):
    calls = []

    async def run(argv, **_kwargs):
        calls.append(next((item for item in argv if item in {A, B}), None))
        return Ran(cancelled=cancel_after is not None and len(calls) >= cancel_after)
    return run, calls


async def _beat():
    return None


def _execute(name, target, prepared, requested, attempted, runner):
    adapter = NetworkExecutionAdapter(prepared=prepared, parser=network_capability_adapter(name),
                                      command_runner=runner, max_stdout_bytes=10_000, max_stderr_bytes=1_000,
                                      command_usage=attempted.command_usage)
    context = CapabilityExecutionContext(specification=CAPABILITY_REGISTRY.require(name), target=target,
                                         requested_budget=requested)
    return asyncio.run(CapabilityExecutor().execute(context, adapter, heartbeat=_beat, cancelled=lambda: False))


def _device_worker(store, name, values):
    """The worker's reconstruction of an admitted device action: estimate, call units, device
    envelope, then the distinct hold admission reserved."""
    target, _ = web_hunt_target(store.run, store.run["context_pack"], store.run["policy_json"])
    prepared = network_capability_adapter(name).prepare(target=target, args=values, policy=POLICY)
    limits = {"agent_actions", "active_actions", "tcp_ports_attempted", "hosts_attempted", "udp_ports_attempted",
              "tool_wall_seconds", "device_fragility_points"}
    requested = {key: int(value) for key, value in prepared.estimated_budget.items() if key in limits}
    requested.update(agent_actions=1, active_actions=1)
    reserve_device_traffic(store.run, CAPABILITY_REGISTRY.require(name), requested)
    admitted = {key: value for key, value in store.run["budget_used_json"].items() if value}
    requested, prepared, attempted = bound_distinct_usage(requested, prepared, admitted, store.run["context_pack"])
    assert requested == admitted
    return target, prepared, requested, attempted


def _device_store(attempted_ports):
    store = DeviceStore(request_limit=100, fragility_limit=100)
    store.run["budget_json"].update(max_device_fragility_points=100, max_tcp_ports=100)
    store.run["context_pack"].update({CONTEXT_KEY: {DEVICE: attempted_ports},
                                      "hosts_attempted_addresses": [DEVICE]})
    return store


def test_a_device_resweep_of_attempted_ports_charges_fragility_for_every_connection():
    """A 30-port re-sweep needs no TCP allowance but makes 30 connections: it settles 30
    fragility points and 30 device requests, not one."""
    store = _device_store("1-30")
    values = {"ports": list(range(1, 31))}
    asyncio.run(admit(store, "ports.discover", values))
    assert store.run["budget_used_json"]["device_fragility_points"] == 30
    assert not store.run["budget_used_json"].get("tcp_ports_attempted")
    target, prepared, requested, attempted = _device_worker(store, "ports.discover", values)
    runner, _calls = _runner()
    result = _execute("ports.discover", target, prepared, requested, attempted, runner)
    actual = dict(result.actual_budget)
    assert "tcp_ports_attempted" not in actual
    asyncio.run(settle_device_traffic(store, store.run, requested, actual, status="completed"))
    assert actual["device_fragility_points"] == 30
    state = store.run["context_pack"]["device_policy_state"]
    assert state["fragility_used"] == state["requests_used"] == 30


def test_a_device_sweep_of_some_new_ports_charges_the_new_ports_and_every_connection():
    store = _device_store("1-20")
    values = {"port_range": "1-30"}
    asyncio.run(admit(store, "ports.discover", values))
    used = store.run["budget_used_json"]
    assert used["tcp_ports_attempted"] == 10 and used["device_fragility_points"] == 30
    target, prepared, requested, attempted = _device_worker(store, "ports.discover", values)
    runner, _calls = _runner()
    actual = dict(_execute("ports.discover", target, prepared, requested, attempted, runner).actual_budget)
    asyncio.run(settle_device_traffic(store, store.run, requested, actual, status="completed"))
    assert actual["tcp_ports_attempted"] == 10 and actual["device_fragility_points"] == 30


def test_a_device_fingerprint_of_ports_a_sweep_found_charges_fragility_for_each_port():
    store = _device_store("1-30")
    values = {"ports": [22, 23, 25]}
    asyncio.run(admit(store, "service.fingerprint", values))
    target, prepared, requested, attempted = _device_worker(store, "service.fingerprint", values)
    runner, _calls = _runner()
    actual = dict(_execute("service.fingerprint", target, prepared, requested, attempted, runner).actual_budget)
    asyncio.run(settle_device_traffic(store, store.run, requested, actual, status="completed"))
    assert "tcp_ports_attempted" not in actual and actual["device_fragility_points"] == 3


def test_a_device_tls_inspect_charges_fragility_for_every_handshake():
    """Ten handshakes are one port (none when the port was attempted) and ten fragility points."""
    spec = CAPABILITY_REGISTRY.require("tls.inspect")
    target = TargetBinding(target_id="device-1", target_kind="device", canonical_host=DEVICE,
                           allowed_origins=(f"https://{DEVICE}",), allowed_addresses=(DEVICE,),
                           scope_receipt_id="scope")
    charges = {key: int(value) for key, value in spec.budget_cost.items()}
    store = DeviceStore()
    reserve_device_traffic(store.run, spec, charges)
    assert charges["device_fragility_points"] == 10
    for port_hold in ({"tcp_ports_attempted": 1}, {}):
        reserved = {**{key: value for key, value in charges.items() if key != "tcp_ports_attempted"}, **port_hold}

        async def operation(reserved=reserved):
            measured = {"ok": True, "budget_consumed": {"tcp_ports_attempted": 10, "tool_wall_seconds": 3}}
            return tls_port_usage(measured, reserved)
        adapter = TlsInspectionExecutionAdapter(specification=spec, operation=operation,
                                                requested_budget=reserved, redacted_execution={})
        context = CapabilityExecutionContext(specification=spec, target=target, requested_budget=reserved)
        result = asyncio.run(CapabilityExecutor().execute(context, adapter, heartbeat=_beat,
                                                          cancelled=lambda: False))
        assert result.status == "success"
        actual = dict(result.actual_budget)
        assert actual.get("tcp_ports_attempted", 0) == port_hold.get("tcp_ports_attempted", 0)
        asyncio.run(settle_device_traffic(store, store.run, reserved, actual, status="completed"))
        assert actual["device_fragility_points"] == 10
    state = store.run["context_pack"]["device_policy_state"]
    assert state["fragility_used"] == state["requests_used"] == 20
    # No handshake: no fragility and no attempt.
    unsent = tls_port_usage({"ok": False, "budget_consumed": {"tcp_ports_attempted": 0}}, charges)
    assert unsent["budget_consumed"]["device_fragility_points"] == 0 and unsent["execution_started"] is False


# --- a run stopped part way --------------------------------------------------------------------


def _two_address_sweep(context, ports):
    target = TargetBinding(target_id="network-1", target_kind="network", canonical_host=None,
                           allowed_addresses=(A, B), scope_receipt_id="scope")
    prepared = network_capability_adapter("ports.discover").prepare(target=target, args={"ports": ports},
                                                                     policy=POLICY)
    assert [command.destination_address for command in prepared.commands] == [A, B]
    requested = {key: int(value) for key, value in prepared.estimated_budget.items()}
    admitted = distinct_charge(context, prepared, requested)
    requested, prepared, attempted = bound_distinct_usage(requested, prepared, admitted, context)
    return target, prepared, requested, attempted


def test_a_sweep_cancelled_after_its_new_address_is_charged_every_port_that_address_was_sent():
    """B's ports 1-100 were attempted; A's were not. Cancelled after A's command, the sweep
    attempted A's 100 new ports and is charged 100 (pro rata gave 50)."""
    context = {CONTEXT_KEY: {B: "1-100"}, "hosts_attempted_addresses": [A, B]}
    target, prepared, requested, attempted = _two_address_sweep(context, list(range(1, 101)))
    assert requested["tcp_ports_attempted"] == 100
    runner, calls = _runner(cancel_after=1)
    result = _execute("ports.discover", target, prepared, requested, attempted, runner)
    assert calls == [A] and result.status == "cancelled"
    assert result.actual_budget["tcp_ports_attempted"] == 100
    # Every port the hold reserved was attempted: they are remembered.
    connection = Updates()
    asyncio.run(record_attempted_usage(connection, hunt_id="hunt-1", run={"context_pack": context},
                                       attempted=attempted, reserved=requested, actual=result.actual_budget))
    assert len(connection.updates) == 1


def test_a_command_that_never_started_is_neither_charged_nor_recorded():
    """A's port 80 and host were attempted, B's were not. Cancelled after A's command, B was sent
    nothing: no port or host is charged, and B is not remembered as attempted (pro rata charged
    the whole one-port, one-host hold and recorded B)."""
    context = {CONTEXT_KEY: {A: "80"}, "hosts_attempted_addresses": [A]}
    target, prepared, requested, attempted = _two_address_sweep(context, [80])
    assert requested["tcp_ports_attempted"] == 1 and requested["hosts_attempted"] == 1
    runner, calls = _runner(cancel_after=1)
    result = _execute("ports.discover", target, prepared, requested, attempted, runner)
    assert calls == [A]
    assert result.actual_budget["tcp_ports_attempted"] == 0 and result.actual_budget["hosts_attempted"] == 0
    connection = Updates()
    asyncio.run(record_attempted_usage(connection, hunt_id="hunt-1", run={"context_pack": context},
                                       attempted=attempted, reserved=requested, actual=result.actual_budget))
    assert connection.updates == []


def test_a_completed_run_settles_exactly_its_hold():
    """Admission held A's ten new ports; another action then recorded A's port 1. The worker
    adopts the hold of ten, and a completed run settles all ten, so its ports are remembered."""
    admitted_context = {CONTEXT_KEY: {B: "1-10"}, "hosts_attempted_addresses": [A, B]}
    target, _prepared, held, _attempted = _two_address_sweep(admitted_context, list(range(1, 11)))
    assert held["tcp_ports_attempted"] == 10
    later = {CONTEXT_KEY: {A: "1", B: "1-10"}, "hosts_attempted_addresses": [A, B]}
    prepared = network_capability_adapter("ports.discover").prepare(
        target=target, args={"ports": list(range(1, 11))}, policy=POLICY)
    estimate = {key: int(value) for key, value in prepared.estimated_budget.items()}
    requested, prepared, attempted = bound_distinct_usage(estimate, prepared, held, later)
    assert requested == held
    runner, _calls = _runner()
    result = _execute("ports.discover", target, prepared, requested, attempted, runner)
    assert result.actual_budget["tcp_ports_attempted"] == 10


def test_the_worker_hands_each_command_s_usage_to_the_network_adapter():
    worker = (ROOT / "api/worker.py").read_text(encoding="utf-8")
    assert "command_usage=attempted.command_usage" in worker
    builder = (ROOT / "api/capabilities/network_execution.py").read_text(encoding="utf-8")
    assert "command_usage=command_usage" in builder
