"""A used-up limit refuses the actions that need it; only the clock ends a Hunt.

A safety ceiling (state-changing requests, TCP ports, hosts, UDP ports, out-of-band interactions,
device fragility) or a call or traffic limit that is used up refuses only the actions that need
it, with a budget.raise request, and the Hunt keeps its status. Only ``max_duration_seconds`` (the
``tool_wall_seconds`` ledger) running out ends it as ``budget_exhausted``. Ports and hosts are
counted once per Hunt, and a verification's state-changing hold settles to what it sent.

Database rows are labelled fixtures; the refusal, settlement, ledger and accounting are production
code. The PostgreSQL scenario is tests/test_hunt_recording_postgres.py.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import uuid

import httpx
import pytest

from capabilities.inline import ControlPlaneExecutionAdapter
from capabilities.network import PortsDiscoverAdapter, ServiceFingerprintAdapter
from capabilities.nse import NseCheckAdapter
from hunt import permission_admission, port_accounting
from hunt.distinct_accounting import Attempted, bound_distinct_usage, distinct_charge, record_attempted_usage
from hunt.permission_admission import PermissionPending, budget_refusal, settle_refusal
from hunt.start_contract import HUNT_BUDGET_PROFILES
from hunt.verification_budget import (
    CLOCK_DIMENSION, record_budget_shortage, verification_traffic_charge, web_candidate_budget,
)
from runtime.budgets import BudgetExceeded, reserve_budget_snapshot
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy, TargetBinding
import workflow_experiment

ROOT = Path(__file__).resolve().parents[1]
HUNT = uuid.UUID(int=7)
ADDRESS = "192.0.2.10"
TARGET = TargetBinding(target_id="target-1", target_kind="network", canonical_host=None,
                       allowed_addresses=(ADDRESS,), scope_receipt_id="scope-1")
POLICY = ScanPolicy(active_testing=True, network_discovery=True, approval_receipt_id="approval-1")
SAFETY = ("state_changing_requests", "tcp_ports_attempted", "hosts_attempted", "udp_ports_attempted",
          "oob_interactions", "device_fragility_points")
WORK = ("agent_actions", "active_actions", "http_requests", "browser_actions")


class Updates:
    def __init__(self):
        self.updates = []

    async def execute(self, query, *args):
        self.updates.append((query, args))


def test_the_safety_ceilings_keep_their_values():
    expected = {
        "fast": (4, 100, 50, 100, 10, 20), "balanced": (20, 1_200, 500, 1_000, 50, 100),
        "thorough": (80, 10_000, 5_000, 5_000, 200, 500),
    }
    for profile, values in expected.items():
        limits = HUNT_BUDGET_PROFILES[profile].ledger_limits()
        assert tuple(limits[dimension] for dimension in SAFETY) == values, profile


@pytest.mark.parametrize("dimension", SAFETY + WORK)
def test_a_used_up_limit_other_than_the_clock_leaves_the_hunt_running(dimension):
    limits = HUNT_BUDGET_PROFILES["balanced"].ledger_limits()
    used = {dimension: limits[dimension]}
    db = Updates()
    result = asyncio.run(record_budget_shortage(db, hunt_id=HUNT, limits=limits, used=used,
                                                shortages={dimension: 1}))
    assert result["error"] == f"budget_exhausted:{dimension}"
    assert result["retryable_with_smaller_action"] is False
    assert db.updates == []


def test_only_the_clock_running_out_ends_the_hunt():
    limits = HUNT_BUDGET_PROFILES["balanced"].ledger_limits()
    for shortages in ({CLOCK_DIMENSION: 15}, {"tcp_ports_attempted": 10, CLOCK_DIMENSION: 15}):
        db = Updates()
        asyncio.run(record_budget_shortage(db, hunt_id=HUNT, limits=limits, shortages=shortages,
                                           used={CLOCK_DIMENSION: limits[CLOCK_DIMENSION], "tcp_ports_attempted": 1_200}))
        assert len(db.updates) == 1
        query, args = db.updates[0]
        assert "status='budget_exhausted'" in query and args == (HUNT, f"budget_exhausted:{CLOCK_DIMENSION}")
    # A clock with time left but too little for this action refuses only the action.
    db = Updates()
    asyncio.run(record_budget_shortage(db, hunt_id=HUNT, limits=limits, shortages={CLOCK_DIMENSION: 15},
                                       used={CLOCK_DIMENSION: limits[CLOCK_DIMENSION] - 5}))
    assert db.updates == []


class _Transaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class SettlementConnection:
    """Labelled fixture: one active Hunt row; every write is recorded."""

    def __init__(self):
        policy = {"active_testing": True, "allow_state_changing_http": True, "network_discovery": True}
        self.run = {"id": HUNT, "status": "active", "completed_at": None, "budget_json": "{}",
                    "target_kind": "network", "context_pack": "{}", "policy_json": json.dumps(policy),
                    "stop_reason": None}
        self.executed = []

    async def fetchrow(self, query, *args):
        return dict(self.run)

    async def execute(self, query, *args):
        self.executed.append(query)
        if "status='budget_exhausted'" in query:
            self.run["status"] = "budget_exhausted"

    def transaction(self):
        return _Transaction()


class Pool:
    def __init__(self, connection):
        self.connection = connection

    def acquire(self):
        connection = self.connection

        class _Acquire:
            async def __aenter__(self):
                return connection

            async def __aexit__(self, *args):
                return False
        return _Acquire()


def _settle(monkeypatch, *, used_dimension, name="http.request"):
    connection = SettlementConnection()
    raised = []

    async def passthrough(*args):
        return args[-1]

    async def no_denial(*args):
        return None

    async def raise_request(conn, **kwargs):
        raised.append(kwargs)
        return {"id": uuid.uuid4(), "kind": kwargs["kind"], "status": "pending", "title": "Raise the limit",
                "expires_at": None, "approve_command": "shakerscan approve x"}, True

    async def not_preauthorized(*args):
        return None

    async def store_refused(conn, **kwargs):
        conn.executed.append(f"park:{kwargs['status']}")

    monkeypatch.setattr(permission_admission, "complete_destination_subject", lambda run, refusal: passthrough(refusal))
    monkeypatch.setattr(permission_admission, "credential_use_refusal", passthrough)
    monkeypatch.setattr(permission_admission, "recent_denial", no_denial)
    monkeypatch.setattr(permission_admission, "raise_request", raise_request)
    monkeypatch.setattr(permission_admission, "try_preauthorized_grant", not_preauthorized)
    monkeypatch.setattr(permission_admission, "public_request", lambda request: {**request, "id": str(request["id"])})
    monkeypatch.setattr(permission_admission, "_store_refused_action", store_refused)
    limits = HUNT_BUDGET_PROFILES["balanced"].ledger_limits()
    used = {used_dimension: limits[used_dimension]}
    charges = {"agent_actions": 1, used_dimension: 1}
    try:
        reserve_budget_snapshot(limits, used, charges)
    except BudgetExceeded as exc:
        refusal = budget_refusal(connection.run, limits=limits, used=used, shortages=exc.shortages, charges=charges)
    else:
        raise AssertionError("the fixture must use the limit up")
    with pytest.raises(PermissionPending) as pending:
        asyncio.run(settle_refusal(Pool(connection), hunt_id=HUNT, action_id=uuid.uuid4(), name=name,
                                   input_summary={}, input_digest="d" * 64, refusal=refusal))
    return connection, raised, pending.value


@pytest.mark.parametrize("dimension", ["state_changing_requests", "tcp_ports_attempted", "hosts_attempted"])
def test_a_used_up_safety_ceiling_parks_the_action_for_a_raise_and_the_hunt_keeps_running(monkeypatch, dimension):
    connection, raised, pending = _settle(monkeypatch, used_dimension=dimension)
    assert connection.run["status"] == "active"
    assert not any("budget_exhausted" in query for query in connection.executed if not query.startswith("park:"))
    assert raised and raised[0]["kind"] == "budget.raise" and raised[0]["reason_code"] == "budget_exhausted"
    assert pending.detail["code"] == "permission_required"
    assert pending.detail["error"] == f"budget_exhausted:{dimension}"
    assert "keeps running" in pending.detail["message"]


def test_a_used_up_clock_parks_the_action_and_ends_the_hunt(monkeypatch):
    connection, raised, pending = _settle(monkeypatch, used_dimension=CLOCK_DIMENSION)
    assert connection.run["status"] == "budget_exhausted"
    assert "Hunt stops" in pending.detail["message"]


# --- distinct ports --------------------------------------------------------------------------


def _prepared(adapter, args):
    return adapter.prepare(target=TARGET, args=args, policy=POLICY)


def test_network_actions_name_their_ports_when_each_command_lists_them():
    assert port_accounting.action_pairs(_prepared(PortsDiscoverAdapter(), {"ports": [22, 443]})) == {
        (ADDRESS, 22), (ADDRESS, 443)}
    assert len(port_accounting.action_pairs(_prepared(PortsDiscoverAdapter(), {"port_range": "8000-8099"}))) == 100
    assert len(port_accounting.action_pairs(_prepared(PortsDiscoverAdapter(), {"profile": "known_services"}))) == 23
    # A top-ports sweep does not name its ports: it keeps its full charge.
    assert port_accounting.action_pairs(_prepared(PortsDiscoverAdapter(), {"profile": "top_1000"})) == frozenset()
    assert port_accounting.action_pairs(_prepared(ServiceFingerprintAdapter(), {"ports": [443, 8443]})) == {
        (ADDRESS, 443), (ADDRESS, 8443)}
    nse = _prepared(NseCheckAdapter(), {"ports": [443], "scripts": ["ssl-enum-ciphers"]})
    assert port_accounting.action_pairs(nse) == {(ADDRESS, 443)}


def test_a_port_the_hunt_already_attempted_needs_no_new_allowance():
    """Balanced: a sweep used up all 1,200 ports; fingerprinting the open ports it found, and a
    TLS inspection of one, reserve nothing from the TCP ceiling and are admitted."""
    limits = HUNT_BUDGET_PROFILES["balanced"].ledger_limits()
    used = {"tcp_ports_attempted": 1_200, "hosts_attempted": 1}
    context = {port_accounting.CONTEXT_KEY: {ADDRESS: "1-1200"}, "hosts_attempted_addresses": [ADDRESS]}
    fingerprint = _prepared(ServiceFingerprintAdapter(), {"ports": [443, 1100]})
    charges = distinct_charge(context, fingerprint, dict(fingerprint.estimated_budget))
    assert "tcp_ports_attempted" not in charges and "hosts_attempted" not in charges
    reserve_budget_snapshot(limits, used, charges)  # admitted
    tls = port_accounting.distinct_port_charge(context, frozenset({(ADDRESS, 443)}),
                                               {"tcp_ports_attempted": 1, "tool_wall_seconds": 15})
    assert tls == {"tool_wall_seconds": 15}
    reserve_budget_snapshot(limits, used, tls)
    # A port the Hunt has not attempted still needs the ceiling, and is refused.
    fresh = _prepared(ServiceFingerprintAdapter(), {"ports": [443, 8443]})
    charges = distinct_charge(context, fresh, dict(fresh.estimated_budget))
    assert charges["tcp_ports_attempted"] == 1
    with pytest.raises(BudgetExceeded) as refused:
        reserve_budget_snapshot(limits, used, charges)
    assert set(refused.value.shortages) == {"tcp_ports_attempted"}


def test_the_worker_adopts_the_admitted_port_hold_and_refuses_a_smaller_one():
    context = {port_accounting.CONTEXT_KEY: {ADDRESS: "443"}}
    prepared = _prepared(ServiceFingerprintAdapter(), {"ports": [443, 8443]})
    requested = {key: int(value) for key, value in prepared.estimated_budget.items()}
    admitted = distinct_charge(context, prepared, requested)
    budget, bounded, attempted = bound_distinct_usage(requested, prepared, admitted, context)
    assert budget == admitted and bounded.estimated_budget["tcp_ports_attempted"] == 1
    assert attempted.pairs == {(ADDRESS, 443), (ADDRESS, 8443)}
    # A zero hold for a port the Hunt has not attempted is not adopted: the digests disagree.
    budget, bounded, _ = bound_distinct_usage(requested, prepared, {**admitted, "tcp_ports_attempted": 0}, context)
    assert budget["tcp_ports_attempted"] == 2 and bounded.estimated_budget["tcp_ports_attempted"] == 2


def test_settlement_records_measured_ports_and_the_open_ports_a_sweep_saw():
    connection = Updates()
    run = {"context_pack": {port_accounting.CONTEXT_KEY: {ADDRESS: "22"}}}
    pairs = frozenset({(ADDRESS, 443), (ADDRESS, 444), (ADDRESS, 445)})
    asyncio.run(record_attempted_usage(
        connection, hunt_id=HUNT, run=run, attempted=Attempted(pairs=pairs),
        reserved={"tcp_ports_attempted": 3}, actual={"tcp_ports_attempted": 3},
        observations=[{"kind": "open_port", "address": "192.0.2.11", "port": 8080, "transport": "tcp"},
                      {"kind": "open_port", "address": ADDRESS, "port": 53, "transport": "udp"}]))
    (query, args), = connection.updates
    assert args[1] == [port_accounting.CONTEXT_KEY]
    assert json.loads(args[2]) == {ADDRESS: "22,443-445", "192.0.2.11": "8080"}
    # A hold that was not wholly measured records nothing but what the sweep saw open.
    connection = Updates()
    asyncio.run(record_attempted_usage(
        connection, hunt_id=HUNT, run=run, attempted=Attempted(pairs=pairs),
        reserved={"tcp_ports_attempted": 3}, actual={"tcp_ports_attempted": 2}, observations=[]))
    assert connection.updates == []
    assert port_accounting.attempted_pairs({port_accounting.CONTEXT_KEY: {ADDRESS: "22,443-445"}}) == {
        (ADDRESS, 22), (ADDRESS, 443), (ADDRESS, 444), (ADDRESS, 445)}


def test_tls_handshakes_count_as_the_one_port_they_attempt():
    measured = {"ok": True, "budget_consumed": {"tcp_ports_attempted": 10, "tool_wall_seconds": 3}}
    assert port_accounting.tls_port_usage(measured, {"tcp_ports_attempted": 1, "tool_wall_seconds": 15}) == {
        "ok": True, "budget_consumed": {"tcp_ports_attempted": 1, "tool_wall_seconds": 3}, "execution_started": True}
    # The port was already attempted: admission reserved none and none is reported.
    assert port_accounting.tls_port_usage(measured, {"tool_wall_seconds": 15})["budget_consumed"] == {
        "tool_wall_seconds": 3}
    unsent = {"ok": False, "budget_consumed": {"tcp_ports_attempted": 0, "tool_wall_seconds": 0}}
    assert port_accounting.tls_port_usage(unsent, {"tool_wall_seconds": 15})["execution_started"] is False
    web = TargetBinding(target_id="t", target_kind="web", canonical_host="app.test",
                        allowed_origins=("https://app.test",), allowed_addresses=("192.0.2.30", "192.0.2.31"),
                        scope_receipt_id="s")
    assert port_accounting.tls_pair(web, "https://app.test:8443") == ("192.0.2.30", 8443)
    assert port_accounting.tls_pair(web, "http://app.test") is None


def test_admission_charges_tls_and_network_actions_their_distinct_ports():
    source = (ROOT / "api/hunt/interaction_router.py").read_text(encoding="utf-8")
    assert "charges = distinct_charge(context, prepared_network, charges)" in source
    assert "tls_port = _tls_admission_pair(run, context, policy, request.input)" in source
    assert "operation=inspect_tls_port," in source
    worker = (ROOT / "api/worker.py").read_text(encoding="utf-8")
    assert "bound_distinct_usage(requested_budget, prepared, stored.record.requested, context)" in worker
    assert "record_attempted_usage(conn, hunt_id=hunt_id, run=locked, attempted=attempted" in worker


# --- a verification's state-changing hold settles to what it sent ----------------------------


def _verify(result=None, *, blocked=None):
    requested = {**web_candidate_budget("mass_assignment"), "tool_wall_seconds": 180, "agent_actions": 1,
                 "active_actions": 1}
    requested.pop("browser_actions", None)

    async def operation():
        if blocked is not None:
            raise blocked
        return result

    from fastapi import HTTPException
    adapter = ControlPlaneExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("candidate.verify"), operation=operation,
        requested_budget=requested, redacted_execution={}, blocked_exceptions=(HTTPException,),
        conservative_full_budget=True, measured_wall=True, settle=verification_traffic_charge)
    return asyncio.run(adapter.execute(heartbeat=lambda: None, cancelled=lambda: False)), requested


def test_a_mutating_verification_settles_its_state_changing_hold_to_what_it_sent():
    sent, requested = _verify({"ok": True, "verification": {"traffic": {"http_requests": 6, "state_changing_requests": 2}}})
    assert requested["state_changing_requests"] == 12
    assert sent.actual_budget["http_requests"] == 6 and sent.actual_budget["state_changing_requests"] == 2
    # A verification that reports no traffic, or whose report is not a count, keeps its whole hold.
    for verification in ({}, {"traffic": None}, {"traffic": {"http_requests": True}}):
        unknown, _ = _verify({"ok": True, "verification": verification})
        assert unknown.actual_budget["state_changing_requests"] == 12 and unknown.actual_budget["http_requests"] == 24
    from fastapi import HTTPException
    failed, _ = _verify(blocked=HTTPException(409, "busy"))
    assert failed.actual_budget["state_changing_requests"] == 12


def test_a_workflow_reports_the_requests_both_runs_and_its_probe_sent():
    calls = []
    executed = asyncio.run(workflow_experiment.execute_workflow(
        "https://example.test",
        {"proof_family": "workflow", "steps": [
            {"label": "before", "checkpoint": "before", "method": "GET", "path": "/object"},
            {"label": "mutate", "checkpoint": "mutation", "method": "PATCH", "path": "/object",
             "json_body": {"owner": "user2"}, "compare_to": "before"},
            {"label": "cleanup", "checkpoint": "cleanup", "method": "PUT", "path": "/object", "json_body": {"owner": "user1"}},
            {"label": "restored", "checkpoint": "after", "method": "GET", "path": "/object", "compare_to": "before"},
        ], "assertions": [
            {"type": "comparison_changed", "control": "before", "candidate": "mutate", "predicate": "transition_invariant_broken"},
            {"type": "restored", "control": "before", "candidate": "restored", "predicate": "before_after_state"},
        ]},
        principal_contexts={},
        transport=httpx.MockTransport(lambda request: calls.append(request.method) or httpx.Response(200)),
    ))
    assert calls == ["GET", "PATCH", "PUT", "GET"]
    assert executed["request_count"] == 4 and executed["state_changing_request_count"] == 2
    steps = [{"kind": "http"}] * 4
    probe = {"request_count": 3, "cleanup_request_count": 1}
    assert workflow_experiment.workflow_traffic(executed, executed, probe, steps) == {
        "http_requests": 12, "state_changing_requests": 8}
    blocked_replay = {"observations": [], "assertion_results": []}
    assert workflow_experiment.workflow_traffic(executed, blocked_replay, {}, steps) == {
        "http_requests": 4, "state_changing_requests": 2}
    # A browser step's requests are not counted by the runs: no report.
    assert workflow_experiment.workflow_traffic(executed, executed, {}, [{"kind": "http"}, {"kind": "browser"}]) is None
    assert workflow_experiment.workflow_traffic({"request_count": 2}, {}, {}, steps) is None


def test_the_web_verification_passes_its_workflow_traffic_on():
    api_source = (ROOT / "api/api.py").read_text(encoding="utf-8")
    verifier = api_source[api_source.index("async def _verify_web_candidate_workflow_unlocked"):]
    assert '"traffic": result.get("traffic"),' in verifier[:verifier.index("async def _verify_suspected_finding_workflow(")]
    arsenal = (ROOT / "api/arsenal_routes/router.py").read_text(encoding="utf-8")
    assert '"traffic": workflow_traffic(executed, replayed, materialization, normalized["steps"]),' in arsenal
    router = (ROOT / "api/hunt/interaction_router.py").read_text(encoding="utf-8")
    assert "settle=verification_traffic_charge," in router


def test_every_hunt_budget_stop_goes_through_the_one_clock_rule():
    """The admission settlement, the worker replay and the confirmed SSH queue all record a
    shortage through ``record_budget_shortage``; nothing else marks a Hunt exhausted."""
    writers = sorted(
        str(path.relative_to(ROOT)) for path in (ROOT / "api").rglob("*.py")
        if "hunt_runs SET status='budget_exhausted'" in path.read_text(encoding="utf-8")
    )
    assert writers == ["api/hunt/verification_budget.py"]
    router = (ROOT / "api/hunt/interaction_router.py").read_text(encoding="utf-8")
    ssh = router[router.index("async def confirm_hunt_shell_plan"):]
    ssh = ssh[:ssh.index("\nasync def ", 10)]
    assert "await record_budget_shortage(" in ssh
