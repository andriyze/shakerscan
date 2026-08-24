from __future__ import annotations

import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
import sys
import types

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

import worker
from runtime.budget_reservations import DurableBudgetReservation
from runtime.capability_settlement import terminalize_capability_reservation
from runtime.models import ScanBudget, ScanPolicy, TargetBinding
from runtime.reservation_store import StoredBudgetReservation
from scan.action_plan import ScanAction
from scan.execution import ScanExecutionPlan
from scanner_tools.request_replay import ReplayAuthorization, build_replay_plan


def _authority(
    *, enabled: bool = True, network: bool = False, approval: bool = False,
    budget: ScanBudget | None = None,
):
    plan = ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=network,
            network_discovery=network,
            subdomain_discovery=enabled,
            scope_receipt_id="scope-1",
            approval_receipt_id="approval-1" if network or approval else None,
        ),
        budget_profile="balanced",
        budget=budget or ScanBudget(1_200, 100, 50, 20, 10, 60, 2),
    )
    target = TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
        scope_receipt_id="scope-1",
    )
    options = plan.option_metadata()
    options.update({
        "active": network,
        "network_discovery": network,
        "subfinder": enabled,
        "_canonical_target_binding": target.canonical_dict(),
    })
    return plan, target, options


def _external_full_budget() -> ScanBudget:
    return ScanBudget(
        3_600, 20_000, 1_000, 1_000, 20_000, 4_000, 8, 0, 500,
    )


class _Transaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class _Connection:
    def __init__(self, plan):
        canonical = plan.canonical_dict()
        self.row = {
            "status": "running",
            "policy_json": canonical["policy"],
            "budget_json": canonical["budget"],
            "budget_used_json": {},
            "result": None,
        }

    def transaction(self):
        return _Transaction()

    async def fetchrow(self, query, *_args):
        if "INSERT INTO scan_stage_checkpoints" in query:
            return {
                "scan_id": _args[0],
                "job_id": _args[1],
                "stage_index": _args[2],
                "stage_name": _args[3],
                "status": _args[4],
            }
        if "policy_json" in query:
            return dict(self.row)
        if "budget_used_json" in query:
            return {"budget_used_json": dict(self.row["budget_used_json"])}
        if "SELECT status" in query:
            return {"status": self.row["status"]}
        if "UPDATE scan_capability_actions" in query and "reservation_id=$4" in query:
            return {"reservation_id": _args[3]}
        raise AssertionError(query)

    async def execute(self, query, *_args):
        if "UPDATE scans SET budget_used_json" in query:
            self.row["budget_used_json"] = json.loads(_args[1])
            return "UPDATE 1"
        raise AssertionError(query)

    async def fetchval(self, query, *_args):
        if "SELECT result FROM scans" in query:
            return self.row["result"]
        raise AssertionError(query)


class _Acquire:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *_args):
        return False


class _Pool:
    def __init__(self, connection):
        self.connection = connection

    def acquire(self):
        return _Acquire(self.connection)


class _ReservationStore:
    def __init__(self, events):
        self.events = events
        self.current = None

    async def create_requested(
        self, _conn, *, action_id, action_digest, record,
    ):
        self.events.append(("create", record.status))
        self.current = StoredBudgetReservation(
            action_id=action_id,
            action_digest=action_digest,
            record=record,
        )
        return self.current

    async def load_by_action(
        self, _conn, *, owner_kind, owner_id, action_id, for_update=False,
    ):
        assert owner_kind == "scan"
        assert for_update is True
        if self.current is None or self.current.action_id != action_id:
            return None
        assert self.current.record.owner_id == owner_id
        return self.current

    async def load(self, _conn, _reservation_id, *, for_update=False):
        assert for_update is True
        return self.current

    async def persist_transition(
        self, _conn, *, previous, current, ledger_after_hold=None,
    ):
        assert previous.record.state_digest == self.current.record.state_digest
        self.events.append(("transition", current.status))
        self.current = StoredBudgetReservation(
            action_id=previous.action_id,
            action_digest=previous.action_digest,
            record=current,
            ledger_after_hold=(
                dict(ledger_after_hold)
                if ledger_after_hold is not None
                else previous.ledger_after_hold
            ),
            ledger_after_settlement=previous.ledger_after_settlement,
            receipt=previous.receipt,
        )
        return self.current

    async def persist_terminal(
        self, _conn, *, previous, terminal, ledger_after_settlement, receipt,
    ):
        assert previous.record.state_digest == self.current.record.state_digest
        self.events.append(("terminal", terminal.status))
        self.current = StoredBudgetReservation(
            action_id=previous.action_id,
            action_digest=previous.action_digest,
            record=terminal,
            ledger_after_hold=previous.ledger_after_hold,
            ledger_after_settlement=dict(ledger_after_settlement),
            receipt=receipt.public_dict() if receipt else None,
        )
        return self.current


def test_policy_disabled_scan_never_opens_a_database_or_executes(monkeypatch):
    _plan, _target, options = _authority(enabled=False)

    class _NoPool:
        def acquire(self):
            raise AssertionError("policy-disabled discovery touched persistence")

    monkeypatch.setattr(worker, "db_pool", _NoPool())
    summary = asyncio.run(worker._execute_scan_subdomain_discovery(
        options, "00000000-0000-0000-0000-000000000001", job_id="job-1",
    ))

    assert summary["status"] == "skipped"
    assert summary["reason"] == "policy_disabled"
    assert summary["observation_count"] == 0


def test_scan_subdomain_discovery_reserves_before_target_traffic_and_settles(
    monkeypatch,
):
    plan, _target, options = _authority(enabled=True)
    connection = _Connection(plan)
    events = []
    store = _ReservationStore(events)

    async def run_streaming(argv, **kwargs):
        events.append(("traffic", store.current.record.status))
        assert argv == [
            "subfinder", "-d", "example.test", "-silent", "-json",
            "-disable-update-check", "-timeout", "10", "-max-time", "2",
        ]
        assert kwargs["hard_timeout"] == 60.0
        return SimpleNamespace(
            stdout='{"host":"api.example.test"}\n',
            returncode=0,
            timed_out=False,
            partial=False,
            stdout_truncated=False,
            cancelled=False,
        )

    monkeypatch.setattr(worker, "db_pool", _Pool(connection))
    monkeypatch.setattr(worker, "PostgresBudgetReservationStore", lambda: store)
    monkeypatch.setattr(worker, "run_streaming", run_streaming)
    monkeypatch.setattr(worker, "_worker_runtime_identity", lambda: "worker:test")
    monkeypatch.setattr(worker, "_scan_cancel_requested", lambda _scan_id: False)

    summary = asyncio.run(worker._execute_scan_subdomain_discovery(
        options, "00000000-0000-0000-0000-000000000001", job_id="job-1",
    ))

    assert events[:3] == [
        ("create", "requested"),
        ("transition", "reserved"),
        ("transition", "running"),
    ]
    assert ("traffic", "running") in events
    assert events[-1] == ("terminal", "committed")
    assert summary["status"] == "success"
    assert summary["observations"] == [{
        "kind": "subdomain",
        "host": "api.example.test",
        "root_domain": "example.test",
    }]
    assert summary["automatically_scanned_discovered_hosts"] is False
    assert summary["receipt"]["budget_reservation_state"] == "committed"
    assert store.current.receipt["scan_id"] == (
        "00000000-0000-0000-0000-000000000001"
    )
    assert connection.row["budget_used_json"]["hosts_attempted"] == 1






def test_collection_replay_uses_only_an_established_interactive_session(
    monkeypatch,
):
    _plan, target, options = _authority(enabled=True, approval=True)
    profile_id = "00000000-0000-0000-0000-000000000009"
    options = {
        **options,
        "credential_profile_refs": [{
            "profile_id": profile_id,
            "profile_version": 3,
            "auth_kind": "form_login",
            "principal_slot": "primary",
            "scan_lane": "primary",
        }],
    }
    session_cookie = "session=worker-private-replay-cookie"
    replay_plan = build_replay_plan(
        [{
            "id": "request-1",
            "method": "GET",
            "url": "https://app.example.test/account",
            "headers": {},
            "body": b"",
        }],
        allowed_origins=target.allowed_origins,
        authorization=ReplayAuthorization(),
    )

    class Resolution:
        profile = SimpleNamespace(
            profile_id=profile_id,
            current_version=3,
            auth_kind="form_login",
            principal_slot="primary",
            target_kind="web",
        )

        def http_headers(self):
            raise worker.CredentialResolutionError("interactive exchange required")

    class ResolutionContext:
        async def __aenter__(self):
            return Resolution()

        async def __aexit__(self, *_args):
            return False

    class Resolver:
        def resolve(self, *_args, **_kwargs):
            return ResolutionContext()

    async def validate_authority(*_args, **_kwargs):
        return SimpleNamespace()

    monkeypatch.setattr(worker, "WorkerCredentialResolver", Resolver)
    monkeypatch.setattr(
        worker, "validate_worker_credential_authority", validate_authority,
    )

    bound, receipt_context = asyncio.run(
        worker._bind_scan_replay_primary_credential(
            object(),
            plan=replay_plan,
            target=target,
            scan_id="00000000-0000-0000-0000-000000000001",
            options=options,
            trusted_primary_headers={"Cookie": session_cookie},
        )
    )

    assert bound.wire_requests()[0]["headers"]["Cookie"] == session_cookie
    assert session_cookie not in repr(bound.public_dict())
    assert receipt_context["principal_profile_ref"] == profile_id
    assert receipt_context["principal_profile_version"] == 3
    assert receipt_context["principal_slot"] == "primary"
    assert re.fullmatch(
        r"[0-9a-f]{64}", receipt_context["principal_binding_digest"],
    )






def test_candidate_verification_never_promotes_sqlmap_label_without_differential():
    summary = worker._canonical_candidate_verification_summary(
        {
            "observations": [{
                "kind": "xss_alert",
                "proof_state": "verified",
            }],
        },
        {
            "observations": [{
                "kind": "sqli_finding",
                # Even a malformed or legacy adapter claim cannot override the
                # deterministic payload/control proof contract.
                "proof_state": "verified",
            }],
        },
        candidate_count=1,
    )

    assert summary["xss"]["verified_count"] == 1
    assert summary["sqli"]["verified_count"] == 0
    assert summary["sqli"]["suspected_count"] == 1
    assert summary["finding_promotion_authority"] == (
        "deterministic_proof_contracts_only"
    )




def test_scan_port_discovery_uses_same_reserve_before_traffic_boundary(
    monkeypatch,
):
    plan, target, options = _authority(enabled=False, network=True)
    connection = _Connection(plan)
    events = []
    store = _ReservationStore(events)
    _normalized, admission = worker.prepare_worker_dispatch(options)
    execution = worker.build_native_scan_execution(plan, options)

    async def run_streaming(argv, **kwargs):
        events.append(("traffic", store.current.record.status))
        assert argv == [
            "naabu", "-host", "192.0.2.10", "-p", "21,22,25,53,80",
            "-Pn", "-scan-type", "c", "-rate", "10", "-c", "10",
            "-timeout", "1500ms", "-retries", "1", "-json", "-silent",
            "-no-color", "-disable-update-check", "-no-stdin",
        ]
        assert kwargs["hard_timeout"] == 30.0
        return SimpleNamespace(
            stdout='{"ip":"192.0.2.10","port":21}\n',
            returncode=0,
            timed_out=False,
            partial=False,
            stdout_truncated=False,
            cancelled=False,
        )

    monkeypatch.setattr(worker, "db_pool", _Pool(connection))
    monkeypatch.setattr(worker, "PostgresBudgetReservationStore", lambda: store)
    monkeypatch.setattr(worker, "run_streaming", run_streaming)
    monkeypatch.setattr(worker, "_worker_runtime_identity", lambda: "worker:test")
    monkeypatch.setattr(worker, "_scan_cancel_requested", lambda _scan_id: False)

    stored, redelivery = asyncio.run(
        worker._execute_reserved_scan_capability(
            admission=admission,
            execution=execution,
            scan_id="00000000-0000-0000-0000-000000000001",
            job_id="job-1",
            capability_name="ports.discover",
            capability_args={"ports": [21, 22, 25, 53, 80]},
            action_id="discover_network.ports",
            target_binding=target,
            reservation_limits={
                "hosts_attempted": 1,
                "tcp_ports_attempted": 5,
                "tool_wall_seconds": 30,
            },
        )
    )

    assert events[:3] == [
        ("create", "requested"),
        ("transition", "reserved"),
        ("transition", "running"),
    ]
    assert ("traffic", "running") in events
    assert events[-1] == ("terminal", "committed")
    assert stored.record.capability_name == "ports.discover"
    assert stored.receipt["scan_id"] == (
        "00000000-0000-0000-0000-000000000001"
    )
    assert stored.receipt["observations"][0]["port"] == 21
    assert redelivery is False


def test_scan_tls_uses_same_reserve_before_handshake_boundary(monkeypatch):
    plan, target, options = _authority(enabled=False, network=False)
    connection = _Connection(plan)
    events = []
    store = _ReservationStore(events)
    _normalized, admission = worker.prepare_worker_dispatch(options)
    execution = worker.build_native_scan_execution(plan, options)

    async def handshake():
        events.append(("traffic", store.current.record.status))
        return {
            "ok": True,
            "status": "success",
            "observation": {
                "kind": "tls_protocol",
                "origin": "https://app.example.test",
                "server_hostname": "app.example.test",
                "pinned_address": "192.0.2.10",
                "port": 443,
                "protocol": "TLSv1.3",
            },
            "budget_consumed": {
                "tcp_ports_attempted": 1,
                "tool_wall_seconds": 1,
            },
        }

    monkeypatch.setattr(worker, "db_pool", _Pool(connection))
    monkeypatch.setattr(worker, "PostgresBudgetReservationStore", lambda: store)
    monkeypatch.setattr(worker, "_worker_runtime_identity", lambda: "worker:test")
    monkeypatch.setattr(worker, "_scan_cancel_requested", lambda _scan_id: False)

    stored, redelivery = asyncio.run(
        worker._execute_reserved_scan_capability(
            admission=admission,
            execution=execution,
            scan_id="00000000-0000-0000-0000-000000000001",
                job_id="job-1",
                capability_name="tls.inspect",
                capability_args={
                    "origins_ref": "frozen_https_origins",
                    "origin_count": 1,
                    "addresses_ref": "frozen_addresses",
                    "address_count": 1,
                },
            action_id="deterministic_baseline.tls.inspect",
            target_binding=target,
            reservation_limits={
                "tcp_ports_attempted": 1,
                "tool_wall_seconds": 15,
            },
            inline_operation=handshake,
        )
    )

    assert events[:3] == [
        ("create", "requested"),
        ("transition", "reserved"),
        ("transition", "running"),
    ]
    assert ("traffic", "running") in events
    assert events[-1] == ("terminal", "committed")
    assert stored.record.capability_name == "tls.inspect"
    assert stored.record.actual == {
        "tcp_ports_attempted": 1,
        "tool_wall_seconds": 1,
    }
    assert stored.receipt["observations"][0]["protocol"] == "TLSv1.3"
    assert redelivery is False


def test_scan_http_uses_same_reserve_before_request_boundary(monkeypatch):
    plan, target, options = _authority(enabled=False, network=False)
    connection = _Connection(plan)
    events = []
    store = _ReservationStore(events)
    _normalized, admission = worker.prepare_worker_dispatch(options)
    execution = worker.build_native_scan_execution(plan, options)

    async def request():
        events.append(("traffic", store.current.record.status))
        return {
            "ok": True,
            "request": {
                "method": "HEAD",
                "origin": "https://app.example.test",
                "path": "/",
                "pinned_address": "192.0.2.10",
                "follow_redirects": True,
            },
            "response": {
                "status": 200,
                "selected_headers": {"server": "nginx"},
            },
            "redirect_chain": [{
                "status": 302,
                "location": "/home",
                "followed": True,
            }],
            "hops_followed": 1,
        }

    monkeypatch.setattr(worker, "db_pool", _Pool(connection))
    monkeypatch.setattr(worker, "PostgresBudgetReservationStore", lambda: store)
    monkeypatch.setattr(worker, "_worker_runtime_identity", lambda: "worker:test")
    monkeypatch.setattr(worker, "_scan_cancel_requested", lambda _scan_id: False)

    stored, redelivery = asyncio.run(
        worker._execute_reserved_scan_capability(
            admission=admission,
            execution=execution,
            scan_id="00000000-0000-0000-0000-000000000001",
            job_id="job-1",
            capability_name="http.request",
            capability_args={
                "method": "HEAD",
                "path": "/",
                "follow_redirects": True,
            },
            action_id="deterministic_baseline.http.request",
            target_binding=target,
            reservation_limits={
                "http_requests": 4,
                "tool_wall_seconds": 15,
            },
            inline_operation=request,
        )
    )

    assert events[:3] == [
        ("create", "requested"),
        ("transition", "reserved"),
        ("transition", "running"),
    ]
    assert ("traffic", "running") in events
    assert events[-1] == ("terminal", "committed")
    assert stored.record.actual == {
        "http_requests": 2,
        "tool_wall_seconds": 1,
    }
    assert stored.receipt["observations"][0]["kind"] == "http_observation"
    assert redelivery is False


def test_scan_capability_dispatch_is_bound_to_exact_canonical_action(monkeypatch):
    plan, target, options = _authority(enabled=False, network=False)
    connection = _Connection(plan)
    events = []
    store = _ReservationStore(events)
    _normalized, admission = worker.prepare_worker_dispatch(options)
    execution = worker.build_native_scan_execution(plan, options)
    action = ScanAction(
        action_id="baseline.http",
        stage="deterministic_baseline",
        ordinal=0,
        capability_name="http.request",
        capability_args={
            "method": "GET", "path": "/", "follow_redirects": False,
        },
        target_binding_digest=target.digest,
        input_binding_digest="a" * 64,
        requested_budget={"http_requests": 1, "tool_wall_seconds": 15},
        placement={
            "eligible_backends": ["local", "broker"],
            "adapter_name": "agent.http_request",
            "adapter_version": "1",
        },
        dependencies=(),
        required=True,
        supporting=False,
        output_schema="http-observation/v1",
    )

    async def request():
        return {
            "ok": True,
            "request": {
                "method": "GET",
                "origin": "https://app.example.test",
                "path": "/",
                "pinned_address": "192.0.2.10",
                "follow_redirects": False,
            },
            "response": {"status": 200, "selected_headers": {}},
            "redirect_chain": [],
            "hops_followed": 0,
        }

    monkeypatch.setattr(worker, "db_pool", _Pool(connection))
    monkeypatch.setattr(worker, "PostgresBudgetReservationStore", lambda: store)
    async def allow_action(*_args, **_kwargs):
        return worker.ActionAuthorityDecision.ALLOWED
    monkeypatch.setattr(worker, "revalidate_scan_action_authority", allow_action)
    monkeypatch.setattr(worker, "_worker_runtime_identity", lambda: "worker:test")
    monkeypatch.setattr(worker, "_scan_cancel_requested", lambda _scan_id: False)

    stored, redelivery = asyncio.run(worker._execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
        capability_name="http.request",
        capability_args=action.capability_args,
        action_id=action.action_id,
        target_binding=target,
        reservation_limits={"http_requests": 999, "tool_wall_seconds": 999},
        inline_operation=request,
        canonical_action=action,
    ))

    assert redelivery is False
    assert dict(stored.record.requested) == dict(action.requested_budget)
    assert stored.action_digest == action.action_digest
    assert stored.receipt["input_digest"] == action.action_digest


def test_scan_capability_rejects_substituted_canonical_action_before_traffic():
    plan, target, options = _authority(enabled=False, network=False)
    _normalized, admission = worker.prepare_worker_dispatch(options)
    execution = worker.build_native_scan_execution(plan, options)
    substituted = SimpleNamespace(
        action_id="another.action",
        capability_name="http.request",
        target_binding_digest=target.digest,
    )

    with pytest.raises(
        worker.ScanCapabilityContractError,
        match="canonical Scan action differs",
    ):
        asyncio.run(worker._execute_reserved_scan_capability(
            admission=admission,
            execution=execution,
            scan_id="00000000-0000-0000-0000-000000000001",
            job_id="job-1",
            capability_name="http.request",
            capability_args={"method": "GET", "path": "/"},
            action_id="baseline.http",
            target_binding=target,
            reservation_limits={"http_requests": 1, "tool_wall_seconds": 15},
            inline_operation=lambda: asyncio.sleep(0),
            canonical_action=substituted,
        ))


def test_fixed_external_scan_tool_rejects_incomplete_reservation_before_process(
    monkeypatch,
):
    plan, target, options = _authority(enabled=False, network=True)
    connection = _Connection(plan)
    events = []
    store = _ReservationStore(events)
    _normalized, admission = worker.prepare_worker_dispatch(options)
    execution = worker.build_native_scan_execution(plan, options)
    process_result = {}

    async def process_runner(payload, *, heartbeat):
        events.append(("traffic", store.current.record.status))
        assert payload["tool_name"] == "nuclei"
        assert payload["_cancelled"]() is False
        await heartbeat()
        return {
            "status": "success",
            "elapsed_seconds": 2,
            "typed_output": {
                "parser": "nuclei-typed-v1",
                "records": [{
                    "kind": "template_match",
                    "template_id": "example-cve",
                    "proof_state": "candidate",
                }],
                "errors": [],
            },
            "settlement": {"mode": "exact", "actual": 3},
        }

    monkeypatch.setattr(worker, "db_pool", _Pool(connection))
    monkeypatch.setattr(worker, "PostgresBudgetReservationStore", lambda: store)
    monkeypatch.setattr(worker, "_worker_runtime_identity", lambda: "worker:test")
    monkeypatch.setattr(worker, "_scan_cancel_requested", lambda _scan_id: False)

    with pytest.raises(
        worker.ScanCapabilityContractError,
        match="fixed external capability budget is incomplete",
    ):
        asyncio.run(worker._execute_reserved_scan_capability(
            admission=admission,
            execution=execution,
            scan_id="00000000-0000-0000-0000-000000000001",
            job_id="job-1",
            capability_name="templates.scan",
            capability_args={},
            action_id="deterministic_baseline.templates",
            target_binding=target,
            reservation_limits={
                "http_requests": 10,
                "tool_wall_seconds": 10,
            },
            scanner_process_payload={"tool_name": "nuclei"},
            scanner_process_runner=process_runner,
            scanner_result_holder=process_result,
        ))

    assert events == []
    assert process_result == {}


def test_parent_standalone_reuses_verified_placed_discovery_without_traffic(
    monkeypatch,
):
    parent_id = "00000000-0000-0000-0000-000000000001"
    source_id = "00000000-0000-0000-0000-000000000002"
    requested = DurableBudgetReservation.request(
        owner_kind="scan",
        owner_id=source_id,
        capability_name="subdomains.discover",
        amounts={"hosts_attempted": 1, "tool_wall_seconds": 60},
        reservation_id="reservation-1",
    )
    running = requested.reserve(lease_seconds=90).start(
        worker_id="worker:test", lease_seconds=90,
    )
    terminal, receipt = terminalize_capability_reservation(
        running,
        action_digest="a" * 64,
        capability_name="subdomains.discover",
        adapter_name="subfinder",
        adapter_version="1",
        parser_version="subfinder-lines/v1",
        target_id="target-1",
        target_kind="web",
        capability_input={"root_domain": "example.test"},
        action_status="completed",
        actual_budget={"hosts_attempted": 1, "tool_wall_seconds": 1},
        worker_id="worker:test",
        started_at=running.started_at.isoformat(),
        finished_at=(running.started_at + timedelta(seconds=1)).isoformat(),
        receipt_id="receipt-1",
        result={
            "receipt_observations": [{
                "kind": "subdomain",
                "host": "api.example.test",
                "root_domain": "example.test",
            }],
        },
    )
    stored = StoredBudgetReservation(
        action_id="discover_surface.subdomains",
        action_digest="a" * 64,
        record=terminal,
        ledger_after_settlement={
            "hosts_attempted": 1,
            "tool_wall_seconds": 1,
        },
        receipt=receipt.public_dict(),
    )
    summary = worker._scan_subdomain_summary_from_stored(
        stored, root_domain="example.test",
    )

    class _SourceConnection:
        async def fetchrow(self, query, *_args):
            assert "scan_role" in query
            return {
                "status": "completed",
                "result": {"subdomain_discovery": summary},
            }

    class _SourceStore:
        async def load(self, _conn, reservation_id, *, for_update=False):
            assert reservation_id == "reservation-1"
            assert for_update is False
            return stored

    monkeypatch.setattr(worker, "db_pool", _Pool(_SourceConnection()))
    monkeypatch.setattr(
        worker, "PostgresBudgetReservationStore", lambda: _SourceStore(),
    )
    reused = asyncio.run(worker._reuse_placed_scan_subdomain_discovery(
        parent_scan_id=parent_id,
        source_scan_id=source_id,
        expected_summary=summary,
    ))

    assert reused["reused_from_placed_discovery"] is True
    assert reused["source_scan_id"] == source_id
    assert reused["observations"] == summary["observations"]


def test_parent_reuses_receiptless_placed_failure_only_as_partial_truth(monkeypatch):
    parent_id = "00000000-0000-0000-0000-000000000001"
    source_id = "00000000-0000-0000-0000-000000000002"
    subdomain = {
        "schema_version": "canonical-scan-subdomain-discovery/v1",
        "enabled": True,
        "status": "failed",
        "observations": [],
        "observation_count": 0,
        "durable_budget_settled": False,
    }
    network = {
        "schema_version": "canonical-scan-network-discovery/v1",
        "enabled": True,
        "status": "failed",
        "actions": [],
        "observations": [],
        "observation_count": 0,
        "durable_budget_settled": False,
    }

    class _FailedSourceConnection:
        async def fetchrow(self, query, *_args):
            assert "scan_role" in query
            return {
                "status": "failed",
                "result": {
                    "subdomain_discovery": subdomain,
                    "network_discovery": network,
                },
            }

    monkeypatch.setattr(worker, "db_pool", _Pool(_FailedSourceConnection()))
    reused_subdomain = asyncio.run(
        worker._reuse_placed_scan_subdomain_discovery(
            parent_scan_id=parent_id,
            source_scan_id=source_id,
            expected_summary=subdomain,
        )
    )
    reused_network = asyncio.run(worker._reuse_placed_scan_network_discovery(
        parent_scan_id=parent_id,
        source_scan_id=source_id,
        expected_summary=network,
    ))

    assert reused_subdomain["status"] == "failed"
    assert reused_network["status"] == "failed"
    assert reused_subdomain["reused_from_placed_discovery"] is True
    assert reused_network["reused_from_placed_discovery"] is True


def _stored_network_capability(
    capability_name,
    *,
    observations,
    amounts,
):
    requested = DurableBudgetReservation.request(
        owner_kind="scan",
        owner_id="00000000-0000-0000-0000-000000000001",
        capability_name=capability_name,
        amounts=amounts,
    )
    running = requested.reserve(lease_seconds=90).start(
        worker_id="worker:test", lease_seconds=90,
    )
    adapter = {
        "ports.discover": ("naabu", "naabu-jsonl/v1"),
        "service.fingerprint": ("nmap", "nmap-xml/v1"),
        "templates.scan": ("nuclei", "nuclei-typed-v1"),
        "templates.passive_scan": ("nuclei", "nuclei-typed-v1"),
        "web.probe": ("httpx", "httpx-typed-v1"),
        "web.crawl": ("katana", "katana-typed-v1"),
        "web.content_discover": ("ffuf", "ffuf-typed-v1"),
        "auth.session.establish": ("auth.session", "credential-session/v1"),
        "authz.verify": ("authz.differential", "authz-differential/v1"),
        "http.request": ("agent.http_request", "http-observation/v1"),
        "dns.inspect": ("scanner.dns", "dns-posture-observation/v1"),
        "tls.inspect": ("scanner.tls", "tls-observation/v2"),
        "xss.verify": ("dalfox", "dalfox-typed-v1"),
        "sqli.verify": ("sqlmap", "sqlmap-typed-v1"),
    }[capability_name]
    terminal, receipt = terminalize_capability_reservation(
        running,
        action_digest="c" * 64,
        capability_name=capability_name,
        adapter_name=adapter[0],
        adapter_version="1",
        parser_version=adapter[1],
        target_id="target-1",
        target_kind="web",
        capability_input={},
        action_status="completed",
        actual_budget=amounts,
        worker_id="worker:test",
        started_at=running.started_at.isoformat(),
        finished_at=(running.started_at + timedelta(seconds=1)).isoformat(),
        receipt_id=f"receipt-{capability_name}",
        scope_receipt_id="scope-1",
        approval_receipt_id="approval-1",
        result={"receipt_observations": observations},
    )
    return StoredBudgetReservation(
        action_id=capability_name,
        action_digest="c" * 64,
        record=terminal,
        ledger_after_settlement=dict(amounts),
        receipt=receipt.public_dict(),
    )


def test_template_stage_places_one_reserved_nuclei_result(monkeypatch):
    _plan, _target, options = _authority(
        enabled=False, network=True, budget=_external_full_budget(),
    )
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "templates.scan",
            observations=[{
                "kind": "template_match",
                "template_id": "example-cve",
                "name": "Example CVE",
                "severity": "high",
                "matched_at": "https://app.example.test/account",
                "proof_state": "candidate",
            }],
            amounts={"http_requests": 3, "tool_wall_seconds": 2},
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_template_capability(
        "https://app.example.test/account?id=1",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert len(calls) == 1
    call = calls[0]
    assert call["capability_name"] == "templates.scan"
    assert call["action_id"] == "deterministic_baseline.templates.scan"
    assert call["reservation_limits"] == {
        "http_requests": 4_000,
        "tool_wall_seconds": 300,
    }
    assert call["scanner_process_payload"]["execution_target"] == (
        "https://app.example.test/account?id=1"
    )
    assert call["scanner_process_payload"]["pinned_address"] == "192.0.2.10"
    assert call["scanner_process_payload"]["oob_interactsh_server"] is None
    assert summary["status"] == "success"
    assert summary["observations"][0]["proof_state"] == "candidate"
    assert summary["receipt"]["budget_reservation_state"] == "committed"


def test_verify_stage_places_one_reserved_xss_result(monkeypatch):
    _plan, _target, options = _authority(
        enabled=False, network=True, budget=_external_full_budget(),
    )
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "xss.verify",
            observations=[{
                "kind": "xss_alert",
                "alert_type": "V",
                "url": "https://app.example.test/search?q=%3Credacted%3E",
                "param": "q",
                "payload_sha256": "a" * 64,
                "message": "verified alert",
                "proof_state": "verified",
            }],
            amounts={"http_requests": 2, "tool_wall_seconds": 2},
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_xss_verification_capability(
        "https://app.example.test/search?q=test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert len(calls) == 1
    call = calls[0]
    assert call["capability_name"] == "xss.verify"
    assert call["action_id"].startswith("deterministic_verify.xss.")
    assert call["reservation_limits"] == {
        "http_requests": 400,
        "tool_wall_seconds": 120,
    }
    assert call["scanner_process_payload"]["tool_name"] == "dalfox"
    assert call["scanner_process_payload"]["execution_target"] == (
        "https://app.example.test/search?q=test"
    )
    assert call["scanner_process_payload"]["registered_target"] == (
        "https://app.example.test"
    )
    assert call["scanner_process_payload"]["scanner_options"] == {
        "severity": "high",
    }
    assert call["scanner_process_payload"]["pinned_address"] == "192.0.2.10"
    assert call["scanner_process_payload"]["oob_interactsh_server"] is None
    assert summary["status"] == "success"
    assert summary["observations"][0]["proof_state"] == "verified"
    assert summary["receipt"]["budget_reservation_state"] == "committed"


def test_verify_stage_never_runs_without_active_permission(monkeypatch):
    _plan, _target, options = _authority(enabled=True, network=False)

    async def execute_capability(**_kwargs):
        raise AssertionError("passive Scan launched Dalfox")

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_xss_verification_capability(
        "https://app.example.test/search?q=test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert summary["status"] == "skipped"
    assert summary["reason"] == "active_testing_not_authorized"


def test_verify_stage_places_one_reserved_sqli_result(monkeypatch):
    _plan, _target, options = _authority(
        enabled=False, network=True, budget=_external_full_budget(),
    )
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "sqli.verify",
            observations=[{
                "kind": "sqli_finding",
                "message": "Parameter 'q' is vulnerable.",
                "param": "q",
                "method": None,
                "proof_state": "candidate",
            }],
            amounts={"http_requests": 2, "tool_wall_seconds": 2},
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_sqli_verification_capability(
        "https://app.example.test/search?q=test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert len(calls) == 1
    call = calls[0]
    assert call["capability_name"] == "sqli.verify"
    assert call["action_id"].startswith("deterministic_verify.sqli.")
    assert call["reservation_limits"] == {
        "http_requests": 900,
        "tool_wall_seconds": 300,
    }
    assert call["scanner_process_payload"]["tool_name"] == "sqlmap"
    assert call["scanner_process_payload"]["execution_target"] == (
        "https://app.example.test/search?q=test"
    )
    assert call["scanner_process_payload"]["registered_target"] == (
        "https://app.example.test"
    )
    assert call["scanner_process_payload"]["scanner_options"] == {}
    assert call["scanner_process_payload"]["pinned_address"] == "192.0.2.10"
    assert call["scanner_process_payload"]["oob_interactsh_server"] is None
    assert summary["status"] == "success"
    assert summary["observations"][0]["url"] == (
        "https://app.example.test/search?q=%3Credacted%3E"
    )
    assert summary["observations"][0]["method"] == "GET"
    assert summary["observations"][0]["proof_state"] == "candidate"
    assert summary["receipt"]["budget_reservation_state"] == "committed"


def test_sqli_verify_stage_never_runs_without_active_permission(monkeypatch):
    _plan, _target, options = _authority(enabled=True, network=False)

    async def execute_capability(**_kwargs):
        raise AssertionError("passive Scan launched SQLMap")

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_sqli_verification_capability(
        "https://app.example.test/search?q=test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert summary["status"] == "skipped"
    assert summary["reason"] == "active_testing_not_authorized"


def test_recon_stage_places_one_reserved_http_fingerprint(monkeypatch):
    _plan, _target, options = _authority(enabled=True, network=False)
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "web.probe",
            observations=[{
                "kind": "http_fingerprint",
                "url": "https://app.example.test/",
                "status": 200,
                "title": "Example",
                "webserver": "nginx",
                "technologies": ["nginx"],
            }],
            amounts={"http_requests": 1, "tool_wall_seconds": 1},
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_web_probe_capability(
        "https://app.example.test/account?id=1",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert len(calls) == 1
    call = calls[0]
    assert call["capability_name"] == "web.probe"
    assert call["action_id"] == "deterministic_recon.web.probe"
    assert call["reservation_limits"] == {
        "http_requests": 1,
        "tool_wall_seconds": 30,
    }
    assert call["scanner_process_payload"]["tool_name"] == "httpx"
    assert call["scanner_process_payload"]["execution_target"] == (
        "https://app.example.test/account?id=1"
    )
    assert summary["status"] == "success"
    assert summary["observations"][0]["kind"] == "http_fingerprint"
    assert summary["receipt"]["budget_reservation_state"] == "committed"


def test_recon_stage_places_one_reserved_crawl_result(monkeypatch):
    _plan, _target, options = _authority(enabled=False, network=True)
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "web.crawl",
            observations=[{
                "kind": "discovered_route",
                "url": "https://app.example.test/api/orders",
                "method": "GET",
                "source": "https://app.example.test/",
            }],
            amounts={"http_requests": 2, "tool_wall_seconds": 2},
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_web_crawl_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert len(calls) == 1
    call = calls[0]
    assert call["capability_name"] == "web.crawl"
    assert call["action_id"] == "deterministic_recon.web.crawl"
    assert call["reservation_limits"] == {
        "http_requests": 10,
        "tool_wall_seconds": 6,
    }
    assert call["scanner_process_payload"]["tool_name"] == "katana"
    assert call["scanner_process_payload"]["pinned_address"] == "192.0.2.10"
    assert summary["status"] == "success"
    assert summary["observations"][0]["kind"] == "discovered_route"
    assert summary["receipt"]["budget_reservation_state"] == "committed"


def test_recon_stage_places_one_reserved_content_discovery_result(monkeypatch):
    _plan, _target, options = _authority(enabled=False, network=True)
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "web.content_discover",
            observations=[{
                "kind": "content_discovery",
                "url": "https://app.example.test/admin",
                "status": 403,
                "length": 120,
                "redirect_location": None,
            }],
            amounts={"http_requests": 2, "tool_wall_seconds": 2},
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_content_discovery_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert len(calls) == 1
    call = calls[0]
    assert call["capability_name"] == "web.content_discover"
    assert call["action_id"] == "deterministic_recon.web.content_discover"
    assert call["capability_args"] == {"wordlist": "common"}
    assert call["reservation_limits"] == {
        "http_requests": 10,
        "tool_wall_seconds": 6,
    }
    assert call["scanner_process_payload"]["tool_name"] == "ffuf"
    assert call["scanner_process_payload"]["scanner_options"] == {
        "wordlist": "common"
    }
    assert summary["status"] == "success"
    assert summary["observations"][0]["kind"] == "content_discovery"
    assert summary["receipt"]["budget_reservation_state"] == "committed"


def test_content_discovery_runs_read_only_without_active_permission(monkeypatch):
    _plan, _target, options = _authority(enabled=True, network=False)

    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "web.content_discover", observations=[],
            amounts={"http_requests": 1, "tool_wall_seconds": 1},
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_content_discovery_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert summary["status"] == "success"
    assert len(calls) == 1
    assert calls[0]["capability_name"] == "web.content_discover"
    assert calls[0]["target_binding"].digest == _target.digest


def test_crawl_stage_runs_read_only_without_active_permission(monkeypatch):
    _plan, _target, options = _authority(enabled=True, network=False)

    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "web.crawl", observations=[],
            amounts={"http_requests": 1, "tool_wall_seconds": 1},
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_web_crawl_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert summary["status"] == "success"
    assert len(calls) == 1
    assert calls[0]["capability_name"] == "web.crawl"
    assert calls[0]["target_binding"].digest == _target.digest


def test_template_stage_never_runs_without_active_permission(monkeypatch):
    _plan, _target, options = _authority(enabled=True, network=False)

    async def execute_capability(**_kwargs):
        raise AssertionError("passive Scan launched Nuclei")

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_template_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert summary["status"] == "skipped"
    assert summary["reason"] == "active_testing_not_authorized"


def test_passive_template_stage_runs_exact_read_only_profile_without_approval(
    monkeypatch,
):
    _plan, target, options = _authority(enabled=True, network=False)
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "templates.passive_scan", observations=[],
            amounts={"http_requests": 7, "tool_wall_seconds": 1},
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    action = SimpleNamespace(
        action_id="passive.templates",
        capability_name="templates.passive_scan",
        requested_budget={"http_requests": 7, "tool_wall_seconds": 30},
    )
    template_options = {
        "severity": "critical,high,medium,low,info",
        "template_ids": (
            "git-config,git-credentials-disclosure,"
            "http-missing-security-headers,openapi,server-status,web-config"
        ),
        "template_pack_digest": "a" * 64,
        "template_request_cost_upper_bound": 7,
    }

    summary = asyncio.run(worker._execute_scan_template_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
        canonical_action=action,
        canonical_template_options=template_options,
    ))

    assert summary["status"] == "success"
    assert summary["capability_name"] == "templates.passive_scan"
    assert len(calls) == 1
    assert calls[0]["capability_name"] == "templates.passive_scan"
    assert calls[0]["reservation_limits"] == action.requested_budget
    assert calls[0]["target_binding"].digest == target.digest
    assert calls[0]["scanner_process_payload"]["scanner_options"] == (
        template_options
    )


def test_tls_stage_uses_registered_inline_capability_with_exact_hold(monkeypatch):
    _plan, target, options = _authority(enabled=True, network=False)
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "tls.inspect",
            observations=[{
                "kind": "tls_protocol",
                "origin": "https://app.example.test",
                "server_hostname": "app.example.test",
                "pinned_address": "192.0.2.10",
                "port": 443,
                "protocol": "TLSv1.3",
            }],
            amounts={
                "tcp_ports_attempted": 1,
                "tool_wall_seconds": 1,
            },
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_tls_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert len(calls) == 1
    call = calls[0]
    assert call["capability_name"] == "tls.inspect"
    assert call["capability_args"] == {
        "origins_ref": "frozen_https_origins",
        "origin_count": 1,
        "addresses_ref": "frozen_addresses",
        "address_count": 1,
    }
    assert call["action_id"] == "deterministic_baseline.tls.inspect"
    assert call["target_binding"] == target
    assert call["reservation_limits"] == {
        "tcp_ports_attempted": 4,
        "tool_wall_seconds": 15,
    }
    assert callable(call["inline_operation"])
    assert "scanner_process_payload" not in call
    assert summary["status"] == "success"
    assert summary["observations"][0]["kind"] == "tls_protocol"
    assert summary["durable_budget_settled"] is True


def test_http_baseline_stage_uses_registered_inline_capability(monkeypatch):
    _plan, target, options = _authority(enabled=True, network=False)
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "http.request",
            observations=[{
                "kind": "http_observation",
                "request": {
                    "method": "HEAD",
                    "origin": "https://app.example.test",
                    "path": "/",
                    "pinned_address": "192.0.2.10",
                },
                "response": {
                    "status": 200,
                    "selected_headers": {"server": "nginx"},
                },
                "redirect_chain": [],
            }],
            amounts={"http_requests": 1, "tool_wall_seconds": 1},
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_http_baseline_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert len(calls) == 1
    call = calls[0]
    assert call["capability_name"] == "http.request"
    assert call["capability_args"] == {
        "method": "HEAD",
        "path": "/",
        "follow_redirects": True,
    }
    assert call["action_id"] == "deterministic_baseline.http.request"
    assert call["target_binding"] == target
    assert call["reservation_limits"] == {
        "http_requests": 4,
        "tool_wall_seconds": 15,
    }
    assert callable(call["inline_operation"])
    assert summary["status"] == "success"
    assert summary["observations"][0]["kind"] == "http_observation"


def test_http_baseline_binds_worker_private_primary_headers(monkeypatch):
    _plan, _target, options = _authority(enabled=True, network=False)
    options = {
        **options,
        "auth_header": "Bearer primary-secret",
        "resolved_credential_profiles": [{
            "profile_id": "profile-1",
            "profile_version": 2,
            "auth_kind": "bearer_token",
            "principal_slot": "primary",
            "scan_lane": "primary",
        }],
    }
    captured = {}

    async def raw_operation(*_args, **kwargs):
        captured.update(kwargs)
        return {
            "ok": True,
            "request": {
                "method": "HEAD",
                "origin": "https://app.example.test",
                "path": "/",
                "query_keys": [],
                "as_principal": kwargs["principal_slot"],
                "body_kind": None,
                "pinned_address": "192.0.2.10",
                "follow_redirects": True,
            },
            "response": {"status": 200, "selected_headers": {}},
            "redirect_chain": [],
        }

    async def execute_capability(**kwargs):
        assert kwargs["capability_args"]["as_principal"] == "primary"
        assert len(kwargs["capability_args"]["principal_binding_digest"]) == 64
        await kwargs["inline_operation"]()
        return _stored_network_capability(
            "http.request",
            observations=[],
            amounts={"http_requests": 1, "tool_wall_seconds": 1},
        ), False

    monkeypatch.setattr(worker, "execute_bound_http_request", raw_operation)
    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )

    asyncio.run(worker._execute_scan_http_baseline_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert captured["trusted_headers"] == {
        "Authorization": "Bearer primary-secret",
    }
    assert captured["principal_slot"] == "primary"


def test_passive_scan_establishes_approved_primary_session_as_a_capability(
    monkeypatch,
):
    _plan, _target, options = _authority(
        enabled=True, network=False, approval=True,
    )
    secret = "form-worker-private-password"
    options = {
        **options,
        "login_username": "operator",
        "login_password": secret,
        "login_url": "/login?tenant=blue",
        "resolved_credential_profiles": [{
            "profile_id": "profile-1",
            "profile_version": 3,
            "auth_kind": "form_login",
            "principal_slot": "primary",
            "scan_lane": "primary",
        }],
    }
    calls = []

    session = SimpleNamespace(
        established=True,
        headers=lambda: {"Cookie": "session=worker-private-cookie"},
        execution_result=lambda: {
            "ok": True,
            "status": "success",
            "observation": {
                "kind": "credential_session",
                "lane": "primary",
                "auth_kind": "form_login",
                "status": "established",
                "endpoint_path": "/login?<redacted-query>",
                "header_names": ["Cookie"],
                "cookie_names": ["session"],
                "secret_values_visible": False,
            },
            "budget_consumed": {
                "http_requests": 2,
                "tool_wall_seconds": 1,
            },
        },
    )

    async def establish(credential, *, target):
        assert target.canonical_host == "app.example.test"
        assert credential.auth_kind == "form_login"
        assert secret not in repr(credential)
        return session

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        operation_result = await kwargs["inline_operation"]()
        assert secret not in json.dumps(operation_result)
        return _stored_network_capability(
            "auth.session.establish",
            observations=[operation_result["observation"]],
            amounts={"http_requests": 2, "tool_wall_seconds": 1},
        ), False

    monkeypatch.setattr(
        worker, "establish_target_bound_http_session", establish,
    )
    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    holder = {}
    summary = asyncio.run(worker._execute_scan_auth_session_capability(
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
        private_session_holder=holder,
    ))

    assert len(calls) == 1
    call = calls[0]
    assert call["capability_name"] == "auth.session.establish"
    assert call["action_id"] == "resolve_inputs.auth.session.establish.primary"
    assert call["reservation_limits"] == {
        "http_requests": 2,
        "tool_wall_seconds": 30,
    }
    assert call["capability_args"]["endpoint_path"] == (
        "/login?<redacted-query>"
    )
    assert secret not in json.dumps(call["capability_args"])
    assert holder["session"] is session
    assert summary["status"] == "success"
    assert summary["worker_private_session_available"] is True
    assert secret not in json.dumps(summary)


def test_interactive_session_never_executes_without_credential_approval(monkeypatch):
    _plan, _target, options = _authority(enabled=True, network=False)
    options = {
        **options,
        "login_username": "operator",
        "login_password": "worker-private-password",
        "login_url": "/login",
    }

    async def unexpected_execution(**_kwargs):
        raise AssertionError("unapproved credential session reached execution")

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", unexpected_execution,
    )
    summary = asyncio.run(worker._execute_scan_auth_session_capability(
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
        private_session_holder={},
    ))

    assert summary["enabled"] is True
    assert summary["status"] == "blocked"
    assert summary["reason"] == "credential_approval_missing"
    assert summary["durable_budget_settled"] is False


def test_secondary_form_session_uses_its_own_reserved_action(monkeypatch):
    _plan, _target, options = _authority(
        enabled=True, network=False, approval=True,
    )
    options = {
        **options,
        "login_url": "/owner/login",
        "user2_login_url": "/attacker/login",
        "user2_login_username": "attacker",
        "user2_login_password": "worker-private-secondary-password",
        "resolved_credential_profiles": [{
            "profile_id": "profile-2",
            "profile_version": 4,
            "auth_kind": "form_login",
            "principal_slot": "secondary",
            "scan_lane": "secondary",
        }],
    }
    session = SimpleNamespace(
        established=True,
        headers=lambda: {"Cookie": "session=worker-private-secondary"},
        execution_result=lambda: {
            "ok": True,
            "status": "success",
            "observation": {
                "kind": "credential_session",
                "lane": "secondary",
                "auth_kind": "form_login",
                "status": "established",
                "endpoint_path": "/attacker/login",
                "header_names": ["Cookie"],
                "cookie_names": ["session"],
                "secret_values_visible": False,
            },
            "budget_consumed": {
                "http_requests": 2,
                "tool_wall_seconds": 1,
            },
        },
    )
    calls = []

    async def establish(credential, *, target):
        assert target.canonical_host == "app.example.test"
        assert credential.lane == "secondary"
        assert credential.endpoint_url == "/attacker/login"
        return session

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        operation_result = await kwargs["inline_operation"]()
        return _stored_network_capability(
            "auth.session.establish",
            observations=[operation_result["observation"]],
            amounts={"http_requests": 2, "tool_wall_seconds": 1},
        ), False

    monkeypatch.setattr(
        worker, "establish_target_bound_http_session", establish,
    )
    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    holder = {}
    summary = asyncio.run(worker._execute_scan_auth_session_capability(
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
        private_session_holder=holder,
        lane="secondary",
    ))

    assert calls[0]["action_id"] == (
        "resolve_inputs.auth.session.establish.secondary"
    )
    assert calls[0]["capability_args"]["lane"] == "secondary"
    assert holder["session"] is session
    assert summary["status"] == "success"


def test_authz_proof_reserves_content_free_binding_before_differential(
    monkeypatch,
):
    _plan, target, options = _authority(enabled=False, network=True)
    primary_secret = "Bearer owner-worker-private"
    secondary_secret = "Bearer attacker-worker-private"
    options = {
        **options,
        "auth_header": primary_secret,
        "user2_header": secondary_secret,
        "resolved_credential_profiles": [{
            "profile_id": "profile-1",
            "profile_version": 3,
            "auth_kind": "bearer_token",
            "principal_slot": "primary",
            "scan_lane": "primary",
        }, {
            "profile_id": "profile-2",
            "profile_version": 4,
            "auth_kind": "bearer_token",
            "principal_slot": "secondary",
            "scan_lane": "secondary",
        }],
    }
    routes = ["/api/orders"]
    calls = []

    async def verify(base_url, supplied_routes, **kwargs):
        assert base_url == "https://app.example.test"
        assert supplied_routes == routes
        assert kwargs["target"] == target
        assert kwargs["primary_headers"] == {
            "Authorization": primary_secret,
        }
        assert kwargs["secondary_headers"] == {
            "Authorization": secondary_secret,
        }
        return {
            "ok": True,
            "status": "success",
            "observation": {
                "kind": "authz_differential",
                "proof_state": "verified",
                "principal_contexts_distinct": True,
                "secret_values_visible": False,
            },
            "budget_consumed": {
                "http_requests": 4,
                "tool_wall_seconds": 1,
            },
        }

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        operation_result = await kwargs["inline_operation"]()
        return _stored_network_capability(
            "authz.verify",
            observations=[operation_result["observation"]],
            amounts={"http_requests": 4, "tool_wall_seconds": 1},
        ), False

    monkeypatch.setattr(
        worker, "verify_target_bound_object_authorization", verify,
    )
    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_authz_verification_capability(
        "https://app.example.test",
        routes,
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert calls[0]["capability_name"] == "authz.verify"
    assert calls[0]["action_id"] == "verify_candidates.authz.verify"
    assert calls[0]["reservation_limits"] == {
        "http_requests": 4,
        "tool_wall_seconds": 60,
    }
    assert calls[0]["capability_args"]["route_count"] == 1
    assert len(calls[0]["capability_args"]["route_inventory_digest"]) == 64
    assert primary_secret not in json.dumps(calls[0]["capability_args"])
    assert secondary_secret not in json.dumps(calls[0]["capability_args"])
    assert summary["status"] == "success"
    assert summary["observations"][0]["proof_state"] == "verified"


def test_placed_http_tools_bind_primary_credentials_without_public_secrets(
    monkeypatch,
):
    _plan, _target, options = _authority(
        enabled=False, network=True, budget=_external_full_budget(),
    )
    secret = "Bearer external-tool-worker-private"
    options = {
        **options,
        "auth_header": secret,
        "resolved_credential_profiles": [{
            "profile_id": "profile-1",
            "profile_version": 3,
            "auth_kind": "bearer_token",
            "principal_slot": "primary",
            "scan_lane": "primary",
        }],
    }
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            kwargs["capability_name"],
            observations=[],
            amounts={
                key: min(1, int(value))
                for key, value in kwargs["reservation_limits"].items()
            },
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    functions_and_targets = (
        (worker._execute_scan_web_probe_capability,
         "https://app.example.test/"),
        (worker._execute_scan_web_crawl_capability,
         "https://app.example.test/"),
        (worker._execute_scan_content_discovery_capability,
         "https://app.example.test/"),
        (worker._execute_scan_template_capability,
         "https://app.example.test/"),
        (worker._execute_scan_xss_verification_capability,
         "https://app.example.test/search?q=test"),
        (worker._execute_scan_sqli_verification_capability,
         "https://app.example.test/search?id=1"),
    )
    summaries = []
    for index, (operation, execution_target) in enumerate(
        functions_and_targets, start=1,
    ):
        summaries.append(asyncio.run(operation(
            execution_target,
            options,
            scan_id="00000000-0000-0000-0000-000000000001",
            job_id=f"job-{index}",
        )))

    assert len(calls) == len(functions_and_targets)
    for call in calls:
        assert call["capability_args"]["as_principal"] == "primary"
        assert len(call["capability_args"]["principal_binding_digest"]) == 64
        assert secret not in json.dumps(call["capability_args"])
        assert call["scanner_process_payload"]["trusted_headers"] == {
            "Authorization": secret,
        }
    assert secret not in json.dumps(summaries)


def test_http_redirect_probe_skips_when_http_origin_is_not_bound(monkeypatch):
    _plan, _target, options = _authority(enabled=True, network=False)

    async def unexpected_execution(**_kwargs):
        raise AssertionError("unbound HTTP origin must never reach the wire")

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", unexpected_execution,
    )
    summary = asyncio.run(worker._execute_scan_http_redirect_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert summary["status"] == "skipped"
    assert summary["reason"] == "http_origin_not_bound"
    assert summary["observations"] == []


def test_http_redirect_probe_uses_bound_http_origin(monkeypatch):
    _plan, _target, options = _authority(enabled=True, network=False)
    target = TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=(
            "https://app.example.test", "http://app.example.test",
        ),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
        scope_receipt_id="scope-1",
    )
    options["_canonical_target_binding"] = target.canonical_dict()
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "http.request",
            observations=[{
                "kind": "http_observation",
                "request": {
                    "method": "HEAD",
                    "origin": "http://app.example.test",
                    "path": "/",
                    "pinned_address": "192.0.2.10",
                },
                "response": {
                    "status": 200,
                    "selected_headers": {"server": "nginx"},
                },
                "redirect_chain": [],
            }],
            amounts={"http_requests": 1, "tool_wall_seconds": 1},
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_http_redirect_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert len(calls) == 1
    call = calls[0]
    assert call["capability_name"] == "http.request"
    assert call["capability_args"] == {
        "method": "HEAD",
        "path": "/",
        "follow_redirects": True,
    }
    assert call["action_id"] == "deterministic_baseline.http_redirect"
    assert call["target_binding"] == target
    assert call["reservation_limits"] == {
        "http_requests": 4,
        "tool_wall_seconds": 15,
    }
    assert callable(call["inline_operation"])
    assert summary["schema_version"] == (
        "canonical-scan-http-redirect-execution/v1"
    )
    assert summary["status"] == "success"


def test_security_txt_stage_uses_fixed_registered_request(monkeypatch):
    _plan, target, options = _authority(enabled=True, network=False)
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "http.request",
            observations=[{
                "kind": "http_observation",
                "request": {
                    "method": "GET",
                    "origin": "https://app.example.test",
                    "path": "/.well-known/security.txt",
                    "pinned_address": "192.0.2.10",
                },
                "response": {
                    "status": 200,
                    "selected_headers": {},
                    "security_txt": {
                        "present": True,
                        "url": (
                            "https://app.example.test/"
                            ".well-known/security.txt"
                        ),
                        "sample": "Contact: mailto:security@example.test",
                    },
                },
                "redirect_chain": [],
            }],
            amounts={"http_requests": 1, "tool_wall_seconds": 1},
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_security_txt_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert len(calls) == 1
    call = calls[0]
    assert call["capability_name"] == "http.request"
    assert call["capability_args"] == {
        "method": "GET",
        "path": "/.well-known/security.txt",
        "follow_redirects": True,
    }
    assert call["action_id"] == "deterministic_baseline.security_txt"
    assert call["target_binding"] == target
    assert call["reservation_limits"] == {
        "http_requests": 4,
        "tool_wall_seconds": 15,
    }
    assert callable(call["inline_operation"])
    assert summary["schema_version"] == (
        "canonical-scan-security-txt-execution/v1"
    )
    assert summary["status"] == "success"


def test_security_txt_receipt_keeps_only_bounded_public_policy(monkeypatch):
    _plan, target, _options = _authority(enabled=True, network=False)

    async def raw_operation(*_args, **_kwargs):
        return {
            "ok": True,
            "request": {
                "method": "GET",
                "origin": "https://app.example.test",
                "path": "/.well-known/security.txt",
                "pinned_address": "192.0.2.10",
            },
            "response": {
                "status": 200,
                "body_sample": (
                    "Contact: mailto:security@example.test\n"
                    "Expires: 2030-01-01T00:00:00Z\n"
                ),
                "selected_json": {"private": "value"},
                "selected_headers": {"authorization": "private"},
                "final_url": (
                    "https://app.example.test/.well-known/security.txt"
                ),
            },
            "redirect_chain": [],
            "hops_followed": 0,
        }

    monkeypatch.setattr(worker, "execute_bound_http_request", raw_operation)
    result = asyncio.run(worker._run_scan_security_txt_operation(
        origin="https://app.example.test",
        capability_args={
            "method": "GET",
            "path": "/.well-known/security.txt",
            "follow_redirects": True,
        },
        target=target,
        timeout_seconds=15,
    ))

    policy = result["response"]["security_txt"]
    assert policy["present"] is True
    assert policy["url"] == (
        "https://app.example.test/.well-known/security.txt"
    )
    assert policy["sample"].startswith("Contact:")
    assert len(policy["sample"]) <= 500
    assert result["response"]["body_sample"] == ""
    assert result["response"]["selected_json"] == {}
    assert result["response"]["selected_headers"] == {}


def test_dns_posture_stage_uses_registered_inline_capability(monkeypatch):
    _plan, target, options = _authority(enabled=True, network=False)
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        return _stored_network_capability(
            "dns.inspect",
            observations=[{
                "kind": "dns_posture",
                "canonical_host": "app.example.test",
                "bound_addresses": {"A": ["192.0.2.10"], "AAAA": []},
                "query_names": {},
                "records": {},
                "authenticated_queries": [],
                "query_count": 8,
                "errors": [],
            }],
            amounts={"hosts_attempted": 4, "tool_wall_seconds": 1},
        ), False

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_dns_capability(
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert len(calls) == 1
    call = calls[0]
    assert call["capability_name"] == "dns.inspect"
    assert call["capability_args"] == {}
    assert call["action_id"] == "deterministic_baseline.dns.inspect"
    assert call["target_binding"] == target
    assert call["reservation_limits"] == {
        "hosts_attempted": 4,
        "tool_wall_seconds": 15,
    }
    assert callable(call["inline_operation"])
    assert summary["schema_version"] == (
        "canonical-scan-dns-inspection-execution/v1"
    )
    assert summary["status"] == "success"


def test_http_baseline_receipt_redacts_paths_queries_and_bodies(monkeypatch):
    _plan, target, _options = _authority(enabled=True, network=False)

    async def raw_operation(*_args, **_kwargs):
        return {
            "ok": True,
            "request": {
                "method": "HEAD",
                "origin": "https://app.example.test",
                "path": "/reset/secret-value-123456789012345678901234?q=token",
                "pinned_address": "192.0.2.10",
            },
            "response": {
                "status": 302,
                "body_sample": "private response body",
                "selected_json": {"token": "private"},
                "selected_headers": {
                    "server": "nginx",
                    "authorization": "Bearer private",
                },
                "final_url": (
                    "https://app.example.test/reset/"
                    "secret-value-123456789012345678901234?q=token"
                ),
                "location": "/reset/token/opaque-secret-value-1234567890?q=x",
            },
            "redirect_chain": [{
                "status": 302,
                "location": "/reset/token/opaque-secret-value-1234567890?q=x",
                "followed": True,
            }],
            "hops_followed": 1,
        }

    monkeypatch.setattr(worker, "execute_bound_http_request", raw_operation)
    result = asyncio.run(worker._run_scan_http_baseline_operation(
        origin="https://app.example.test",
        capability_args={
            "method": "HEAD", "path": "/", "follow_redirects": True,
        },
        target=target,
        timeout_seconds=15,
    ))

    assert result["request"]["path"] == (
        "/reset/<redacted>?q=%3Credacted%3E"
    )
    assert result["response"]["body_sample"] == ""
    assert result["response"]["selected_json"] == {}
    assert result["response"]["selected_headers"] == {"server": "nginx"}
    assert "secret-value" not in result["response"]["final_url"]
    assert "opaque-secret" not in result["redirect_chain"][0]["location"]


def test_network_policy_runs_two_registry_actions_with_partitioned_budget(
    monkeypatch,
):
    _plan, _target, options = _authority(enabled=False, network=True)
    calls = []

    async def execute_capability(**kwargs):
        calls.append(kwargs)
        if kwargs["capability_name"] == "ports.discover":
            return _stored_network_capability(
                "ports.discover",
                observations=[{
                    "kind": "open_port",
                    "address": "192.0.2.10",
                    "port": 21,
                    "transport": "tcp",
                }],
                amounts={
                    "hosts_attempted": 1,
                    "tcp_ports_attempted": 5,
                    "tool_wall_seconds": 30,
                },
            ), False
        return _stored_network_capability(
            "service.fingerprint",
            observations=[{
                "kind": "service",
                "address": "192.0.2.10",
                "port": 21,
                "service": "ftp",
            }],
            amounts={
                "hosts_attempted": 1,
                "tcp_ports_attempted": 1,
                "tool_wall_seconds": 30,
            },
        ), False

    monkeypatch.setattr(
        worker,
        "_execute_reserved_scan_capability",
        execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_network_discovery(
        options,
        "00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert [call["capability_name"] for call in calls] == [
        "ports.discover", "service.fingerprint",
    ]
    assert calls[0]["capability_args"]["ports"] == [21, 22, 25, 53]
    assert calls[1]["capability_args"]["ports"] == [21]
    assert calls[0]["target_binding"].allowed_addresses == ("192.0.2.10",)
    assert sum(
        call["reservation_limits"]["tcp_ports_attempted"] for call in calls
    ) == 8
    assert sum(
        call["reservation_limits"]["tool_wall_seconds"] for call in calls
    ) == 60
    assert summary["status"] == "success"
    assert summary["open_ports"][0]["port"] == 21
    assert summary["services"][0]["service"] == "ftp"
    assert summary["durable_budget_settled"] is True


def test_worker_runs_subdomain_discovery_inside_the_fixed_surface_stage():
    root = Path(__file__).resolve().parents[1]
    source = (root / "api" / "worker.py").read_text()
    dispatcher = (root / "api" / "scan" / "action_adapter.py").read_text()
    reservation_start = source.index(
        "async def _execute_reserved_scan_capability("
    )
    helper_start = source.index("async def _execute_scan_subdomain_discovery(")
    reservation_helper = source[reservation_start:helper_start]
    helper_end = source.index("\n\ndef _attach_scan_subdomain_summary", helper_start)
    helper = source[helper_start:helper_end]
    deterministic_start = source.index(
        "async def _execute_reserved_deterministic_scan("
    )
    deterministic = source[deterministic_start:helper_start]
    standalone_start = source.index("async def process_scan_job(")
    standalone_end = source.index("\n\nasync def process_scan_plan_job", standalone_start)
    standalone = source[standalone_start:standalone_end]
    shard_start = source.index("async def process_scan_shard_job(")
    shard_end = source.index("\n\nasync def process_scan_merge_job", shard_start)
    shard = source[shard_start:shard_end]
    plan_start = source.index("async def process_scan_plan_job(")
    plan = source[plan_start:shard_start]
    merge = source[shard_end:source.index("\n\nasync def process_exploit_batch_job", shard_end)]

    assert "network_capability_adapter(capability_name)" in reservation_helper
    assert "PostgresBudgetReservationStore" in reservation_helper
    assert reservation_helper.index("reserve_against(") < reservation_helper.index(
        "CapabilityExecutor().execute("
    )
    assert "heartbeat_reservation" in reservation_helper
    assert "terminalize_capability_reservation(" in reservation_helper
    assert "persist_terminal(" in reservation_helper
    assert 'capability_name="subdomains.discover"' in helper
    assert "async def _execute_scan_network_discovery(" in helper
    assert 'capability_name="ports.discover"' in helper
    assert 'capability_name="service.fingerprint"' in helper
    assert "automatically_scanned_discovered_hosts" in source
    assert "PostgresScanActionStore" in deterministic
    assert "PostgresScanExecutionBackend" in deterministic
    assert "ScanOrchestrator(" in deterministic
    assert "class DatabaseNeutralScanActionDispatcher" in dispatcher
    assert '"ports.discover", "service.fingerprint", "subdomains.discover"' in dispatcher
    assert "return await self._network(action, heartbeat)" in dispatcher
    assert '"web.probe", "web.crawl", "web.content_discover"' in dispatcher
    assert "return await self._external(action, heartbeat)" in dispatcher
    assert "run_scan(" not in dispatcher
    assert "_execute_scan_subdomain_discovery(" not in standalone
    assert standalone.index("_hydrate_generic_scan_credentials(") < (
        standalone.index("_execute_reserved_deterministic_scan(")
    )
    assert "_execute_scan_network_discovery(" not in standalone
    assert "parallel_discovery" in shard
    assert "_execute_scan_subdomain_discovery(" not in shard
    assert "_execute_scan_network_discovery(" not in shard
    assert "canonical_subdomain_discovery" in plan
    assert "canonical_network_discovery" in plan
    assert "needs_placed_discovery" in plan
    assert "canonical_subdomain_discovery" in merge
    assert "canonical_network_discovery" in merge
    assert "_attach_scan_subdomain_summary(" in merge
