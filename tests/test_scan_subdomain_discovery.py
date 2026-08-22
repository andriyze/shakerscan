from __future__ import annotations

import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
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
from scan.execution import ScanExecutionPlan


def _authority(*, enabled: bool = True, network: bool = False):
    plan = ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=network,
            network_discovery=network,
            subdomain_discovery=enabled,
            scope_receipt_id="scope-1",
            approval_receipt_id="approval-1" if network else None,
        ),
        budget_profile="balanced",
        budget=ScanBudget(1_200, 100, 50, 20, 10, 60, 2),
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


def test_deterministic_scan_reserves_remaining_budget_before_process_and_redelivery(
    monkeypatch,
):
    plan, _target, options = _authority(enabled=True)
    connection = _Connection(plan)
    connection.row["budget_used_json"] = {
        "http_requests": 7,
        "state_changing_requests": 0,
        "browser_actions": 2,
        "tcp_ports_attempted": 0,
        "hosts_attempted": 1,
        "tool_wall_seconds": 5,
    }
    events = []
    store = _ReservationStore(events)
    calls = 0

    async def fake_run_scan(
        target,
        runtime_options,
        scan_id=None,
        job_id=None,
        canonical_runtime_budget=None,
        **_kwargs,
    ):
        nonlocal calls
        calls += 1
        events.append(("traffic", store.current.record.status))
        assert target == "https://app.example.test"
        assert runtime_options["scan_execution_plan_digest"] == plan.digest
        assert canonical_runtime_budget == {
            "http_requests": 93,
            "state_changing_requests": 0,
            "browser_actions": 18,
            "tcp_ports_attempted": 1,
            "hosts_attempted": 49,
            "tool_wall_seconds": 55,
        }
        return {
            "target": target,
            "findings": [{"id": "finding-1"}],
            "result": {"score": 90, "grade": "A"},
            "coverage": {"status": "complete"},
            "discovery": {"browser_crawl": {"pages_visited": 2}},
            "tls": {
                "canonical_runtime": {
                    "schema_version": "canonical-tls-runtime/v1",
                    "tcp_ports_attempted": 1,
                },
            },
            "request_budget": {
                "schema_version": "request_meter_v1",
                "mode": "enforce",
                "fully_metered": True,
                "attempted_requests": 3,
                "state_changing_attempted_requests": 0,
            },
            "scan_metadata": {"schema_version": "scan-report/v2"},
        }

    async def skip_web_probe(*_args, **_kwargs):
        return worker._skipped_scan_web_probe_summary("test_isolation")

    monkeypatch.setattr(worker, "db_pool", _Pool(connection))
    monkeypatch.setattr(worker, "PostgresBudgetReservationStore", lambda: store)
    monkeypatch.setattr(worker, "run_scan", fake_run_scan)
    monkeypatch.setattr(
        worker,
        "_execute_scan_web_probe_capability",
        skip_web_probe,
    )
    monkeypatch.setattr(worker, "_worker_runtime_identity", lambda: "worker:test")
    monkeypatch.setattr(worker, "_scan_cancel_requested", lambda _scan_id: False)

    result = asyncio.run(worker._execute_reserved_deterministic_scan(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert events[:3] == [
        ("create", "requested"),
        ("transition", "reserved"),
        ("transition", "running"),
    ]
    assert ("traffic", "running") in events
    assert events[-1] == ("terminal", "committed")
    assert calls == 1
    assert store.current.record.actual["http_requests"] == 3
    assert store.current.record.actual["browser_actions"] == 2
    assert result["deterministic_scan_execution"]["receipt"][
        "budget_reservation_state"
    ] == "committed"

    connection.row["result"] = result
    redelivered = asyncio.run(worker._execute_reserved_deterministic_scan(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))
    assert calls == 1
    assert redelivered["deterministic_scan_execution"][
        "idempotent_redelivery"
    ] is True


def test_active_scan_places_reserved_nuclei_before_baseline_process(monkeypatch):
    plan, _target, options = _authority(enabled=False, network=True)
    connection = _Connection(plan)
    events = []
    store = _ReservationStore(events)
    placement_seen = {}

    async def fake_external_tool(payload, *, heartbeat):
        tool = payload["tool_name"]
        events.append((tool, store.current.record.status))
        assert payload["_cancelled"]() is False
        await heartbeat()
        if tool == "httpx":
            return {
                "status": "success",
                "elapsed_seconds": 1,
                "typed_output": {
                    "parser": "httpx-typed-v1",
                    "records": [{
                        "kind": "http_fingerprint",
                        "url": "https://app.example.test/",
                        "status": 200,
                        "title": "Example",
                        "webserver": "nginx",
                        "technologies": ["nginx"],
                    }],
                    "errors": [],
                },
                "settlement": {"mode": "exact", "actual": 1},
            }
        if tool == "katana":
            return {
                "status": "success",
                "elapsed_seconds": 2,
                "typed_output": {
                    "parser": "katana-typed-v1",
                    "records": [{
                        "kind": "discovered_route",
                        "url": "https://app.example.test/api/orders?q=%3Credacted%3E",
                        "method": "GET",
                        "source": "https://app.example.test/",
                    }],
                    "errors": [],
                },
                "settlement": {
                    "mode": "observed_lower_bound",
                    "actual": None,
                    "observed_minimum": 2,
                },
            }
        if tool == "ffuf":
            return {
                "status": "success",
                "elapsed_seconds": 2,
                "typed_output": {
                    "parser": "ffuf-typed-v1",
                    "records": [{
                        "kind": "content_discovery",
                        "url": "https://app.example.test/admin",
                        "status": 403,
                        "length": 120,
                        "redirect_location": None,
                    }],
                    "errors": [],
                },
                "settlement": {
                    "mode": "observed_lower_bound",
                    "actual": None,
                    "observed_minimum": 2,
                },
            }
        if tool == "nuclei":
            return {
                "status": "success",
                "elapsed_seconds": 2,
                "typed_output": {
                    "parser": "nuclei-typed-v1",
                    "records": [{
                        "kind": "template_match",
                        "template_id": "example-cve",
                        "name": "Example CVE",
                        "severity": "high",
                        "matched_at": "https://app.example.test/",
                        "proof_state": "candidate",
                    }],
                    "errors": [],
                },
                "settlement": {"mode": "exact", "actual": 3},
            }
        if tool == "dalfox":
            return {
                "status": "success",
                "elapsed_seconds": 2,
                "typed_output": {
                    "parser": "dalfox-typed-v1",
                    "records": [{
                        "kind": "xss_alert",
                        "alert_type": "V",
                        "url": "https://app.example.test/api/orders?q=%3Credacted%3E",
                        "param": "q",
                        "payload_sha256": "a" * 64,
                        "message": "verified alert",
                        "proof_state": "verified",
                    }],
                    "errors": [],
                },
                "settlement": {"mode": "exact", "actual": 2},
            }
        assert tool == "sqlmap"
        return {
            "status": "success",
            "elapsed_seconds": 2,
            "typed_output": {
                "parser": "sqlmap-typed-v1",
                "records": [{
                    "kind": "sqli_finding",
                    "message": "Parameter 'q' is vulnerable.",
                    "param": "q",
                    "method": None,
                    "proof_state": "candidate",
                }, {
                    "kind": "sqli_dbms_fingerprint",
                    "message": "[INFO] back-end DBMS: PostgreSQL",
                    "proof_state": "candidate",
                }],
                "errors": [],
            },
            "settlement": {"mode": "exact", "actual": 2},
        }

    async def fake_run_scan(
        target,
        runtime_options,
        scan_id=None,
        job_id=None,
        canonical_runtime_budget=None,
        canonical_placed_capabilities=None,
        **_kwargs,
    ):
        events.append(("baseline", store.current.record.status))
        placement_seen.update(canonical_placed_capabilities or {})
        assert target == "https://app.example.test"
        assert canonical_runtime_budget == {
            "http_requests": 88,
            "state_changing_requests": 0,
            "browser_actions": 20,
            "tcp_ports_attempted": 1,
            "hosts_attempted": 50,
            "tool_wall_seconds": 49,
        }
        return {
            "target": target,
            "findings": [],
            "result": {"score": 90, "grade": "A"},
            "coverage": {"status": "complete"},
            "discovery": {"browser_crawl": {"pages_visited": 0}},
            "tls": {
                "canonical_runtime": {
                    "schema_version": "canonical-tls-runtime/v1",
                    "tcp_ports_attempted": 1,
                },
            },
            "request_budget": {
                "schema_version": "request_meter_v1",
                "mode": "enforce",
                "fully_metered": True,
                "attempted_requests": 4,
                "state_changing_attempted_requests": 0,
            },
            "scan_metadata": {"schema_version": "scan-report/v2"},
        }

    monkeypatch.setattr(worker, "db_pool", _Pool(connection))
    monkeypatch.setattr(worker, "PostgresBudgetReservationStore", lambda: store)
    monkeypatch.setattr(worker, "_execute_agent_scanner_process", fake_external_tool)
    monkeypatch.setattr(worker, "run_scan", fake_run_scan)
    monkeypatch.setattr(worker, "_worker_runtime_identity", lambda: "worker:test")
    monkeypatch.setattr(worker, "_scan_cancel_requested", lambda _scan_id: False)

    result = asyncio.run(worker._execute_reserved_deterministic_scan(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
        network_discovery_summary={
            "status": "success",
            "actions": [],
        },
    ))

    assert ("httpx", "running") in events
    assert ("katana", "running") in events
    assert ("ffuf", "running") in events
    assert ("nuclei", "running") in events
    assert ("dalfox", "running") in events
    assert ("sqlmap", "running") in events
    assert ("baseline", "running") in events
    assert events.index(("httpx", "running")) < events.index(
        ("katana", "running")
    )
    assert events.index(("katana", "running")) < events.index(
        ("ffuf", "running")
    )
    assert events.index(("ffuf", "running")) < events.index(
        ("nuclei", "running")
    )
    assert events.index(("nuclei", "running")) < events.index(
        ("dalfox", "running")
    )
    assert events.index(("dalfox", "running")) < events.index(
        ("sqlmap", "running")
    )
    assert events.index(("sqlmap", "running")) < events.index(
        ("baseline", "running")
    )
    assert placement_seen["templates.scan"]["status"] == "success"
    assert placement_seen["web.probe"]["status"] == "success"
    assert placement_seen["web.probe"]["observations"][0]["status"] == 200
    assert placement_seen["web.crawl"]["status"] == "success"
    assert placement_seen["web.crawl"]["observations"][0]["url"] == (
        "https://app.example.test/api/orders?q=%3Credacted%3E"
    )
    assert placement_seen["web.content_discover"]["status"] == "success"
    assert placement_seen["web.content_discover"]["observations"][0][
        "status"
    ] == 403
    assert placement_seen["templates.scan"]["observations"][0][
        "proof_state"
    ] == "candidate"
    assert placement_seen["xss.verify"]["status"] == "success"
    assert placement_seen["xss.verify"]["observations"][0][
        "proof_state"
    ] == "verified"
    assert placement_seen["sqli.verify"]["status"] == "success"
    assert placement_seen["sqli.verify"]["observations"][0]["url"] == (
        "https://app.example.test/api/orders?q=%3Credacted%3E"
    )
    assert placement_seen["sqli.verify"]["observations"][0][
        "proof_state"
    ] == "candidate"
    assert result["canonical_capabilities"]["templates.scan"][
        "receipt"
    ]["budget_reservation_state"] == "committed"
    assert result["canonical_capabilities"]["xss.verify"][
        "receipt"
    ]["budget_reservation_state"] == "committed"
    assert result["canonical_capabilities"]["sqli.verify"][
        "receipt"
    ]["budget_reservation_state"] == "committed"
    stage_execution = result["canonical_stage_execution"]
    assert [row["name"] for row in stage_execution["stages"]] == [
        "bind_target",
        "resolve_inputs",
        "discover_surface",
        "discover_network",
        "deterministic_baseline",
        "deterministic_active",
        "verify_candidates",
        "finalize_evidence",
    ]
    assert stage_execution["stages"][5]["adapter"] == "native_worker"
    assert stage_execution["stages"][5]["capability_names"] == [
        "xss.verify", "sqli.verify",
    ]
    assert stage_execution["stages"][6]["adapter"] == (
        "native_worker.proof_contracts"
    )
    assert stage_execution["stages"][6]["capability_names"] == []
    verification = result["canonical_candidate_verification"]
    assert verification["xss"]["verified_count"] == 1
    assert verification["sqli"]["verified_count"] == 0
    assert verification["sqli"]["suspected_count"] == 1
    assert verification["sqli"]["promotion_blocked_reason"] == (
        "deterministic_differential_missing"
    )
    assert stage_execution["stages"][7]["capability_names"] == [
        "scan.execute"
    ]


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


def test_enabled_network_stage_requires_placement_before_surface_traffic(
    monkeypatch,
):
    _plan, _target, options = _authority(enabled=False, network=True)

    async def unexpected_surface_traffic(*_args, **_kwargs):
        raise AssertionError("surface traffic ran before network placement check")

    monkeypatch.setattr(
        worker, "_execute_scan_web_probe_capability", unexpected_surface_traffic,
    )

    with pytest.raises(
        worker.ScanCapabilityContractError,
        match="discover_network stage requires",
    ):
        asyncio.run(worker._execute_reserved_deterministic_scan(
            "https://app.example.test",
            options,
            scan_id="00000000-0000-0000-0000-000000000001",
            job_id="job-1",
        ))


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


def test_external_scan_tool_reserves_before_process_and_settles_typed_output(
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

    stored, redelivery = asyncio.run(
        worker._execute_reserved_scan_capability(
            admission=admission,
            execution=execution,
            scan_id="00000000-0000-0000-0000-000000000001",
            job_id="job-1",
            capability_name="templates.scan",
            capability_args={},
            action_id="deterministic_baseline.templates",
            target_binding=target,
            reservation_limits={
                "http_requests": 20,
                "tool_wall_seconds": 10,
            },
            scanner_process_payload={"tool_name": "nuclei"},
            scanner_process_runner=process_runner,
            scanner_result_holder=process_result,
        )
    )

    assert events[:3] == [
        ("create", "requested"),
        ("transition", "reserved"),
        ("transition", "running"),
    ]
    assert ("traffic", "running") in events
    assert events[-1] == ("terminal", "committed")
    assert stored.record.capability_name == "templates.scan"
    assert stored.record.actual == {
        "http_requests": 3,
        "tool_wall_seconds": 2,
    }
    assert stored.receipt["observations"][0]["template_id"] == "example-cve"
    assert process_result["result"]["status"] == "success"
    assert redelivery is False


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
        "web.probe": ("httpx", "httpx-typed-v1"),
        "web.crawl": ("katana", "katana-typed-v1"),
        "web.content_discover": ("ffuf", "ffuf-typed-v1"),
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
    _plan, _target, options = _authority(enabled=False, network=True)
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
        "http_requests": 25,
        "tool_wall_seconds": 15,
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
    _plan, _target, options = _authority(enabled=False, network=True)
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
        "http_requests": 10,
        "tool_wall_seconds": 6,
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
    _plan, _target, options = _authority(enabled=False, network=True)
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
        "http_requests": 10,
        "tool_wall_seconds": 6,
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
        "http_requests": 4,
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


def test_content_discovery_never_runs_without_active_permission(monkeypatch):
    _plan, _target, options = _authority(enabled=True, network=False)

    async def execute_capability(**_kwargs):
        raise AssertionError("passive Scan launched FFUF")

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_content_discovery_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert summary["status"] == "skipped"
    assert summary["reason"] == "active_testing_not_authorized"


def test_crawl_stage_never_runs_without_active_permission(monkeypatch):
    _plan, _target, options = _authority(enabled=True, network=False)

    async def execute_capability(**_kwargs):
        raise AssertionError("passive Scan launched Katana")

    monkeypatch.setattr(
        worker, "_execute_reserved_scan_capability", execute_capability,
    )
    summary = asyncio.run(worker._execute_scan_web_crawl_capability(
        "https://app.example.test",
        options,
        scan_id="00000000-0000-0000-0000-000000000001",
        job_id="job-1",
    ))

    assert summary["status"] == "skipped"
    assert summary["reason"] == "active_testing_not_authorized"


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


def test_worker_wires_discovery_before_credentials_and_only_once_per_scan_role():
    source = (Path(__file__).resolve().parents[1] / "api" / "worker.py").read_text()
    reservation_start = source.index(
        "async def _execute_reserved_scan_capability("
    )
    helper_start = source.index("async def _execute_scan_subdomain_discovery(")
    reservation_helper = source[reservation_start:helper_start]
    helper_end = source.index("\n\ndef _attach_scan_subdomain_summary", helper_start)
    helper = source[helper_start:helper_end]
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
    assert standalone.index("_execute_scan_subdomain_discovery(") < standalone.index(
        "_hydrate_generic_scan_credentials("
    ) < standalone.index("_execute_reserved_deterministic_scan(")
    assert standalone.index("_execute_scan_network_discovery(") < standalone.index(
        "_hydrate_generic_scan_credentials("
    )
    assert "parallel_discovery" in shard
    assert shard.index("_execute_scan_subdomain_discovery(") < shard.index(
        "result = await _execute_reserved_deterministic_scan("
    )
    assert "canonical_subdomain_discovery" in plan
    assert "canonical_network_discovery" in plan
    assert "needs_placed_discovery" in plan
    assert "canonical_subdomain_discovery" in merge
    assert "canonical_network_discovery" in merge
    assert "_attach_scan_subdomain_summary(" in merge
