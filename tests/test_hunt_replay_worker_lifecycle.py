"""Production admission and complete replay worker, real loopback HTTP and ledger.

Only persistence/queue/authority I/O are doubled. The worker function is compiled
unchanged from its composition root so this exercises its actual budget call site,
not a hand-written reconstruction of that call or a source-string assertion.
"""
from __future__ import annotations

import ast
import asyncio
from contextlib import AsyncExitStack
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace
from typing import Any, Mapping
import uuid

import pytest

from capabilities.network import CapabilityInputError
from capabilities.replay import ReplayExecutionAdapter, worker_hunt_replay_budget, hunt_replay_additional_budget
from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from hunt.service_binding import collection_uses_service_origin, registered_hunt_locator
from hunt.target_binding import web_hunt_target
from hunt.worker_accounting import worker_hunt_budget_accounting
from hunt.verification_budget import record_budget_shortage
from runtime.budget_reservations import DurableBudgetReservation
from runtime.budgets import BudgetExceeded
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.credential_refs import CredentialReferenceError
from runtime.credential_resolver import CredentialResolutionError
from runtime.models import ScanPolicy, TargetBinding
from runtime.pinned_http_replay import PinnedAiohttpReplayTransport
from runtime.request_collection_store import (
    RequestCollectionContractError, RequestCollectionSelection, request_collection_selection_digest,
)
from runtime.request_replay_executor import ReplayExecutionError, replay_reservation_budget
from runtime.reservation_store import StoredBudgetReservation, ReservationConflict, ReservationStoreError
from scan.authorization import ActionAuthorityDecision, revalidate_scan_action_authority
from scanner_tools.request_collections import RequestSelector, select_requests
from scanner_tools.request_replay import ReplayAuthorization, RequestReplayError, build_selected_replay_plan
from tests.test_hunt_authz_verification_limit import AdmissionStore, Lifecycle, admission, HUNT, TARGET


class Store:
    def __init__(self):
        self.rows = {}
        self.transitions = []

    async def load(self, conn, reservation_id, **_):
        return self.rows.get(reservation_id)

    async def create_requested(self, conn, *, record, action_id, action_digest):
        stored = StoredBudgetReservation(action_id, action_digest, record)
        self.rows[record.reservation_id] = stored
        self.transitions.append(record.status)
        return stored

    async def persist_transition(self, conn, *, previous, current, ledger_after_hold=None):
        assert self.rows[current.reservation_id].record.state_digest == previous.record.state_digest
        stored = replace(previous, record=current, ledger_after_hold=ledger_after_hold or previous.ledger_after_hold)
        self.rows[current.reservation_id] = stored
        self.transitions.append(current.status)
        return stored

    async def persist_terminal(self, conn, *, previous, terminal, ledger_after_settlement, receipt):
        assert self.rows[terminal.reservation_id].record.state_digest == previous.record.state_digest
        stored = replace(previous, record=terminal, ledger_after_settlement=ledger_after_settlement,
                         receipt=receipt.public_dict() if receipt is not None else None)
        self.rows[terminal.reservation_id] = stored
        self.transitions.append(terminal.status)
        return stored


class Connection(AdmissionStore):
    def __init__(self, *, kind, origin, registered_origin, active_limit, method="GET"):
        super().__init__()
        cid, bid, sid = (str(uuid.UUID(int=n)) for n in (3, 4, 5))
        payload = {"collection": {"info": {"name": "replay fixture"}, "item": [
            {"name": "read", "request": {"method": method, "url": origin + "/probe"}},
        ]}}
        self.request_id = select_requests(payload, RequestSelector(limit=1, safe_methods_only=False))[0]["id"]
        self.method = method
        replay_policy = "safe_reads" if method == "GET" else "confirmed_active"
        self.plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(self.plaintext.encode()).hexdigest()
        selector = RequestCollectionSelection(request_ids=(self.request_id,), safe_methods_only=method == "GET", max_requests=1)
        selection_digest = request_collection_selection_digest(
            collection_id=cid, payload_sha256=digest, binding_id=bid,
            allowed_origins=[origin], selector=selector, replay_policy=replay_policy, environment_sha256=None,
        )
        self.collection = {
            "id": cid, "encrypted_payload": "encrypted-fixture", "payload_sha256": digest,
            "binding_id": bid, "allowed_origins": [origin], "environment_id": None,
            "environment_sha256": None, "selection_id": sid, "selection_digest": selection_digest,
            "selector_json": selector.public_dict(), "replay_policy": replay_policy,
        }
        self.run.update(target_kind=kind, target_id=None if kind == "device" else TARGET,
                        device_target_id=TARGET if kind == "device" else None)
        self.run["context_pack"] = {
            "target": {"locator" if kind == "device" else "url": registered_origin},
            "authorized_target_addresses": ["127.0.0.1"],
            "request_collections": [{"collection_id": cid, "selection_id": sid, "allowed_origins": [origin],
                "replay_policy": replay_policy, "selector": selector.public_dict(), "payload_sha256": digest}],
        }
        self.registered_locator = registered_origin
        self.run["policy_json"].update(active_testing=True, approval_receipt_id=str(uuid.UUID(int=6)))
        self.run["budget_json"].update(max_active_actions=active_limit, max_device_fragility_points=20)
        self.run["policy_json"]["allowed_capabilities"] = ["collections.replay_safe", "collections.replay_active", "http.request"]
        self.run["policy_json"]["allow_state_changing_http"] = method != "GET"
        self.run["budget_json"]["max_state_changing_requests"] = 100
        self.approvals = []
        self.result = None
        self.raw_archive = []
        self.store = Store()

    async def fetch(self, query, *args):
        assert "FROM request_collection_requests" in query
        return [{"request_id": self.request_id, "ordinal": 0, "folder": "", "name": "fixture",
            "method": self.method, "redacted_url": self.collection["allowed_origins"][0] + "/probe",
            "normalized_path": "/probe", "body_mode": "none", "auth_type": None,
            "tags_json": [], "safe_method": self.method == "GET", "supported": True}]

    async def fetchrow(self, query, *args):
        if "FROM hunt_runs" in query:
            return self.run
        if "FROM request_collections" in query:
            return self.collection
        if "FROM targets" in query or "FROM device_targets" in query:
            return {"locator": self.registered_locator, "url": self.registered_locator,
                    "primary_locator": self.registered_locator, "is_active": True}
        if "FROM scope_receipts" in query:
            return {"id": "scope", "target_id": TARGET, "allowed_hosts": ["fixture.test"], "verdict": "allowed"}
        if "FROM approval_receipts" in query:
            self.approvals.append("dispatch")
            return {"id": uuid.UUID(int=6), "scope_receipt_id": "scope", "approved_by": "operator",
                    "action_name": "target.authorization", "risk_tier": "active", "expires_at": None,
                    "confirmations": ["confirm_authorized"]}
        return await super().fetchrow(query, *args)

    async def execute(self, query, *args):
        if query.startswith("UPDATE hunt_actions"):
            action = self.actions[str(args[0])]
            if "SET status=$2" in query:
                action.update(status=args[1], result_summary=json.loads(args[2]), receipt_id=args[3])
            elif "status='running'" in query:
                action["status"] = "running"
            else:
                action.update(status="failed", result_summary=json.loads(args[1]))
            return "UPDATE 1"
        if "UPDATE hunt_runs SET status='budget_exhausted'" in query:
            self.run.update(status="budget_exhausted", stop_reason=args[1])
            return "UPDATE 1"
        return await super().execute(query, *args)

    def exists(self, key):
        return False

    def set(self, key, value, **_):
        self.result = json.loads(value)

    def hset(self, *_, **__):
        pass

    def expire(self, *_):
        pass

    def delete(self, *_):
        pass


async def noop(*_, **__):
    pass


def worker(conn):
    path = Path(__file__).resolve().parents[1] / "api/worker.py"
    names = {"process_request_collection_replay_job", "_worker_hunt_ledger_limits", "_worker_terminal_replay_result",
             "_revalidate_hunt_action_authority"}
    tree = ast.parse(path.read_text())
    definitions = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names]
    assert len(definitions) == len(names)
    # Keep real worker authority and receipt evaluation; only storage I/O is doubled.
    async def dispatch(**kwargs):
        return await CapabilityExecutor().execute(
            CapabilityExecutionContext(specification=kwargs["specification"], target=kwargs["target"],
                requested_budget=kwargs["requested_budget"], adapter_managed_cancellation=True),
            kwargs["adapter"], heartbeat=kwargs["heartbeat"], cancelled=kwargs["cancelled"],
        )
    async def archive(_conn, rows, *_):
        conn.raw_archive.extend(rows)
    namespace = {**globals(), "db_pool": conn, "get_redis": lambda: conn,
                 "RESULTS_DIR": path.parents[1],
                 "http_archive": SimpleNamespace(hunt_run_call_recorder=lambda *_, **__: (rows := [], rows.append),
                                                 archive_hunt_capture=archive),
        "PostgresBudgetReservationStore": lambda: conn.store,
        "decrypt_secret": lambda encrypted: conn.plaintext if encrypted == "encrypted-fixture" else None,
        "_worker_json_object": lambda v: json.loads(v) if isinstance(v, str) else dict(v or {}),
        "_worker_json_array": lambda v: json.loads(v) if isinstance(v, str) else list(v or []),
        "_worker_runtime_identity": lambda: "worker:fixture", "_worker_hunt_web_target": web_hunt_target,
        "_AGENT_TOOL_RESULT_TTL_SECONDS": 60,
        "agent_tools": SimpleNamespace(CAPABILITY_REGISTRY=CAPABILITY_REGISTRY),
        "require_device_admission": noop, "record_device_traffic": noop,
        "require_worker_device_policy": lambda _, capability=None: None,
        "_dispatch_registered_hunt_adapter": dispatch,
    }
    module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
                              *definitions], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(path), "exec"), namespace)
    return namespace["process_request_collection_replay_job"]


async def execute(conn, capability="collections.replay_safe"):
    fn = admission(conn)
    async def approval(*_, **kwargs):
        conn.approvals.append(kwargs["risk_tier"])
        return {"scope_receipt_id": "scope"}
    async def load_collection(*_, **__):
        return conn.collection, conn.run["context_pack"]["request_collections"][0]
    fn.__globals__.update(
        _hunt_bound_collection=load_collection,
        _hunt_public=lambda *_a, **_kw: {"capabilities": [{"name": capability}]},
        _hunt_managed_principal_reference=lambda *_, **__: None,
        collection_uses_service_origin=collection_uses_service_origin,
        web_hunt_target=web_hunt_target, _validate_approval_receipt_for_action=approval,
        require_device_admission=noop,
    )
    life = Lifecycle(capability)
    life.specification = CAPABILITY_REGISTRY.require(capability)
    life.placement = life.specification.hunt_executor
    action = await fn(str(HUNT), capability, SimpleNamespace(
        input={"collection_id": conn.collection["id"]}, idempotency_key="replay-" + str(len(conn.actions)),
    ), life)
    job = {
        "job_id": str(uuid.uuid4()), "hunt_id": str(HUNT), "action_id": action["action_id"],
        "action_digest": "a" * 64, "reservation_id": str(uuid.uuid4()),
        "collection_id": conn.collection["id"], "binding_id": conn.collection["binding_id"],
        "selection_id": conn.collection["selection_id"], "selection_digest": conn.collection["selection_digest"],
        "expected_payload_sha256": conn.collection["payload_sha256"],
        "allowed_origins": conn.collection["allowed_origins"], "replay_policy": conn.collection["replay_policy"], "capability_name": capability,
        "selector": {"request_ids": [conn.request_id], "limit": 1}, "tool_wall_seconds": 60,
    }
    await worker(conn)(job)
    return conn.result


@pytest.mark.parametrize("kind", ["web", "api", "network", "device"])
@pytest.mark.parametrize("active_limit,alternate", [(0, True), (1, True), (0, False)])
def test_anonymous_service_replay_admission_worker_wire_and_settlement(kind, active_limit, alternate):
    async def scenario():
        wire = []
        async def serve(reader, writer):
            try:
                wire.append(await reader.readuntil(b"\r\n\r\n"))
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server:
            origin = f"http://fixture.test:{server.sockets[0].getsockname()[1]}"
            registered = ("fixture.test" if kind == "device" else "https://fixture.test/app") if alternate else origin
            conn = Connection(kind=kind, origin=origin, registered_origin=registered,
                              active_limit=active_limit)
            result = await execute(conn)
            if active_limit == 0 and alternate:
                assert result["error"] == "budget_insufficient_for_action:active_actions", result
                assert conn.run["status"] == "active"
                assert wire == []
                assert conn.run["budget_used_json"].get("active_actions", 0) == 0
                # A zero action-specific ceiling must not lock the entire Hunt:
                # a read on its registered service still admits normally.
                fn = admission(conn)
                fn.__globals__["require_device_admission"] = noop
                life = Lifecycle("http.request")
                life.specification = CAPABILITY_REGISTRY.require("http.request")
                life.placement = life.specification.hunt_executor
                next_action = await fn(str(HUNT), "http.request", SimpleNamespace(
                    input={"method": "GET", "path": "/"}, idempotency_key="after-unaffordable-replay"), life)
                assert conn.actions[next_action["action_id"]]["status"] == "reserved"
            else:
                assert result["status"] == "success", result
                assert len(wire) == 1 and wire[0].startswith(b"GET /probe ")
                expected = int(alternate)
                assert conn.run["budget_used_json"].get("active_actions", 0) == expected
                assert conn.approvals == (["active", "dispatch"] if alternate else ["dispatch"])
                settled = next(iter(conn.store.rows.values()))
                assert settled.record.requested.get("active_actions", 0) == settled.record.actual.get("active_actions", 0) == expected
                assert settled.record.status == "committed"
                summary = next(iter(conn.actions.values()))["result_summary"]
                assert summary["budget_accounting"]["actual"] == dict(settled.record.actual)
                # The second action is stopped by the existing operator budget,
                # not by a new port/scheme permission, and sends no extra traffic.
                if alternate:
                    again = await execute(conn)
                    assert again["error"] == "budget_exhausted:active_actions", again
                    assert len(wire) == 1
    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["web", "api", "network", "device"])
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_active_replay_uses_existing_authority_and_exact_request_accounting(kind, method):
    async def scenario():
        wire = []
        async def serve(reader, writer):
            try:
                wire.append(await reader.readuntil(b"\r\n\r\n"))
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server:
            origin = f"http://fixture.test:{server.sockets[0].getsockname()[1]}"
            conn = Connection(kind=kind, origin=origin, registered_origin=origin,
                              active_limit=2, method=method)
            result = await execute(conn, "collections.replay_active")
            assert result["status"] == "success", result
            assert result["safe_methods_only"] is False
            assert all(o.get("response_body_sha256") is None for o in result["observations"])
            assert len(conn.raw_archive) == 1
            assert conn.raw_archive[0]["method"] == method
            assert conn.raw_archive[0]["fidelity"] == "exact_replay_plan_bounded_response"
            assert wire == [wire[0]] and wire[0].startswith(f"{method} /probe ".encode())
            settled = next(iter(conn.store.rows.values())).record
            assert settled.terminal and settled.requested["http_requests"] == 1
            assert settled.actual["http_requests"] == settled.actual["state_changing_requests"] == 1
            assert settled.actual["active_actions"] == 1
            assert conn.run["budget_used_json"]["state_changing_requests"] == 1
    asyncio.run(scenario())


@pytest.mark.parametrize("field", ["active_testing", "allow_state_changing_http"])
def test_active_replay_without_saved_grant_never_reaches_worker(field):
    async def scenario():
        from fastapi import HTTPException
        conn = Connection(kind="device", origin="http://fixture.test:7345", registered_origin="fixture.test",
                          active_limit=1, method="PUT")
        conn.run["policy_json"][field] = False
        with pytest.raises(HTTPException, match="state-changing HTTP permission"):
            await execute(conn, "collections.replay_active")
        assert not conn.actions and not conn.store.rows
    asyncio.run(scenario())
