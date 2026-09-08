"""Exercise real admission control up to dispatch, with an isolated store.

Compile the unchanged admission prefix of the production lifecycle. The queue,
worker and database driver are not under test: the fake transaction serializes
admissions and retains the production UPDATE/INSERT values. No source-string
assertion stands in for executing the verification gate or idempotency branch.
"""
from __future__ import annotations

import ast
import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Mapping
import uuid

from fastapi import HTTPException
import pytest


ROOT = Path(__file__).resolve().parents[1]
HUNT, TARGET = uuid.UUID(int=1), uuid.UUID(int=2)


class Reservation:
    def __init__(self, amounts):
        self.requested = dict(amounts)
        self.status = "requested"

    def reserve_against(self, *, limits, consumed, lease_seconds):
        used = dict(consumed)
        for key, amount in self.requested.items():
            assert used.get(key, 0) + amount <= limits[key]
            used[key] = used.get(key, 0) + amount
        self.status = "reserved"
        return self, used


class ReservationStore:
    async def create_requested(self, conn, *, record, **kwargs):
        return SimpleNamespace(record=record)

    async def persist_transition(self, conn, *, current, **kwargs):
        return SimpleNamespace(record=current)


class AdmissionStore:
    def __init__(self, maximum=1, used=0):
        self.lock = asyncio.Lock()
        self.actions = {}
        self.calls = []
        self.run = {
            "id": HUNT, "target_id": TARGET, "device_target_id": None,
            "target_kind": "web", "status": "active",
            "context_pack": {"target": {"url": "https://fixture.example.test"}},
            "policy_json": {"scope_receipt_id": "scope"},
            "budget_used_json": {"verifications": used},
            "budget_json": {"max_verifications": maximum, "max_capability_calls": 100,
                            "max_active_actions": 100, "max_http_requests": 1000,
                            "max_duration_seconds": 1000},
        }

    @asynccontextmanager
    async def acquire(self):
        yield self

    @asynccontextmanager
    async def transaction(self):
        async with self.lock:
            before = deepcopy((self.run, self.actions))
            try:
                yield self
            except BaseException:
                self.run, self.actions = before
                raise

    async def fetchrow(self, sql, *args):
        self.calls.append(sql)
        if "FROM hunt_actions" in sql:
            return self.actions.get(str(args[0]))
        if "FROM targets" in sql:
            return {"url": "https://fixture.example.test", "is_active": True}
        if "FROM investigation_candidates" in sql:
            return {"status": "open", "family": "bola"}
        raise AssertionError(sql)

    async def execute(self, sql, *args):
        self.calls.append(sql)
        if sql.startswith("UPDATE hunt_runs SET budget_used_json"):
            self.run["budget_used_json"] = json.loads(args[1])
        elif "INSERT INTO hunt_actions" in sql:
            aid, hid, name, status, inputs, result = args
            assert hid == HUNT and str(aid) not in self.actions
            self.actions[str(aid)] = {"capability_name": name, "status": status,
                "input_summary": json.loads(inputs), "result_summary": json.loads(result),
                "receipt_id": None}
        else:
            raise AssertionError(sql)
        return "UPDATE 1"


class Lifecycle:
    def __init__(self, name):
        executor = "inline" if name == "candidate.verify" else "worker_http"
        self.placement = executor
        self.specification = SimpleNamespace(hunt_executor=executor, requires_active_approval=True,
            risk_tier="active", output_schema="fixture", budget_cost={"http_requests": 4, "tool_wall_seconds": 60})
        self.states = []
        self.replayed = False

    def advance(self, state):
        self.states.append(state)

    def mark_replayed(self):
        self.replayed = True


def admission(store):
    source = ROOT / "api/hunt/interaction_router.py"
    module = ast.parse(source.read_text(), filename=str(source))
    function = next(n for n in module.body if isinstance(n, ast.AsyncFunctionDef)
                    and n.name == "_execute_hunt_capability_lifecycle")
    # The first top-level transaction finishes admission, before any dispatch.
    stop = next(i for i, node in enumerate(function.body) if isinstance(node, ast.AsyncWith))
    function.body = function.body[:stop + 1] + ast.parse("return {'action_id': str(action_id)}").body
    ledger = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == "_hunt_ledger_limits")
    selected = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
                               ledger, function], type_ignores=[])
    ast.fix_missing_locations(selected)

    async def run_or_404(conn, hunt_id, *, for_update):
        assert for_update and uuid.UUID(str(hunt_id)) == HUNT and store.lock.locked()
        return deepcopy(store.run)

    async def approval(*args, **kwargs):
        return {"scope_receipt_id": "scope"}

    context = {"__builtins__": __builtins__, "os": os, "uuid": uuid, "json": json,
        "hashlib": hashlib, "Mapping": Mapping, "HTTPException": HTTPException,
        "_pool": lambda: store, "_hunt_run_or_404": run_or_404,
        "_hunt_json": lambda value, default: value if isinstance(value, type(default)) else default,
        "_hunt_public": lambda *args, **kwargs: {"capabilities": [
            {"name": n} for n in ("candidate.verify", "authz.verify", "http.request")]},
        "_validate_approval_receipt_for_action": approval,
        "_uuid_or_400": lambda value, label: uuid.UUID(value),
        "agent_tools": SimpleNamespace(normalize_principal_slot=lambda _: "anonymous", IDENTITY_HEADERS=set()),
        "family_proof": SimpleNamespace(canonical_family=lambda family: family),
        "web_candidate_budget": lambda family: {}, "_AGENT_MUTATING_VERIFY_FAMILIES": frozenset(),
        "PostgresBudgetReservationStore": ReservationStore,
        "DurableBudgetReservation": SimpleNamespace(request=lambda **kwargs: Reservation(kwargs["amounts"])),
        "hunt_capability_action_digest": lambda **kwargs: "a" * 64,
        "hunt_capability_lease_seconds": lambda _: 120,
        "_hunt_redacted_capability_input": lambda name, values: dict(values),
        "HuntActionResult": lambda **kwargs: SimpleNamespace(public_dict=lambda: dict(kwargs)),
    }
    exec(compile(selected, str(source), "exec"), context)
    return context[function.name]


async def call(store, name="authz.verify", key="attempt-0001", values=None):
    lifecycle = Lifecycle(name)
    inputs = values if values is not None else (
        {"candidate_id": str(uuid.UUID(int=3))} if name == "candidate.verify" else {})
    result = await admission(store)(str(HUNT), name,
        SimpleNamespace(input=inputs, idempotency_key=key), lifecycle)
    return result, lifecycle


@pytest.mark.parametrize("maximum,used", [(0, 0), (1, 1), (2, 3)])
def test_authz_exhaustion_is_rejected_before_action_admission(maximum, used):
    store = AdmissionStore(maximum, used)
    with pytest.raises(HTTPException, match="verification budget exhausted") as error:
        asyncio.run(call(store))
    assert error.value.status_code == 409
    assert store.run["budget_used_json"] == {"verifications": used} and not store.actions


def test_authz_last_slot_is_counted_and_idempotent_replay_is_free():
    async def scenario():
        store = AdmissionStore()
        first, _ = await call(store)
        repeated, lifecycle = await call(store)
        assert lifecycle.replayed and repeated["idempotent_replay"]
        assert first["action_id"] == repeated["action_id"]
        assert store.run["budget_used_json"]["verifications"] == 1 and len(store.actions) == 1
        with pytest.raises(HTTPException, match="verification budget exhausted"):
            await call(store, key="attempt-0002")
    asyncio.run(scenario())


@pytest.mark.parametrize("names", [("authz.verify", "candidate.verify"), ("candidate.verify", "authz.verify")])
def test_both_verifiers_share_the_existing_admission_counter(names):
    async def scenario():
        store = AdmissionStore()
        await call(store, name=names[0])
        with pytest.raises(HTTPException, match="verification budget exhausted"):
            await call(store, name=names[1], key="attempt-0002")
        assert store.run["budget_used_json"]["verifications"] == 1
    asyncio.run(scenario())


def test_new_retry_uses_a_new_slot_not_an_extra_charge_for_the_old_key():
    async def scenario():
        store = AdmissionStore(maximum=2)
        await call(store)
        await call(store, key="attempt-0002")
        await call(store)
        assert store.run["budget_used_json"]["verifications"] == 2 and len(store.actions) == 2
    asyncio.run(scenario())


def test_non_verification_capability_is_not_charged_to_verifications():
    store = AdmissionStore(maximum=0)
    asyncio.run(call(store, name="http.request"))
    assert store.run["budget_used_json"]["verifications"] == 0 and len(store.actions) == 1


def test_changed_input_cannot_reuse_idempotency_or_consume_a_second_slot():
    async def scenario():
        store = AdmissionStore(maximum=2)
        await call(store)
        with pytest.raises(HTTPException, match="idempotency key"):
            await call(store, values={"routes": ["/different"]})
        assert store.run["budget_used_json"]["verifications"] == 1 and len(store.actions) == 1
    asyncio.run(scenario())


def test_serialized_concurrent_admissions_cannot_both_spend_the_last_slot():
    async def scenario():
        store = AdmissionStore()
        outcomes = await asyncio.gather(call(store), call(store, key="attempt-0002"), return_exceptions=True)
        assert sum(isinstance(item, HTTPException) for item in outcomes) == 1
        assert store.run["budget_used_json"]["verifications"] == 1 and len(store.actions) == 1
    asyncio.run(scenario())
