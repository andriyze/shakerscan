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
from hunt.action_replay import execution_started_from_budget, replay_observations
from hunt.candidate_verification_preflight import (
    CandidateVerificationRefused, web_candidate_preflight,
)
from hunt.device_traffic import reserve_device_traffic
from hunt.host_accounting import distinct_host_charge
from runtime.hunt_http_contract import require_http_request_authority, redact_http_request_body
from runtime.credential_refs import (
    CredentialReferenceError, select_hunt_immediate_principal_reference,
)
from hunt.credential_uses import (
    HuntCredentialRefusal, admit_action_credentials, record_credential_uses,
)


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
        self.candidate = {"status": "new", "family": "bola",
                          "canonical_locus": {"method": "GET", "route": "/api/orders/{id}"}}
        self.lock = asyncio.Lock()
        self.actions = {}
        self.calls = []
        # Fixture: profile id -> current version of each credential attached to TARGET (an
        # active profile with an active binding). None attaches every selected reference.
        self.attached = None
        self.credential_uses = []
        self.run = {
            "id": HUNT, "target_id": TARGET, "device_target_id": None,
            "target_kind": "web", "status": "active",
            "context_pack": {"target": {"url": "https://fixture.example.test"}},
            "policy_json": {"scope_receipt_id": "scope", "approval_receipt_id": "approval"},
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
            return dict(self.candidate)
        raise AssertionError(sql)

    async def fetch(self, sql, *args):
        self.calls.append(sql)
        assert "FROM credential_profiles p" in sql and "b.binding_id=$2::text" in sql, sql
        assert args[1] == str(TARGET)
        attached = self.attached if self.attached is not None else {
            ref["profile_id"]: ref["profile_version"]
            for ref in self.run["context_pack"].get("credential_refs") or []
        }
        return [{"id": profile_id, "current_version": attached[str(profile_id)]}
                for profile_id in args[0] if str(profile_id) in attached]

    async def execute(self, sql, *args):
        self.calls.append(sql)
        if "INSERT INTO hunt_credential_uses" in sql:
            self.credential_uses.append(args)
            return "INSERT 0 1"
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
        executor = ("inline" if name == "candidate.verify" else
                    "worker_scanner" if name == "xss.verify" else "worker_http")
        self.placement = executor
        self.specification = SimpleNamespace(hunt_executor=executor, requires_active_approval=True,
            risk_tier="active", output_schema="fixture", budget_cost={"http_requests": 4, "tool_wall_seconds": 60})
        self.states = []
        self.replayed = False

    def advance(self, state):
        self.states.append(state)

    def mark_replayed(self):
        self.replayed = True


def admission(store, **overrides):
    source = ROOT / "api/hunt/interaction_router.py"
    module = ast.parse(source.read_text(), filename=str(source))
    function = next(n for n in module.body if isinstance(n, ast.AsyncFunctionDef)
                    and n.name == "_execute_hunt_capability_lifecycle")
    # The admission loop (its transaction, and the refusal settlement after it) finishes
    # admission, before any dispatch.
    stop = next(i for i, node in enumerate(function.body) if isinstance(node, (ast.AsyncWith, ast.For)))
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
        "CredentialReferenceError": CredentialReferenceError,
        "select_hunt_immediate_principal_reference": select_hunt_immediate_principal_reference,
        "family_proof": SimpleNamespace(canonical_family=lambda family: family),
        "web_candidate_budget": lambda family: {}, "_AGENT_MUTATING_VERIFY_FAMILIES": frozenset(),
        "PostgresBudgetReservationStore": ReservationStore,
        "reserve_device_traffic": reserve_device_traffic,
        "require_http_request_authority": require_http_request_authority,
        "DurableBudgetReservation": SimpleNamespace(request=lambda **kwargs: Reservation(kwargs["amounts"])),
        "hunt_capability_action_digest": lambda **kwargs: "a" * 64,
        "hunt_capability_lease_seconds": lambda _: 120,
        "_hunt_redacted_capability_input": lambda name, values: (
            redact_http_request_body(values) if name == "http.request" else dict(values)),
        "HuntActionResult": lambda **kwargs: SimpleNamespace(public_dict=lambda: dict(kwargs)),
        "replay_observations": replay_observations,
        "execution_started_from_budget": execution_started_from_budget,
        "distinct_host_charge": distinct_host_charge,
        "web_candidate_preflight": web_candidate_preflight,
        "CandidateVerificationRefused": CandidateVerificationRefused,
        "admit_action_credentials": admit_action_credentials,
        "HuntCredentialRefusal": HuntCredentialRefusal,
        "record_credential_uses": record_credential_uses,
    }
    from api.hunt import interaction_router as real_router

    async def settle_refusal(*_args, refusal, **_kwargs):
        # Labelled double: the refusal's own record/park transaction is covered by
        # tests/test_hunt_permission_requests_postgres.py; here the answer is what matters.
        raise refusal

    for helper in (
        "HuntRefusal", "from_credential_refusal", "capability_refusal", "http_authority_refusal",
        "replay_authority_refusal", "destination_refusal", "approval_required_refusal",
        "preflight_reason_code", "budget_refusal", "verification_budget_refusal",
        "MAX_ADMISSION_ATTEMPTS", "record_grant_use", "_resume_parked_action", "granted_destination",
        "Any", "parked_outcome", "close_parked_action", "permission_required",
    ):
        context.setdefault(helper, getattr(real_router, helper))
    context.setdefault("settle_refusal", settle_refusal)
    context.update(overrides)
    exec(compile(selected, str(source), "exec"), context)
    return context[function.name]


async def call(store, name="authz.verify", key="attempt-0001", values=None, **overrides):
    lifecycle = Lifecycle(name)
    inputs = values if values is not None else (
        {"candidate_id": str(uuid.UUID(int=3))} if name == "candidate.verify" else
        {"method": "GET", "path": "/"} if name == "http.request" else {})
    result = await admission(store, **overrides)(str(HUNT), name,
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


def test_header_principals_require_two_admitted_authz_profiles_before_reservation():
    store = AdmissionStore()
    refs = [
        {"source": "credential_profiles", "profile_id": str(uuid.UUID(int=index)),
         "principal_slot": slot, "profile_version": 1,
         "auth_kind": "authorization_header",
         "allowed_capabilities": ["authz.verify"]}
        for index, slot in ((11, "primary"), (12, "secondary"))
    ]
    store.run["context_pack"]["credential_refs"] = refs
    values = {"routes": ["/api/orders"], "primary_principal": "primary",
              "secondary_principal": "secondary"}
    asyncio.run(call(store, values=values))
    assert store.run["budget_used_json"]["verifications"] == 1
    assert len(store.actions) == 1

    blocked = AdmissionStore()
    blocked.run["context_pack"]["credential_refs"] = deepcopy(refs)
    blocked.run["context_pack"]["credential_refs"][1]["allowed_capabilities"] = ["http.request"]
    with pytest.raises(HTTPException, match="usable managed profile") as error:
        asyncio.run(call(blocked, values=values))
    assert error.value.status_code == 403
    assert blocked.run["budget_used_json"]["verifications"] == 0
    assert not blocked.actions


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


def test_scanner_capability_rejects_a_principal_it_cannot_apply():
    """Hunt scanner tools run without the managed principal. Accepting as_principal and
    running anonymously recorded an unauthenticated attempt as if it used that identity."""
    from agent_tools import normalize_principal_slot

    store = AdmissionStore()
    overrides = {
        "agent_tools": SimpleNamespace(
            normalize_principal_slot=normalize_principal_slot, IDENTITY_HEADERS=set(),
            canonical_hunt_scanner_budget=lambda _name: {"http_requests": 4, "tool_wall_seconds": 60},
        ),
        "_hunt_public": lambda *args, **kwargs: {"capabilities": [{"name": "xss.verify"}]},
    }
    with pytest.raises(HTTPException, match="cannot apply as_principal") as error:
        asyncio.run(call(
            store, name="xss.verify",
            values={"path": "/search?q=1", "as_principal": "primary"}, **overrides,
        ))
    assert error.value.status_code == 422
    assert not store.actions


@pytest.mark.parametrize("candidate,detail", [
    # sqli canonicalizes to injection, which the family-proof bridge cannot re-execute.
    ({"family": "sqli", "canonical_locus": {"method": "GET", "route": "/search"}},
     "verification bridge supports"),
    ({"family": "data_exposure", "canonical_locus": {"method": "GET"}},
     "verification_route_unresolved"),
    ({"family": "data_exposure", "canonical_locus": {"method": "GET", "url": "https://h.test/"}},
     "verification_route_unresolved"),
    ({"family": "mass_assignment", "canonical_locus": {"method": "PUT", "route": "/api/users"}},
     "explicitly evidenced POST"),
])
def test_candidate_refusals_decided_by_the_candidate_cost_nothing(candidate, detail):
    store = AdmissionStore()
    store.candidate = {"status": "new", **candidate}
    with pytest.raises(HTTPException, match=detail) as error:
        asyncio.run(call(store, name="candidate.verify"))
    assert error.value.status_code == 422
    # No verification counted, no action recorded, nothing reserved: zero charge.
    assert store.run["budget_used_json"] == {"verifications": 0}
    assert not store.actions
    assert not any("INSERT INTO hunt_actions" in sql for sql in store.calls)


def test_contract_path_locus_is_admitted_for_verification():
    store = AdmissionStore()
    store.candidate = {"status": "new", "family": "data_exposure",
                       "canonical_locus": {"method": "GET", "path": "/ftp/acquisitions.md"}}
    asyncio.run(call(store, name="candidate.verify"))
    assert store.run["budget_used_json"]["verifications"] == 1 and len(store.actions) == 1

