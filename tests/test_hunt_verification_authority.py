"""Hunt candidate verification runs under the Hunt's authority and refusals charge nothing.

Regressions for the Enterprise soak of 2026-10-07 (main 96224a9d):

* D1: every ``candidate.verify`` and ``POST /hunts/{id}/candidates/{cid}/verify`` answered
  400 ``execution_feature_disabled`` (Hunts 4bab21a8, 956315ab, 8f1f3528, eea3bdab). Enterprise
  sets ``AI_OPS_ROUTER_EXECUTE_ENABLED=false`` while autonomous Hunt is off, and the web verifier
  checked that autonomous-execution switch even when a Hunt's own operator or planner asked.
* D2: each refused verification was charged 1 agent action, 1 active action, 24 HTTP requests,
  180 wall seconds and a verification, although no request was sent.

The lifecycle test drives the production ``execute_hunt_capability`` for a web Hunt; only the
database, the reservation table and the receipt writer are in-memory doubles.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from copy import deepcopy
from types import SimpleNamespace

import pytest
from capabilities.inline import ControlPlaneExecutionAdapter
from fastapi import HTTPException
from hunt import interaction_router as router
from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from hunt.run_service import hunt_action_outcome_summary, public_hunt_action
from hunt.settlement import (
    capability_charge_basis,
    refund_verification,
    unstarted_refusal_charges,
)
from hunt.verification_refusal import VerificationRefused, refused_before_traffic
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import TargetBinding

from api import api as api_module

HUNT, TARGET = uuid.UUID(int=11), uuid.UUID(int=12)
CANDIDATE = uuid.UUID("7d2c5d0e-4b1a-4f6e-9a7c-3e2b1f0a9c11")
ACTION = uuid.UUID(int=15)
APPROVAL = str(uuid.UUID(int=14))
ORIGIN = "https://fixture.example.test"


# --- D1: the verifier gate -------------------------------------------------------------------

class VerifierPool:
    """The first queries of the web verifier: the candidate does not exist."""

    def __init__(self):
        self.queries = []

    @asynccontextmanager
    async def acquire(self):
        yield self

    async def fetchval(self, query, *args):
        self.queries.append(query)
        if "pg_try_advisory_lock" in query:
            return True
        if "FROM investigation_candidates" in query:
            return True  # a web candidate, so the candidate verifier is used
        raise AssertionError(query)

    async def fetchrow(self, query, *args):
        self.queries.append(query)
        assert "FROM investigation_candidates" in query, query

    async def execute(self, query, *args):
        assert "pg_advisory_unlock" in query, query


@pytest.fixture
def router_switch_off(monkeypatch):
    monkeypatch.setenv("AI_OPS_ROUTER_EXECUTE_ENABLED", "false")
    pool = VerifierPool()
    monkeypatch.setattr(api_module, "db_pool", pool)
    return pool


def test_hunt_verification_does_not_depend_on_the_autonomous_execution_switch(router_switch_off):
    # The candidate is missing, so reaching the 404 proves the switch did not refuse first.
    with pytest.raises(HTTPException) as exc:
        asyncio.run(api_module._verify_suspected_finding_workflow(
            CANDIDATE, APPROVAL, created_by="hunt_v2:fixture", autonomous=False,
        ))
    assert exc.value.status_code == 404
    assert exc.value.detail == "Investigation candidate not found"


def test_a_hunt_verification_reaches_the_verifier_with_the_switch_off(router_switch_off, monkeypatch):
    # The Hunt's own path into the real api.py verifier, as candidate.verify and POST .../verify
    # take it. On the soak every call stopped here with 400 execution_feature_disabled.
    monkeypatch.setattr(
        router, "_verify_suspected_finding_workflow", api_module._verify_suspected_finding_workflow,
    )
    with pytest.raises(HTTPException) as exc:
        asyncio.run(router._execute_hunt_candidate_verification(
            run={"id": HUNT, "device_target_id": None}, context={},
            policy={"approval_receipt_id": APPROVAL}, candidate_uuid=CANDIDATE,
            action_id=ACTION,
        ))
    assert exc.value.detail != "execution_feature_disabled"
    assert (exc.value.status_code, exc.value.detail) == (404, "Investigation candidate not found")


@pytest.mark.parametrize("verifier", [
    "_verify_web_candidate_workflow_unlocked", "_verify_suspected_finding_workflow_unlocked",
])
def test_autonomous_verification_stays_gated_by_the_switch(router_switch_off, verifier):
    # The default is autonomous: router-driven verification keeps the global off switch.
    with pytest.raises(HTTPException) as exc:
        asyncio.run(getattr(api_module, verifier)(CANDIDATE, APPROVAL, created_by="agent"))
    assert (exc.value.status_code, exc.value.detail) == (400, "execution_feature_disabled")
    assert router_switch_off.queries == []


def test_the_hunt_asks_for_verification_under_its_own_authority(monkeypatch):
    calls = []

    async def verifier(*args, **kwargs):
        calls.append(kwargs)
        raise HTTPException(status_code=422, detail="verification_route_unresolved")

    monkeypatch.setattr(router, "_verify_suspected_finding_workflow", verifier)
    run = {"id": HUNT, "device_target_id": None}
    with pytest.raises(VerificationRefused) as exc:
        asyncio.run(router._execute_hunt_candidate_verification(
            run=run, context={}, policy={"approval_receipt_id": APPROVAL}, candidate_uuid=CANDIDATE,
            action_id=ACTION,
        ))
    assert calls == [{"created_by": f"hunt_v2:{HUNT}", "autonomous": False}]
    # The caller still gets the verifier's own answer.
    assert (exc.value.status_code, exc.value.detail) == (422, "verification_route_unresolved")


def test_refusal_marker_keeps_the_answer_and_leaves_other_errors_alone():
    with pytest.raises(VerificationRefused) as refused, refused_before_traffic():
        raise HTTPException(status_code=409, detail="Candidate is already verified")
    assert isinstance(refused.value, HTTPException)
    assert (refused.value.status_code, refused.value.detail) == (409, "Candidate is already verified")
    with pytest.raises(RuntimeError), refused_before_traffic():
        raise RuntimeError("verifier fault after dispatch")


# --- D2: the adapter and settlement -----------------------------------------------------------

REQUESTED = {"agent_actions": 1, "active_actions": 1, "http_requests": 24, "tool_wall_seconds": 180}


def _execute(adapter):
    specification = CAPABILITY_REGISTRY.require("candidate.verify")
    return asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=specification,
            target=TargetBinding(target_id="target-1", target_kind="web",
                                 canonical_host="fixture.example.test",
                                 allowed_origins=(ORIGIN,), scope_receipt_id="scope"),
            requested_budget=REQUESTED,
        ),
        adapter,
        heartbeat=_beat,
        cancelled=lambda: False,
    ))


async def _beat():
    return None


def _verify_adapter(operation):
    return ControlPlaneExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("candidate.verify"),
        operation=operation, requested_budget=REQUESTED, redacted_execution={},
        blocked_exceptions=(HTTPException,), conservative_full_budget=True,
        unstarted_exceptions=(VerificationRefused,), measured_wall=True,
    )


def test_a_verifier_refusal_before_traffic_reports_no_execution():
    async def operation():
        raise VerificationRefused(status_code=400, detail="verification_route_unresolved")

    result = _execute(_verify_adapter(operation))
    assert result.status == "blocked"
    assert result.execution_started is False
    # Released explicitly (an omitted dimension would keep its hold); only the call is charged.
    assert result.actual_budget.get("active_actions", 0) == 0
    assert result.actual_budget.get("http_requests", 0) == 0


def test_an_uncertain_verifier_block_still_charges_the_full_hold():
    async def operation():
        raise HTTPException(status_code=502, detail="verifier stopped after uncertain traffic")

    result = _execute(_verify_adapter(operation))
    assert result.status == "blocked"
    assert result.execution_started is True
    # The traffic hold stays charged; wall time settles to what elapsed (D26).
    assert result.actual_budget == {**REQUESTED, "tool_wall_seconds": 1}


def test_settlement_helpers_release_everything_for_an_unstarted_refusal():
    assert unstarted_refusal_charges({**REQUESTED, "browser_actions": 0}) == {
        key: 0 for key in REQUESTED
    }
    used = {"verifications": 3, "http_requests": 248}
    refund_verification(used)
    assert used == {"verifications": 2, "http_requests": 248}
    refund_verification({"verifications": 0})  # never negative
    assert capability_charge_basis("candidate.verify", refused_before_traffic=True) == "not_charged"
    assert capability_charge_basis("candidate.verify", refused_before_traffic=False) == (
        "conservative_full_reservation"
    )
    assert capability_charge_basis("http.request", refused_before_traffic=False) == (
        "capability_reported_settlement"
    )


# --- D2 end to end: execute_hunt_capability on a web Hunt --------------------------------------

class Reservations:
    """In-memory budget_reservations keeping the production records and transitions."""

    def __init__(self):
        self.rows = {}

    def _store(self, record, previous=None, **extra):
        stored = SimpleNamespace(
            record=record,
            action_digest=getattr(previous, "action_digest", extra.get("action_digest")),
            action_id=getattr(previous, "action_id", extra.get("action_id")),
            receipt=extra.get("receipt"),
            ledger_after_settlement=extra.get("ledger_after_settlement"),
        )
        self.rows[record.reservation_id] = stored
        return stored

    async def create_requested(self, conn, *, action_id, action_digest, record):
        return self._store(record, action_id=action_id, action_digest=action_digest)

    async def persist_transition(self, conn, *, previous, current, ledger_after_hold=None):
        return self._store(current, previous)

    async def load(self, conn, reservation_id, *, for_update=False):
        return self.rows.get(str(reservation_id))

    async def persist_terminal(self, conn, *, previous, terminal, ledger_after_settlement, receipt):
        return self._store(terminal, previous, receipt=receipt,
                           ledger_after_settlement=dict(ledger_after_settlement))


class HuntDatabase:
    def __init__(self):
        self.run = {
            "id": HUNT, "target_id": TARGET, "device_target_id": None, "target_kind": "web",
            "status": "active", "completed_at": None,
            "context_pack": {"target": {"url": ORIGIN}},
            "policy_json": {
                "active_testing": True, "scope_receipt_id": "scope",
                "approval_receipt_id": APPROVAL, "allowed_capabilities": ["candidate.verify"],
            },
            "budget_json": {
                "max_verifications": 5, "max_capability_calls": 100, "max_active_actions": 20,
                "max_http_requests": 1000, "max_duration_seconds": 3600,
                "max_browser_actions": 100, "max_state_changing_requests": 0,
            },
            "budget_used_json": {"agent_actions": 4, "http_requests": 224, "tool_wall_seconds": 64},
        }
        self.actions = {}

    @asynccontextmanager
    async def acquire(self):
        yield self

    @asynccontextmanager
    async def transaction(self):
        yield self

    # The candidate passes the admission preflight (supported family, concrete route), so the
    # verifier's own refusal below comes after it.
    candidate = {
        "id": CANDIDATE, "target_id": TARGET, "status": "new", "family": "access_control",
        "title": "Admin export reachable by a user", "claimed_severity": "high",
        "verifier_contract_id": None, "verification_context": {},
        "canonical_locus": {"route": "/api/admin/export", "method": "GET"},
    }

    async def fetchval(self, query, *args):
        if "pg_try_advisory_lock" in query:
            return True
        if "FROM investigation_candidates" in query:
            return True  # a web candidate
        assert query.startswith("SELECT status FROM hunt_runs"), query
        return self.run["status"]

    async def fetch(self, query, *args):
        # No operator-approved invariant contract exists for the route.
        assert "FROM target_invariant_contracts" in query, query
        return []

    async def fetchrow(self, query, *args):
        if "FROM hunt_actions" in query:
            return self.actions.get(str(args[0]))
        if "FROM targets" in query:
            return {"id": TARGET, "url": ORIGIN, "is_active": True}
        if "FROM investigation_candidates" in query:
            return dict(self.candidate)
        raise AssertionError(query)

    async def execute(self, query, *args):
        if "pg_advisory_unlock" in query:
            return "SELECT 1"
        if query.startswith("UPDATE hunt_runs SET budget_used_json"):
            self.run["budget_used_json"] = json.loads(args[1])
        elif "INSERT INTO hunt_actions" in query:
            action_id, _hunt, name, status, inputs, summary = args
            self.actions[str(action_id)] = {
                "id": action_id, "capability_name": name, "status": status,
                "input_summary": json.loads(inputs), "result_summary": json.loads(summary),
                "receipt_id": None,
            }
        elif "SET status='running'" in query:
            self.actions[str(args[0])]["status"] = "running"
        elif "UPDATE hunt_actions" in query and "result_summary=$3" in query:
            action = self.actions[str(args[0])]
            action.update(status=args[1], result_summary=json.loads(args[2]), receipt_id=args[3])
        else:
            raise AssertionError(query)
        return "UPDATE 1"


@pytest.fixture
def web_hunt(monkeypatch):
    database, reservations = HuntDatabase(), Reservations()

    async def run_or_404(conn, hunt_id, for_update=False):
        assert uuid.UUID(str(hunt_id)) == HUNT
        return deepcopy(database.run)

    async def approval(*args, **kwargs):
        return {"scope_receipt_id": "scope"}

    async def record_receipt(conn, request):
        return {"tool_receipt": {"id": str(uuid.uuid4())}}

    monkeypatch.setattr(router, "_pool", lambda: database)
    monkeypatch.setattr(router, "_hunt_run_or_404", run_or_404)
    monkeypatch.setattr(router, "_validate_approval_receipt_for_action", approval)
    monkeypatch.setattr(router, "PostgresBudgetReservationStore", lambda: reservations)
    monkeypatch.setattr(router, "_arsenal_routes", SimpleNamespace(
        _record_tool_receipt=record_receipt, _redact_agent_payload=lambda value: value,
        ToolReceiptRequest=lambda **fields: SimpleNamespace(**fields),
    ))
    return database, reservations


def _verify(verifier, monkeypatch):
    monkeypatch.setattr(router, "_verify_suspected_finding_workflow", verifier)
    request = router.HuntCapabilityRequest(
        idempotency_key="verify-fixture-0001", input={"candidate_id": str(CANDIDATE)},
    )
    return asyncio.run(router.execute_hunt_capability(str(HUNT), "candidate.verify", request))


REFUSAL = (
    "access_control verification requires an operator-approved invariant contract "
    "for this route (finding stays suspected)"
)


def test_a_verification_refused_before_traffic_is_charged_nothing(web_hunt, monkeypatch):
    """The refusal the admission preflight cannot make: it needs the verifier's own lookups.

    The admission preflight (candidate_verification_preflight) refuses what the stored candidate
    alone decides: unsupported family, no concrete route, a mass-assignment claim without POST.
    This candidate passes it. The real api.py verifier then finds no operator-approved invariant
    contract for the route and refuses before dispatching anything; the same holds for a BOLA
    candidate without two principals' distinct object references and for a target-bound
    approval receipt that no longer validates. None of those sent a request, so none is charged.
    """
    database, reservations = web_hunt
    before = dict(database.run["budget_used_json"])
    monkeypatch.setattr(api_module, "db_pool", database)
    monkeypatch.setenv("AI_OPS_ROUTER_EXECUTE_ENABLED", "false")

    with pytest.raises(HTTPException) as exc:
        _verify(api_module._verify_suspected_finding_workflow, monkeypatch)
    assert (exc.value.status_code, exc.value.detail) == (422, REFUSAL)

    used = database.run["budget_used_json"]
    assert {key: used.get(key, 0) for key in before} == before
    assert used.get("verifications", 0) == 0
    assert used.get("active_actions", 0) == 0
    (stored,) = reservations.rows.values()
    assert stored.record.status == "failed"
    assert not any(stored.record.actual.values())
    assert stored.record.execution_uncertain is False

    (action,) = database.actions.values()
    assert action["status"] == "blocked"
    public = public_hunt_action(action)["result"]
    assert public["budget_accounting"]["basis"] == "refused_before_execution"
    assert public["budget_accounting"]["charge_basis"] == "not_charged"
    assert public["refusal"]["stage"] == "verification"
    assert public["refusal"]["reason"] == REFUSAL
    assert public["execution_started"] is False
    # It never ran, so the outcome counts it as rejected, not executed.
    summary = hunt_action_outcome_summary([public_hunt_action(action)])
    assert (summary["executed_calls"], summary["rejected_calls"]) == (0, 1)


def test_a_verification_that_ran_keeps_the_conservative_charge(web_hunt, monkeypatch):
    database, _reservations = web_hunt

    async def proving_verifier(*args, **kwargs):
        return {"verified": False, "family_proof": {"verdict": "refuted"}}

    result = _verify(proving_verifier, monkeypatch)
    assert result["result"]["ok"] is True
    used = database.run["budget_used_json"]
    assert used["verifications"] == 1
    assert used["active_actions"] == 1
    assert used["http_requests"] == 224 + 24
    # D26: the 180 s reservation gated admission; the charge is the wall time that elapsed.
    assert used["tool_wall_seconds"] == 64 + 1
    (action,) = database.actions.values()
    accounting = public_hunt_action(action)["result"]["budget_accounting"]
    assert accounting["charge_basis"] == "conservative_full_reservation"


def test_a_credential_refusal_returned_by_the_dispatch_is_charged_nothing(web_hunt, monkeypatch):
    """D33: auth_bypass resolves its principals at dispatch, not in preflight. The verifier turns
    that HTTPException into a returned verdict, and the Hunt reported a successful verification
    charged 1 verification, 24 requests and 180 s, with the slot masked as ``***``."""
    from api.hunt.verification_credentials import HuntVerificationCredentialRefused
    from scanner.redaction import redact_sensitive

    database, reservations = web_hunt
    before = dict(database.run["budget_used_json"])
    refusal = HuntVerificationCredentialRefused(
        "credential_missing_for_slot", "Attach a credential for slot user1", slot="user1",
    )

    async def dispatch_refused_verifier(*args, **kwargs):
        # Labelled double: the verdict _verify_web_candidate_workflow_unlocked returns when
        # _arsenal_dispatch_workflow raised its 422 for this refusal before any traffic.
        return {"verified": False, "verified_finding_id": None, "error": {
            "error": "invalid_workflow", "violation": str(refusal), "target_traffic_sent": False,
            **refusal.public_detail(),
        }}

    with pytest.raises(HTTPException) as exc:
        _verify(dispatch_refused_verifier, monkeypatch)
    assert exc.value.status_code == 422
    assert exc.value.detail["reason_code"] == "credential_missing_for_slot"
    used = database.run["budget_used_json"]
    assert {key: used.get(key, 0) for key in before} == before
    assert used.get("verifications", 0) == 0 and used.get("active_actions", 0) == 0
    (stored,) = reservations.rows.values()
    assert not any(stored.record.actual.values())
    (action,) = database.actions.values()
    public = public_hunt_action(action)["result"]
    assert action["status"] == "blocked" and public["execution_started"] is False
    assert public["budget_accounting"]["charge_basis"] == "not_charged"
    summary = hunt_action_outcome_summary([public_hunt_action(action)])
    assert (summary["executed_calls"], summary["rejected_calls"]) == (0, 1)
    # The slot name survives the shared redactor.
    assert "user1" in redact_sensitive({"violation": str(refusal)}, redact_strings=True,
                                       scrub_text=True)["violation"]


def test_a_dispatch_refusal_after_a_create_surface_probe_keeps_the_charge(web_hunt, monkeypatch):
    database, _reservations = web_hunt

    async def probed_then_refused(*args, **kwargs):
        return {"verified": False, "error": {
            "error": "hunt_credential_refused", "reason_code": "credential_missing_for_slot",
            "target_traffic_sent": True,
        }}

    result = _verify(probed_then_refused, monkeypatch)
    assert result["result"]["ok"] is True
    assert database.run["budget_used_json"]["verifications"] == 1


@pytest.mark.parametrize("probe_requests,sent", [(0, False), (3, True)])
def test_the_workflow_dispatch_says_whether_a_credential_refusal_followed_traffic(
    monkeypatch, probe_requests, sent,
):
    """D33: the dispatch's refusal names its reason code and whether a create-surface probe ran."""
    from api.arsenal_routes import router as arsenal
    from api.hunt.verification_credentials import HuntVerificationCredentialRefused

    class Conn:
        async def fetchrow(self, query, *args):
            assert "FROM targets" in query
            return {"id": TARGET, "url": ORIGIN, "is_active": True, "discovery_source": "manual"}

    class Pool:
        @asynccontextmanager
        async def acquire(self):
            yield Conn()

    async def materialize(conn, url, target, params, hypothesis, approval):
        if probe_requests:  # labelled double for a create-surface probe that sent requests
            params["_server_materialization"] = {"request_count": probe_requests}

    async def resolve(conn, target, slots, **kwargs):
        raise HuntVerificationCredentialRefused(
            "credential_missing_for_slot", "Attach a credential for slot user1", slot="user1")

    monkeypatch.setattr(arsenal, "_pool_provider", lambda: Pool())
    monkeypatch.setitem(arsenal._deps, "_active_workflow_cancellations", lambda: {})
    monkeypatch.setitem(arsenal._deps, "_server_materialize_create_ma", lambda: materialize)
    monkeypatch.setitem(arsenal._deps, "_resolve_workflow_principal_contexts", lambda: resolve)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(arsenal._arsenal_dispatch_workflow({
            "target_id": str(TARGET), "workflow_id": str(uuid.uuid4()), "proof_family": "auth_bypass",
            "steps": [{"id": f"step{n}", "principal": "user1", "method": "GET", "path": "/admin"}
                      for n in range(2)],
        }, "approval"))
    assert exc.value.status_code == 422
    detail = exc.value.detail
    assert detail["error"] == "hunt_credential_refused"
    assert detail["reason_code"] == "credential_missing_for_slot" and detail["slot"] == "user1"
    assert detail["violation"] == "credential_missing_for_slot for slot user1"
    assert detail["target_traffic_sent"] is sent


# --- Network targets: the proof runs on the service the candidate names --------------------------
#
# A network target is registered as ``host://H``: it names a host, not an HTTP service. The web
# verifier built its proof workflow from that URL, so every data_exposure, auth_bypass or bola
# verification on a network Hunt failed with ``adapter_fault:ExperimentContractError`` before any
# request, and was charged as an uncertain run (24 requests, 180 s, a verification and an active
# action). The candidate names its service (``canonical_locus.origin``), a suspected finding its
# URL; the proof runs there, and what it proves is recorded on that service.

HOST = "198.51.100.10"
HOST_TARGET = f"host://{HOST}"
SERVICE = f"http://{HOST}:8000"
# Unit fixture: a synthetic provider-shaped secret (the same shape the workflow tests use), served
# by the loopback service below so the real family proof can verify the exposure.
EXPOSED_ENV = b"APP_ENV=production\nSTRIPE_SECRET_KEY=sk_live_acme4f8a2b3cQ7xR1nW9\n"


class StopAfterRouting(Exception):
    """Labelled double: ends the proof once the workflow runtime is handed its base URL."""


class NetworkHuntDatabase(HuntDatabase):
    """A network Hunt whose target row is ``host://<host>``.

    Besides the Hunt's own rows it keeps what the verifier and the promotion write (findings,
    verification records, candidate updates), so a test reads where a proven finding landed.
    """

    def __init__(self, locus, *, host=HOST, finding=None):
        super().__init__()
        self.target_url = f"host://{host}"
        self.run["target_kind"] = "network"
        self.run["context_pack"] = {
            "target": {"url": self.target_url, "kind": "network", "origins": []},
            "authorized_target_addresses": [host],
        }
        self.candidate = {
            "id": CANDIDATE, "target_id": TARGET, "status": "new", "family": "data_exposure",
            "title": "Unauthenticated .env disclosure", "claimed_severity": "critical",
            "verifier_contract_id": None, "verification_context": {}, "canonical_locus": locus,
        }
        # A suspected finding to verify instead of a candidate (POST /findings/{id}/verify).
        self.finding = finding
        self.candidate_updates = []
        self.findings_created = []
        self.verification_records = []
        self.findings_resolved = []
        self.hypothesis = None

    async def fetchval(self, query, *args):
        if "FROM investigation_candidates" in query:
            return self.finding is None
        if "INSERT INTO findings" in query:
            self.findings_created.append({"target_id": args[0], "url": args[7]})
            return uuid.uuid4()
        if "INSERT INTO finding_verifications" in query:
            self.verification_records.append({"target_url": args[8], "verdict": args[5]})
            return uuid.uuid4()
        return await super().fetchval(query, *args)

    async def fetch(self, query, *args):
        if "FROM target_endpoint" in query:
            return []  # no protected endpoints or deny expectations recorded
        if "FROM findings" in query:
            return []  # no earlier finding covers this vulnerability
        return await super().fetch(query, *args)

    async def fetchrow(self, query, *args):
        if "FROM targets" in query:
            return {"id": TARGET, "url": self.target_url, "is_active": True,
                    "discovery_source": "manual"}
        if "FROM hypotheses" in query:
            return self.hypothesis
        if "FROM research_decisions" in query or "FROM findings WHERE target_id" in query:
            return None
        if "FROM findings WHERE id" in query:
            return self.finding
        return await super().fetchrow(query, *args)

    async def execute(self, query, *args):
        if "UPDATE investigation_candidates" in query:
            self.candidate_updates.append((query, args))
            return "UPDATE 1"
        if query.lstrip().startswith("UPDATE findings SET status='resolved'"):
            self.findings_resolved.append(args[0])
            return "UPDATE 1"
        if any(marker in query for marker in (
            "INSERT INTO evidence_instances", "UPDATE evidence_instances", "UPDATE hypotheses",
            "UPDATE tool_receipts",
        )):
            return "UPDATE 1"
        return await super().execute(query, *args)


def _network_verification_doubles(monkeypatch, database, runtime=None):
    """Wire the real verifier and workflow dispatch to ``database``.

    Doubles (labelled): the database itself, the standing approval, the credential lookup (no
    credential attached: the proof reads as anonymous), the hypothesis upsert, and the receipt,
    evidence and command-result writers, which keep the request they were given. The workflow
    runtime, the family proof and the finding promotion are the real ones unless ``runtime``
    replaces the runtime.
    """
    import sys

    # The router module api.py dispatches through (its import layout decides which object).
    arsenal = sys.modules[api_module._arsenal_dispatch_workflow.__module__]
    recorded = {"receipts": [], "evidence": []}

    async def principals(conn, target, slots, **kwargs):
        return {} if kwargs.get("select_only") else {"anonymous": {}}

    async def approval(*args, **kwargs):
        return {"scope_receipt_id": "scope"}

    async def upsert(conn, request):
        hypothesis_id = uuid.uuid4()
        database.hypothesis = {
            "id": hypothesis_id, "target_id": TARGET, "source": request.source,
            "family": request.family, "title": request.title,
            "severity_guess": request.severity_guess, "description": None,
            "metadata_json": request.metadata_json,
        }
        return {"hypothesis": {"id": str(hypothesis_id)}}

    async def record_receipt(conn, request):
        recorded["receipts"].append(request)
        return {"tool_receipt": {"id": str(uuid.uuid4())}}

    async def record_evidence(conn, request):
        recorded["evidence"].append(request)
        return {"evidence_instance": {"id": str(uuid.uuid4())}}

    async def record_command(conn, **fields):
        return {"id": str(uuid.uuid4())}

    monkeypatch.setattr(api_module, "db_pool", database)
    monkeypatch.setenv("AI_OPS_ROUTER_EXECUTE_ENABLED", "false")
    monkeypatch.setattr(api_module, "_resolve_workflow_principal_contexts", principals)
    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", approval)
    monkeypatch.setattr(api_module, "_upsert_hypothesis", upsert)
    monkeypatch.setattr(arsenal, "_pool_provider", lambda: database)
    monkeypatch.setitem(arsenal._deps, "_active_workflow_cancellations", lambda: {})
    monkeypatch.setitem(arsenal._deps, "_resolve_workflow_principal_contexts", lambda: principals)
    monkeypatch.setitem(arsenal._deps, "_record_tool_receipt", lambda: record_receipt)
    monkeypatch.setitem(arsenal._deps, "_record_evidence_instance", lambda: record_evidence)
    monkeypatch.setitem(arsenal._deps, "_record_command_result", lambda: record_command)
    if runtime is not None:
        monkeypatch.setitem(arsenal._deps, "_execute_workflow_runtime", lambda: runtime)
    return recorded


def _verify_on_network_target(monkeypatch, locus, *, database=None, runtime=None):
    """The real execute_hunt_capability -> api.py verifier -> _arsenal_dispatch_workflow."""
    database = database or NetworkHuntDatabase(locus)

    async def run_or_404(conn, hunt_id, for_update=False):
        return deepcopy(database.run)

    async def settle_refusal(*_args, refusal, **_kwargs):
        # Labelled double: the refusal's own record transaction is covered by
        # tests/test_hunt_permission_requests_postgres.py; here the answer and the charge matter.
        raise refusal

    runtime_bases = []

    async def stop_at_runtime(base_url, payload, normalized, contexts, cancel):
        runtime_bases.append(base_url)
        raise StopAfterRouting(base_url)

    monkeypatch.setattr(router, "_pool", lambda: database)
    monkeypatch.setattr(router, "_hunt_run_or_404", run_or_404)
    monkeypatch.setattr(router, "settle_refusal", settle_refusal)
    monkeypatch.setattr(router, "_verify_suspected_finding_workflow", api_module._verify_suspected_finding_workflow)
    recorded = _network_verification_doubles(
        monkeypatch, database, runtime=stop_at_runtime if runtime is None else runtime,
    )
    before = dict(database.run["budget_used_json"])
    request = router.HuntCapabilityRequest(
        idempotency_key="verify-network-0001", input={"candidate_id": str(CANDIDATE)},
    )
    raised = None
    try:
        asyncio.run(router.execute_hunt_capability(str(HUNT), "candidate.verify", request))
    except HTTPException as exc:
        raised = exc
    used = database.run["budget_used_json"]
    delta = {key: used.get(key, 0) - before.get(key, 0)
             for key in set(used) | set(before) if used.get(key, 0) != before.get(key, 0)}
    return database, raised, delta, runtime_bases, recorded


def test_a_network_candidate_is_verified_on_the_service_it_names(web_hunt, monkeypatch):
    database, _raised, _delta, bases, _recorded = _verify_on_network_target(
        monkeypatch, {"path": "/.env", "method": "GET", "origin": SERVICE},
    )
    # Both proof runs would go to the evidenced service, never to the host:// placeholder.
    assert bases == [SERVICE]
    (action,) = database.actions.values()
    assert public_hunt_action(action)["result"].get("error") != "adapter_fault:ExperimentContractError"


@pytest.mark.parametrize("locus", [
    {"path": "/.env", "method": "GET"},  # names no service
    {"path": "/.env", "method": "GET", "origin": "http://198.51.100.11:8000"},  # another host
    {"path": "/.env", "method": "GET", "origin": f"ftp://{HOST}"},  # not HTTP
    {"path": "/.env", "method": "GET", "origin": SERVICE, "url": f"http://{HOST}:9000/.env"},
])
def test_a_network_candidate_without_one_named_service_is_refused_free(web_hunt, monkeypatch, locus):
    database, raised, delta, bases, _recorded = _verify_on_network_target(monkeypatch, locus)
    assert bases == [] and delta == {}
    assert raised is not None and raised.status_code == 422
    assert raised.detail["reason_code"] == "verification_service_unresolved"
    assert "origin" in raised.detail["message"]
    # Refused at admission: no reservation, no verification, no candidate state change.
    assert database.candidate_updates == []
    _old, reservations = web_hunt
    assert not reservations.rows


def test_the_verifier_refuses_a_network_candidate_without_its_service_before_any_change(monkeypatch):
    """The verifier makes the admission refusal again (POST .../verify and any later caller)."""
    database = NetworkHuntDatabase({"path": "/.env", "method": "GET"})
    monkeypatch.setattr(api_module, "db_pool", database)
    monkeypatch.setenv("AI_OPS_ROUTER_EXECUTE_ENABLED", "false")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(api_module._verify_suspected_finding_workflow(
            CANDIDATE, APPROVAL, created_by="hunt_v2:fixture", autonomous=False,
        ))
    assert exc.value.status_code == 422
    assert str(exc.value.detail).startswith("verification_service_unresolved")
    assert database.candidate_updates == []


# --- The real proof on a loopback service: where a verified network finding lands --------------

async def _serving_exposed_env(scenario):
    """A real HTTP service on 127.0.0.1 that serves ``/.env``; returns (result, requested paths)."""
    from aiohttp import web

    requested = []

    async def exposed(request):
        requested.append(request.path)
        return web.Response(body=EXPOSED_ENV, content_type="text/plain")

    app = web.Application()
    app.router.add_get("/.env", exposed)
    runner = web.AppRunner(app, shutdown_timeout=1)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        return await scenario(base), requested
    finally:
        await runner.cleanup()


def _verify_candidate_live(monkeypatch, locus_for, *, host="127.0.0.1"):
    """candidate.verify through the real Hunt lifecycle, verifier, dispatch, workflow runtime,
    family proof and promotion, against the loopback service. Doubles: see
    _network_verification_doubles; the reservations come from the web_hunt fixture."""
    outcome = {}

    async def scenario(base):
        database = NetworkHuntDatabase(locus_for(base), host=host)

        def run_in_thread():
            outcome["result"] = _verify_on_network_target(
                monkeypatch, None, database=database, runtime=api_module._execute_workflow_runtime,
            )

        # The Hunt lifecycle runs its own event loop (asyncio.run), so it runs beside this one.
        await asyncio.get_running_loop().run_in_executor(None, run_in_thread)
        return base

    base, requested = asyncio.run(_serving_exposed_env(scenario))
    return base, requested, outcome["result"]


def test_a_verified_network_candidate_is_recorded_on_the_service_it_was_found_on(
    web_hunt, monkeypatch,
):
    base, requested, (database, raised, delta, _bases, recorded) = _verify_candidate_live(
        monkeypatch, lambda base: {"path": "/.env", "method": "GET", "origin": base},
    )
    assert raised is None
    # Two independent runs read the exposure from the named service.
    assert requested == ["/.env", "/.env"]
    # The finding, its evidence and the verification record name that service, never the
    # host:// locator; the receipt keeps the target and records the service it ran on.
    assert database.findings_created == [{"target_id": TARGET, "url": f"{base}/.env"}]
    (evidence,) = recorded["evidence"]
    assert evidence.concrete_url == base
    assert database.verification_records == [{"target_url": base, "verdict": "exploited"}]
    (receipt,) = recorded["receipts"]
    assert receipt.target_scope["target_url"] == "host://127.0.0.1"
    assert receipt.target_scope["service_origin"] == base
    final_query, final_args = database.candidate_updates[-1]
    assert "latest_verification_id" in final_query and final_args[1] == "verified"
    assert delta["verifications"] == 1


def _suspected_finding(url):
    return {
        "id": CANDIDATE, "target_id": TARGET, "tool": "autonomous_agent", "source": "autonomous",
        "status": "active", "last_verification_verdict": None, "url": url, "method": "GET",
        "title": "Unauthenticated .env disclosure", "severity": "critical",
        "evidence": json.dumps({"family": "data_exposure", "method": "GET", "route": "/.env"}),
    }


def _verify_suspected_live(monkeypatch, *, host):
    """POST /findings/{id}/verify's verifier on a suspected finding of a network target."""
    outcome = {}

    async def scenario(base):
        database = NetworkHuntDatabase({}, host=host, finding=_suspected_finding(f"{base}/.env"))
        recorded = _network_verification_doubles(monkeypatch, database)

        def run_in_thread():
            try:
                outcome["result"] = asyncio.run(api_module._verify_suspected_finding_workflow(
                    CANDIDATE, APPROVAL, created_by="operator:fixture", autonomous=False,
                ))
            except HTTPException as exc:
                outcome["raised"] = exc

        await asyncio.get_running_loop().run_in_executor(None, run_in_thread)
        outcome.update(database=database, recorded=recorded)
        return base

    base, requested = asyncio.run(_serving_exposed_env(scenario))
    return base, requested, outcome


def test_a_suspected_network_finding_is_verified_on_its_own_service(monkeypatch):
    base, requested, outcome = _verify_suspected_live(monkeypatch, host="127.0.0.1")
    assert "raised" not in outcome
    assert outcome["result"]["verified"] is True
    assert requested == ["/.env", "/.env"]
    database = outcome["database"]
    assert database.findings_created == [{"target_id": TARGET, "url": f"{base}/.env"}]
    (evidence,) = outcome["recorded"]["evidence"]
    assert evidence.concrete_url == base


def test_a_suspected_finding_on_another_host_is_refused_before_any_request(monkeypatch):
    # The target is host://127.0.0.2; the finding's URL names a service on 127.0.0.1.
    _base, requested, outcome = _verify_suspected_live(monkeypatch, host="127.0.0.2")
    assert outcome["raised"].status_code == 422
    assert str(outcome["raised"].detail).startswith("verification_service_unresolved")
    assert requested == [] and outcome["database"].findings_created == []


def test_a_route_the_workflow_contract_refuses_is_released_before_any_request(web_hunt, monkeypatch):
    """A candidate route such as //other-host/x fails the workflow contract before the proof runs
    (step_0_path_must_be_relative, nothing sent). The Hunt charged it as an uncertain verification
    (24 requests, 180 s, a verification and an active action); it is now refused at no cost."""
    database, raised, delta, bases, _recorded = _verify_on_network_target(
        monkeypatch, {"path": "//198.51.100.99/x", "method": "GET", "origin": SERVICE},
    )
    assert bases == [] and delta == {}
    assert raised is not None and raised.status_code == 422
    assert raised.detail["error"] == "invalid_workflow" and raised.detail["target_traffic_sent"] is False
    (action,) = database.actions.values()
    public = public_hunt_action(action)["result"]
    assert action["status"] == "blocked" and public["execution_started"] is False
    assert public["budget_accounting"]["charge_basis"] == "not_charged"
    assert action["result_summary"]["violation"].startswith("step_0_path")
    _old, reservations = web_hunt
    (stored,) = reservations.rows.values()
    assert not any(stored.record.actual.values())


def test_a_contract_refusal_after_a_create_surface_probe_keeps_the_charge(web_hunt, monkeypatch):
    database, _reservations = web_hunt

    async def probed_then_refused(*args, **kwargs):
        return {"verified": False, "error": {
            "error": "invalid_workflow", "violation": "step_0_path_must_be_relative",
            "target_traffic_sent": True,
        }}

    result = _verify(probed_then_refused, monkeypatch)
    assert result["result"]["ok"] is True
    assert database.run["budget_used_json"]["verifications"] == 1
