"""Hunt interaction routes.

Extracted verbatim from the api.py monolith. Covers the per-run agent surface:
bounded context queries, semantic capability invocation, explicit confirmation
of an immutable SSH plan, evidence-backed candidate creation, and the handoff to
the deterministic verifier.

The agent never sees secrets and never supplies raw argv. Scope, approval,
multidimensional budgets, capability execution, evidence provenance, and
deterministic proof promotion all stay server-enforced, so the collaborators
that own those decisions are injected by the composition root rather than
re-implemented here.
"""

from __future__ import annotations

import asyncio
import copy
import math
import os
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Callable, Literal, Mapping, Optional, Sequence
import uuid

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from .run_service import agent_tools
from .cancellation import (
    HuntCancellationWatch,
    record_cancellable_job_durable,
)
from .settlement import blocked_actual_charges as _hunt_blocked_actual
from .device_policy import DeviceHuntPolicyState
from .capability_reservations import hunt_capability_action_digest, hunt_capability_lease_seconds, terminalize_hunt_capability
from .capability_executor import CapabilityExecutionContext, CapabilityExecutor
from .action_service import HUNT_ACTION_SERVICE, HuntActionInputError, HuntActionNotFound
from .action_dispatcher import HUNT_ACTION_DISPATCHER, HuntActionRequest, HuntActionResult, RegisteredHuntAdapterFactory
try:
    from action_scope import _decode_json_value
    from ai_gate.targets.widget_playwright import logger
    from api_utils import _json_safe_row, _optional_uuid, _uuid_or_400, utc_now_iso
    from capabilities.browser import BrowserCapabilityInputError, browser_capability_adapter
    from capabilities.inline import ControlPlaneExecutionAdapter, DeviceExecutionAdapter, TlsInspectionExecutionAdapter
    from capabilities.network import CapabilityInputError, network_capability_adapter
    from capabilities.tls import inspect_tls_origin
    from http_experiment import MAX_REDIRECT_HOPS
    from runtime.budget_reservations import DurableBudgetReservation
    from runtime.budgets import BudgetExceeded, reconcile_budget_snapshot, reserve_budget_snapshot
    from runtime.credential_refs import CredentialReferenceError, select_hunt_principal_reference
    from runtime.models import ScanPolicy, TargetBinding
    from runtime.request_collection_store import RequestCollectionContractError, RequestCollectionSelection
    from runtime.reservation_store import PostgresBudgetReservationStore
    from arsenal_routes import router as _arsenal_routes
    from devices import router as _devices
    from devices.router import DeviceAgentShellConfirmRequest
except ModuleNotFoundError:  # package import in host-side tests
    from ..action_scope import _decode_json_value
    from ..ai_gate.targets.widget_playwright import logger
    from ..api_utils import _json_safe_row, _optional_uuid, _uuid_or_400, utc_now_iso
    from ..capabilities.browser import BrowserCapabilityInputError, browser_capability_adapter
    from ..capabilities.inline import ControlPlaneExecutionAdapter, DeviceExecutionAdapter, TlsInspectionExecutionAdapter
    from ..capabilities.network import CapabilityInputError, network_capability_adapter
    from ..capabilities.tls import inspect_tls_origin
    from ..http_experiment import MAX_REDIRECT_HOPS
    from ..runtime.budget_reservations import DurableBudgetReservation
    from ..runtime.budgets import BudgetExceeded, reconcile_budget_snapshot, reserve_budget_snapshot
    from ..runtime.credential_refs import CredentialReferenceError, select_hunt_principal_reference
    from ..runtime.models import ScanPolicy, TargetBinding
    from ..runtime.request_collection_store import RequestCollectionContractError, RequestCollectionSelection
    from ..runtime.reservation_store import PostgresBudgetReservationStore
    from ..arsenal_routes import router as _arsenal_routes
    from ..devices import router as _devices
    from ..devices.router import DeviceAgentShellConfirmRequest

try:
    import device_agent
    import family_proof
    import investigation_candidates
    from request_collection_api import (
        select_request_collection_index_rows as _select_request_collection_index_rows,
    )
    from scanner_tools import device_shell
    from scanner_tools.request_collections import RequestSelector
except ModuleNotFoundError:  # package import in host-side tests
    from .. import device_agent, family_proof, investigation_candidates
    from ..request_collection_api import (
        select_request_collection_index_rows as _select_request_collection_index_rows,
    )
    from scanner.scanner_tools import device_shell
    from scanner.scanner_tools.request_collections import RequestSelector

from .action_service import HuntActionLifecycle
from .run_service import hunt_run_or_404 as _hunt_run_or_404, public_hunt_run as _hunt_public


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


_AGENT_TOOL_MAX_QUERY_ROWS = 100


def _hunt_budget_accounting(
    reserved: Mapping[str, Any],
    actual: Mapping[str, Any],
    used_after_reconciliation: Mapping[str, Any],
    *,
    charge_basis: str = "capability_reported_settlement",
    settlement_status: str,
    reservation_id: str | None,
) -> dict[str, Any]:
    """Publish exact settlement semantics without conflating holds and charges."""

    normalized_reserved = {
        str(key): max(0, int(value)) for key, value in reserved.items()
    }
    normalized_actual = {
        str(key): max(0, int(value)) for key, value in actual.items()
    }
    accounting = {
        "schema_version": "hunt-budget-settlement/v1",
        "charge_basis": charge_basis,
        "settlement_status": settlement_status,
        "reservation_id": reservation_id,
        "reserved": normalized_reserved,
        "actual": normalized_actual,
        "overspent": {
            key: int(normalized_actual.get(key) or 0) - amount
            for key, amount in normalized_reserved.items()
            if int(normalized_actual.get(key) or 0) > amount
        },
        "used_after_reconciliation": {
            str(key): max(0, int(value))
            for key, value in used_after_reconciliation.items()
        },
    }
    if settlement_status == "succeeded":
        accounting["released"] = {
            key: amount - int(normalized_actual.get(key) or 0)
            for key, amount in normalized_reserved.items()
            if amount >= int(normalized_actual.get(key) or 0)
        }
    return accounting


def configure_hunt_interaction_router(
    pool_provider: Callable[[], Any], **collaborators: Callable[..., Any]
) -> None:
    """Bind the pool and the collaborators this domain needs."""
    global _pool_provider
    _pool_provider = pool_provider
    _deps.update(collaborators)


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool is not ready")
    return pool


def _dep(name: str) -> Callable[..., Any]:
    call = _deps.get(name)
    if call is None:
        raise HTTPException(status_code=503, detail=f"{name} is not ready")
    return call


def _get(name: str) -> Any:
    """Resolve an injected collaborator that still lives in the composition root."""
    return _dep(name)()



async def _validate_approval_receipt_for_action(*a: Any, **k: Any) -> Any:
    return await _get("_validate_approval_receipt_for_action")(*a, **k)


async def _verify_suspected_finding_workflow(*a: Any, **k: Any) -> Any:
    return await _get("_verify_suspected_finding_workflow")(*a, **k)


def enqueue_job(*a: Any, **k: Any) -> Any:
    return _get("enqueue_job")(*a, **k)


def get_redis(*a: Any, **k: Any) -> Any:
    return _get("get_redis")(*a, **k)


__all__ = ["configure_hunt_interaction_router", "router"]
class HuntQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # hypotheses / graph_nodes / graph_edges were implemented in the knowledge base but missing
    # from this Literal, so a Hunt could never ask for them: the lead backlog from earlier runs and
    # the persisted application graph (routes, objects, principals and their auth-boundary edges)
    # were unreachable exactly where they are most useful.
    kind: Literal[
        "summary", "endpoints", "findings", "principals", "services", "scans",
        "collections", "candidates", "notes", "receipts", "hypotheses",
        "graph_nodes", "graph_edges"
    ] = "summary"
    filter: dict[str, Any] = Field(default_factory=dict)
    limit: int = Field(default=100, ge=1, le=500)


class HuntCandidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    family: str = Field(min_length=1, max_length=80)
    locus: dict[str, Any] = Field(default_factory=dict)
    title: str = Field(min_length=1, max_length=300)
    claim: str = Field(min_length=1, max_length=8000)
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    evidence_refs: list[str] = Field(min_length=1, max_length=100)
    verifier_contract_id: Optional[str] = Field(default=None, max_length=160)


@router.post("/hunts/{hunt_id}/query")
async def query_hunt(hunt_id: str, request: HuntQueryRequest):
    async with _pool().acquire() as conn:
        run = await _hunt_run_or_404(conn, hunt_id)
    kind = request.kind
    limit = request.limit
    if str(run["target_kind"]) != "device" and kind in {
        "endpoints", "findings", "principals", "notes", "receipts",
        "hypotheses", "graph_nodes", "graph_edges",
    }:
        mapped = {"receipts": "tool_receipts"}.get(kind, kind)
        result = await _agent_tool_query_kb(run["target_id"], mapped, {**request.filter, "limit": limit})
        return {"hunt_id": hunt_id, **result}
    async with _pool().acquire() as conn:
        if kind == "collections":
            target_ref = run["device_target_id"] or run["target_id"]
            rows = await conn.fetch(
                """SELECT id, name, format, request_count, safe_request_count,
                          potentially_mutating_request_count, payload_sha256, updated_at
                   FROM request_collections
                   WHERE is_active=true AND (target_id=$1 OR device_target_id=$1)
                   ORDER BY updated_at DESC LIMIT $2""", target_ref, limit,
            )
        elif kind == "services" and run["device_target_id"]:
            rows = await conn.fetch(
                """SELECT transport, port, state, service_name, product, version, encrypted,
                          web_origin, policy_disposition, last_seen_at
                   FROM device_services WHERE device_target_id=$1
                   ORDER BY state='open' DESC, transport, port LIMIT $2""",
                run["device_target_id"], limit,
            )
        elif kind == "scans" and run["device_target_id"]:
            rows = await conn.fetch(
                """SELECT id, status, progress, current_phase, findings_count, created_at
                   FROM scans WHERE device_target_id=$1 ORDER BY created_at DESC LIMIT $2""",
                run["device_target_id"], limit,
            )
        elif kind == "candidates":
            column = "device_target_id" if run["device_target_id"] else "target_id"
            rows = await conn.fetch(
                f"""SELECT id, family, canonical_locus, title, claim, claimed_severity,
                            evidence_refs, verifier_contract_id, status, last_seen_at
                     FROM investigation_candidates WHERE {column}=$1
                     ORDER BY last_seen_at DESC LIMIT $2""",
                run["device_target_id"] or run["target_id"], limit,
            )
        else:
            return {"hunt_id": hunt_id, "kind": kind, "count": 0, "rows": [],
                    "context": _hunt_public(run).get("context_pack") if kind == "summary" else None}
    items = [_arsenal_routes._redact_agent_payload(_json_safe_row(row)) for row in rows]
    return {"hunt_id": hunt_id, "kind": kind, "count": len(items), "rows": items}


@router.post("/hunts/{hunt_id}/capabilities/{capability_name:path}")
async def execute_hunt_capability(
    hunt_id: str, capability_name: str, request: HuntCapabilityRequest,
):
    name = str(capability_name or "").strip().lower()
    try:
        return await HUNT_ACTION_SERVICE.execute(
            name,
            request.input,
            lambda lifecycle: _execute_hunt_capability_lifecycle(
                hunt_id, name, request, lifecycle,
            ),
        )
    except HuntActionNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except HuntActionInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/hunts/{hunt_id}/shell-plans/{plan_id}/confirm")
async def confirm_hunt_shell_plan(
    hunt_id: str, plan_id: str, request: DeviceAgentShellConfirmRequest,
):
    """Confirm one immutable device SSH plan owned by the unified Hunt runtime."""
    if not request.confirm_exact_commands or not request.confirm_remote_device_effects:
        raise HTTPException(
            status_code=409,
            detail="Confirm both the exact commands and their possible effects on the remote device",
        )
    capability_name = "device.ssh.execute_confirmed"
    spec = agent_tools.CAPABILITY_REGISTRY.require(capability_name)
    plan_uuid = _devices._device_uuid(plan_id, "SSH shell plan")
    queue_token = str(uuid.uuid4())
    action_id = uuid.uuid4()
    charges = {key: int(value) for key, value in spec.budget_cost.items()}
    if charges.get("device_fragility_points") != int(
        device_agent.CONFIRMED_SHELL_FRAGILITY_COST
    ):
        raise RuntimeError("Confirmed SSH fragility contract drifted from the registry")
    durable_store = PostgresBudgetReservationStore()
    durable_worker_id = (
        f"api:{str(os.environ.get('HOSTNAME') or 'local')[:64]}:{os.getpid()}"
    )
    durable_reservation = None
    durable_action_digest: str | None = None
    validated_scope_receipt_id: str | None = None
    dispatch_required = True
    queued: dict[str, Any] | None = None
    admission_error: HTTPException | None = None
    capability_input: dict[str, Any] = {}
    async with _pool().acquire() as conn:
        async with conn.transaction():
            run = await _hunt_run_or_404(conn, hunt_id, for_update=True)
            if str(run["target_kind"]) != "device" or not run["device_target_id"]:
                raise HTTPException(status_code=409, detail="SSH shell plans require a device Hunt")
            if str(run["status"]) not in {"active", "awaiting_planner"}:
                raise HTTPException(status_code=409, detail=f"Hunt is {run['status']}")
            policy = _hunt_json(run["policy_json"], {})
            if not policy.get("active_testing") or not policy.get("credential_access"):
                raise HTTPException(status_code=409, detail="SSH shell confirmation requires active credential authority")
            context = _hunt_json(run["context_pack"], {})
            try:
                native_device_policy = DeviceHuntPolicyState.from_mapping(
                    context.get("device_policy_state") or {}
                )
            except ValueError as exc:
                raise HTTPException(
                    status_code=409,
                    detail="Native device Hunt policy state is unavailable",
                ) from exc
            runtime = (
                dict(context.get("device_runtime") or {})
                if isinstance(context.get("device_runtime"), Mapping)
                else {}
            )
            state = native_device_policy.adapter_state(
                credential_refs=[
                    dict(item)
                    for item in context.get("credential_refs") or []
                    if isinstance(item, Mapping)
                ],
                collection_refs=[
                    dict(item)
                    for item in context.get("request_collections") or []
                    if isinstance(item, Mapping)
                ],
                runtime=runtime,
                allow_state_changing_requests=bool(
                    policy.get("allow_state_changing_http")
                ),
            )
            if native_device_policy.traffic_frozen:
                raise HTTPException(status_code=409, detail="Device traffic is frozen after a health circuit breaker")
            plans = [item for item in state.get("shell_plans", []) if isinstance(item, dict)]
            index = next((i for i, item in enumerate(plans) if str(item.get("plan_id")) == str(plan_uuid)), None)
            if index is None:
                raise HTTPException(status_code=404, detail="SSH shell plan not found in this Hunt")
            try:
                plan = device_shell.validate_shell_plan(plans[index])
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            if str(plan.get("run_id")) != str(run["id"]) or str(plan.get("device_target_id")) != str(run["device_target_id"]):
                raise HTTPException(status_code=409, detail="SSH shell plan scope does not match this Hunt")
            if request.plan_digest != str(plan["plan_digest"]):
                raise HTTPException(status_code=409, detail="SSH shell plan digest changed; review the exact commands again")
            if request.confirmation_phrase != str(plan["confirmation_phrase"]):
                raise HTTPException(status_code=409, detail="SSH shell confirmation phrase does not match the immutable plan")
            try:
                expires_at = datetime.fromisoformat(str(plan["expires_at"]).replace("Z", "+00:00"))
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=409, detail="SSH shell plan has an invalid expiry") from exc
            if (
                plan.get("status") == "proposed"
                and expires_at <= datetime.now(timezone.utc)
            ):
                plans[index] = {**plan, "status": "expired"}
                runtime["shell_plans"], context["device_runtime"] = plans, runtime
                await conn.execute(
                    "UPDATE hunt_runs SET context_pack=$2, updated_at=NOW() WHERE id=$1",
                    run["id"], json.dumps(context, default=str),
                )
                raise HTTPException(status_code=409, detail="SSH shell plan expired; ask the agent to propose it again")
            bound_ssh_ref = _devices._device_agent_credential_reference(state, "ssh")
            if (
                bound_ssh_ref is None
                or str(plan.get("credential_profile_id"))
                != str(bound_ssh_ref.get("profile_id"))
            ):
                raise HTTPException(status_code=409, detail="SSH shell plan credential is no longer bound to this Hunt")
            device = await conn.fetchrow(
                "SELECT id, primary_locator, locator_generation, is_active FROM device_targets WHERE id=$1",
                run["device_target_id"],
            )
            if (
                not device or not device["is_active"]
                or str(device["primary_locator"]) != str(plan["target_locator"])
                or int(device["locator_generation"]) != int(plan["locator_generation"])
            ):
                raise HTTPException(status_code=409, detail="Device address or identity changed; request a new shell plan")
            capability_input = _hunt_confirmed_shell_capability_input(plan, request)

            if plan.get("status") == "queued":
                queued = {
                    "scan_id": str(plan.get("scan_id") or ""),
                    "job_id": str(plan.get("job_id") or ""),
                    "status": "queued",
                    "run_kind": "device_posture",
                    "device_target_id": str(run["device_target_id"]),
                    "target": str(device["primary_locator"]),
                    "profile": "inventory",
                    "safety_profile": "authenticated_active",
                    "ui_url": f"/scans/{plan.get('scan_id')}",
                }
                response = _hunt_public(run)
                response["queued_scan"] = queued
                response["idempotent_replay"] = True
                return response

            if plan.get("status") == "queueing":
                try:
                    action_id = uuid.UUID(str(plan["confirmation_action_id"]))
                    queue_token = str(plan["queue_token"])
                    reservation_id = str(plan["budget_reservation_id"])
                    durable_action_digest = str(plan["action_digest"])
                    validated_scope_receipt_id = str(
                        plan.get("scope_receipt_id") or ""
                    ) or None
                except (KeyError, ValueError) as exc:
                    raise HTTPException(
                        status_code=409,
                        detail="SSH shell confirmation has incomplete durable correlation",
                    ) from exc
                durable_reservation = await durable_store.load(
                    conn, reservation_id, for_update=True,
                )
                if (
                    durable_reservation is None
                    or durable_reservation.action_id != str(action_id)
                    or durable_reservation.action_digest != durable_action_digest
                    or durable_action_digest != hunt_capability_action_digest(
                        hunt_id=run["id"],
                        action_id=action_id,
                        capability_name=capability_name,
                        target_kind=str(run["target_kind"]),
                        target_id=run["device_target_id"],
                        capability_input=capability_input,
                        requested_budget=charges,
                        scope_receipt_id=validated_scope_receipt_id,
                        approval_receipt_id=policy.get("approval_receipt_id"),
                    )
                    or durable_reservation.record.owner_id != str(run["id"])
                    or durable_reservation.record.capability_name != capability_name
                    or dict(durable_reservation.record.requested) != charges
                    or durable_reservation.record.status != "running"
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="SSH shell confirmation reservation is no longer dispatchable",
                    )
                queued = await _hunt_confirmed_shell_dispatch(
                    conn,
                    device_target_id=run["device_target_id"],
                    action_id=action_id,
                    reservation_id=reservation_id,
                    action_digest=durable_action_digest,
                )
                if queued is None:
                    raise HTTPException(
                        status_code=409,
                        detail="SSH shell confirmation is already queueing",
                    )
                dispatch_required = False
            elif plan.get("status") != "proposed":
                raise HTTPException(
                    status_code=409,
                    detail=f"SSH shell plan is already {plan.get('status') or 'unavailable'}",
                )

            if dispatch_required:
                approval_context = await _validate_approval_receipt_for_action(
                    conn,
                    policy.get("approval_receipt_id"),
                    target_url=str(device["primary_locator"]),
                    target_id=run["device_target_id"],
                    action_name="hunt.device.ssh.confirm",
                    command=capability_name,
                    risk_tier="credential",
                    always_require_receipt=True,
                    require_target_binding=True,
                    require_expiry=True,
                    created_by=f"hunt_v2_shell:{hunt_id}",
                )
                validated_scope_receipt_id = str(
                    (approval_context or {}).get("scope_receipt_id")
                    or policy.get("scope_receipt_id")
                    or ""
                ) or None
                legacy_daily = int(await conn.fetchval(
                    """SELECT COALESCE(SUM(fragility_cost),0) FROM device_agent_actions
                       WHERE device_target_id=$1 AND outcome <> 'blocked'
                         AND created_at >= date_trunc('day', NOW())""",
                    run["device_target_id"],
                ) or 0)
                hunt_daily = int(await conn.fetchval(
                    """SELECT COALESCE(SUM(COALESCE((budget_used_json->>'device_fragility_points')::int,0)),0)
                       FROM hunt_runs WHERE device_target_id=$1
                         AND created_at >= date_trunc('day', NOW())""",
                    run["device_target_id"],
                ) or 0)
                if (
                    legacy_daily + hunt_daily
                    + charges["device_fragility_points"]
                    > device_agent.MAX_FRAGILITY_PER_DEVICE_DAY
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="Daily fragility budget for this device is exhausted",
                    )
                durable_action_digest = hunt_capability_action_digest(
                    hunt_id=run["id"],
                    action_id=action_id,
                    capability_name=capability_name,
                    target_kind=str(run["target_kind"]),
                    target_id=run["device_target_id"],
                    capability_input=capability_input,
                    requested_budget=charges,
                    scope_receipt_id=validated_scope_receipt_id,
                    approval_receipt_id=policy.get("approval_receipt_id"),
                )
                requested = DurableBudgetReservation.request(
                    owner_kind="hunt",
                    owner_id=str(run["id"]),
                    capability_name=capability_name,
                    amounts=charges,
                )
                stored = await durable_store.create_requested(
                    conn,
                    action_id=str(action_id),
                    action_digest=durable_action_digest,
                    record=requested,
                )
                budget = _hunt_json(run["budget_json"], {})
                limits = _hunt_ledger_limits(budget)
                used = _hunt_json(run["budget_used_json"], {})
                try:
                    reserved_record, reserved_used = stored.record.reserve_against(
                        limits=limits,
                        consumed={key: int(used.get(key) or 0) for key in limits},
                        lease_seconds=hunt_capability_lease_seconds(charges),
                    )
                except BudgetExceeded as exc:
                    released = stored.record.release(
                        proof_not_started=True,
                        reason="budget_exhausted_before_confirmed_ssh_queue",
                    )
                    await durable_store.persist_terminal(
                        conn,
                        previous=stored,
                        terminal=released,
                        ledger_after_settlement={
                            key: int(used.get(key) or 0) for key in limits
                        },
                        receipt=None,
                    )
                    dimension = next(iter(exc.shortages), "unknown")
                    await conn.execute(
                        """INSERT INTO hunt_actions
                               (id,hunt_run_id,capability_name,status,input_summary,
                                result_summary,completed_at)
                           VALUES ($1,$2,$3,'failed',$4,$5,NOW())""",
                        action_id,
                        run["id"],
                        capability_name,
                        json.dumps(capability_input),
                        json.dumps({
                            "error": f"budget_exhausted:{dimension}",
                            "budget_reservation_id": released.reservation_id,
                            "budget_reservation_state": released.status,
                        }),
                    )
                    await conn.execute(
                        "UPDATE hunt_runs SET status='budget_exhausted', "
                        "stop_reason=$2, updated_at=NOW() WHERE id=$1",
                        run["id"],
                        f"budget_exhausted:{dimension}",
                    )
                    admission_error = HTTPException(
                        status_code=409,
                        detail=f"Hunt budget exhausted: {dimension}",
                    )
                else:
                    reserved = await durable_store.persist_transition(
                        conn,
                        previous=stored,
                        current=reserved_record,
                        ledger_after_hold=reserved_used,
                    )
                    running_record = reserved.record.start(
                        worker_id=durable_worker_id,
                        lease_seconds=hunt_capability_lease_seconds(charges),
                    )
                    durable_reservation = await durable_store.persist_transition(
                        conn,
                        previous=reserved,
                        current=running_record,
                    )
                    used.update(reserved_used)
                    plan = {
                        **plan,
                        "status": "queueing",
                        "queue_token": queue_token,
                        "confirmation_action_id": str(action_id),
                        "budget_reservation_id": (
                            durable_reservation.record.reservation_id
                        ),
                        "action_digest": durable_action_digest,
                        "scope_receipt_id": validated_scope_receipt_id,
                        "confirmed_at": datetime.now(timezone.utc).isoformat(),
                        "confirmed_plan_digest": request.plan_digest,
                        "confirmation_basis": (
                            "explicit_user_exact_command_confirmation"
                        ),
                    }
                    plans[index] = plan
                    runtime["shell_plans"], context["device_runtime"] = plans, runtime
                    await conn.execute(
                        """UPDATE hunt_runs
                           SET context_pack=$2,budget_used_json=$3,
                               status='active',updated_at=NOW()
                           WHERE id=$1""",
                        run["id"],
                        json.dumps(context, default=str),
                        json.dumps(used),
                    )
                    await conn.execute(
                        """INSERT INTO hunt_actions
                               (id,hunt_run_id,capability_name,status,input_summary)
                           VALUES ($1,$2,$3,'running',$4)""",
                        action_id,
                        run["id"],
                        capability_name,
                        json.dumps(capability_input),
                    )
            budget = _hunt_json(run["budget_json"], {})
            limits = _hunt_ledger_limits(budget)
            device_target_id = run["device_target_id"]
            approval_receipt_id = policy.get("approval_receipt_id")

    if admission_error is not None:
        raise admission_error
    if durable_reservation is None or durable_action_digest is None:
        raise HTTPException(
            status_code=500,
            detail="Confirmed SSH reservation was not initialized",
        )

    execution_started = time.perf_counter()
    dispatch_error: Exception | None = None
    capability_execution = None
    if dispatch_required:
        # A confirmed SSH plan reaches a real device, so a Hunt cancelled between confirmation and
        # dispatch must stop here rather than at the next unchecked beat.
        device_cancellation_watch = HuntCancellationWatch(_pool, run["id"])
        await device_cancellation_watch.refresh(force=True)
        parent_token = _devices._DEVICE_AGENT_PARENT_AUTHORITY.set(True)
        shell_token = _devices._DEVICE_AGENT_APPROVED_SHELL_PLAN.set(plan)
        correlation_token = _devices._HUNT_DEVICE_QUEUE_CORRELATION.set({
            "schema_version": "hunt-device-dispatch/v1",
            "hunt_id": str(run["id"]),
            "hunt_action_id": str(action_id),
            "budget_reservation_id": durable_reservation.record.reservation_id,
            "action_digest": durable_action_digest,
            "capability_name": capability_name,
        })
        try:
            dispatch_adapter = DeviceExecutionAdapter(
                specification=spec,
                operation=lambda: _devices.scan_device(
                    str(device_target_id),
                    _devices.DeviceScanRequest(
                        profile="inventory",
                        safety_profile="authenticated_active",
                        confirm_authorized=True,
                        include_web_dast=False,
                        max_web_origins=0,
                        ssh_credential_profile_id=str(
                            plan["credential_profile_id"]
                        ),
                        capability_ids=["agent-confirmed-ssh-shell"],
                        approval_receipt_id=approval_receipt_id,
                    ),
                ),
                requested_budget=durable_reservation.record.requested,
                redacted_execution=capability_input,
                state={},
                # Every queue failure is captured so the exact downstream row
                # can decide whether the hold was consumed before we re-raise.
                blocked_exceptions=(Exception,),
            )
            capability_execution = await CapabilityExecutor().execute(
                CapabilityExecutionContext(
                    specification=spec,
                    target=TargetBinding(
                        target_id=str(device_target_id),
                        target_kind="device",
                        canonical_host=str(plan["target_locator"]),
                        scope_receipt_id=validated_scope_receipt_id,
                    ),
                    requested_budget=durable_reservation.record.requested,
                ),
                dispatch_adapter,
                heartbeat=device_cancellation_watch.heartbeat(),
                cancelled=device_cancellation_watch.cancelled,
            )
            queued = dispatch_adapter.result or None
            if isinstance(dispatch_adapter.blocked_exception, Exception):
                dispatch_error = dispatch_adapter.blocked_exception
        finally:
            _devices._HUNT_DEVICE_QUEUE_CORRELATION.reset(correlation_token)
            _devices._DEVICE_AGENT_APPROVED_SHELL_PLAN.reset(shell_token)
            _devices._DEVICE_AGENT_PARENT_AUTHORITY.reset(parent_token)

    accepted_scan: dict[str, Any] | None = None
    async with _pool().acquire() as conn:
        async with conn.transaction():
            updated = await _hunt_run_or_404(conn, hunt_id, for_update=True)
            latest_reservation = await durable_store.load(
                conn,
                durable_reservation.record.reservation_id,
                for_update=True,
            )
            if (
                latest_reservation is None
                or latest_reservation.action_id != str(action_id)
                or latest_reservation.action_digest != durable_action_digest
                or latest_reservation.record.status != "running"
                or latest_reservation.record.worker_id
                != durable_reservation.record.worker_id
            ):
                raise RuntimeError(
                    "Confirmed SSH reservation changed before settlement"
                )
            accepted_scan = await _hunt_confirmed_shell_dispatch(
                conn,
                device_target_id=device_target_id,
                action_id=action_id,
                reservation_id=latest_reservation.record.reservation_id,
                action_digest=durable_action_digest,
            )
            if (
                accepted_scan is not None
                and queued is not None
                and str(queued.get("scan_id") or "")
                and str(queued.get("scan_id")) != accepted_scan["scan_id"]
            ):
                raise RuntimeError(
                    "Confirmed SSH response does not match its downstream scan"
                )
            elapsed_wall = max(1, math.ceil(time.perf_counter() - execution_started))
            if accepted_scan is not None:
                actual_charges = {
                    key: (
                        min(value, elapsed_wall)
                        if key == "tool_wall_seconds"
                        else value
                    )
                    for key, value in charges.items()
                }
                action_status = "completed"
                result_summary = {
                    "ok": True,
                    "status": "queued",
                    "scan_id": accepted_scan["scan_id"],
                    "job_id": accepted_scan["job_id"],
                    "plan_id": str(plan_uuid),
                    "plan_digest": request.plan_digest,
                    "recovered_after_response_failure": bool(dispatch_error),
                    "receipt_observations": [{
                        "kind": "confirmed_ssh_execution_queue",
                        "status": "queued",
                        "plan_id": str(plan_uuid),
                        "plan_digest": request.plan_digest,
                        "scan_id": accepted_scan["scan_id"],
                        "job_id": accepted_scan["job_id"],
                        "exact_commands_confirmed": True,
                        "remote_device_effects_confirmed": True,
                    }],
                }
            else:
                actual_charges = _hunt_nonexecuting_actual(charges)
                action_status = "failed"
                result_summary = {
                    "ok": False,
                    "error": (
                        f"queue_fault:{type(dispatch_error).__name__}"
                        if dispatch_error is not None
                        else "queue_receipt_missing"
                    ),
                    "plan_id": str(plan_uuid),
                    "plan_digest": request.plan_digest,
                    "receipt_observations": [{
                        "kind": "confirmed_ssh_execution_queue",
                        "status": "not_enqueued",
                        "plan_id": str(plan_uuid),
                        "plan_digest": request.plan_digest,
                    }],
                }
            current_used = _hunt_json(updated["budget_used_json"], {})
            current_ledger = {
                key: int(current_used.get(key) or 0) for key in limits
            }
            prospective_ledger = reconcile_budget_snapshot(
                current_ledger,
                latest_reservation.record.requested,
                actual_charges,
            )
            prospective_used = dict(current_used)
            prospective_used.update(prospective_ledger)
            receipt_result = await _arsenal_routes._record_tool_receipt(
                conn,
                _arsenal_routes.ToolReceiptRequest(
                    tool_name=str(spec.adapter),
                    capability_name=capability_name,
                    adapter_name=str(spec.adapter),
                    adapter_version=str(spec.adapter_version),
                    redacted_argv=[capability_input],
                    target_scope={
                        "target_kind": "device",
                        "target_id": str(device_target_id),
                    },
                    scope_receipt_id=validated_scope_receipt_id,
                    approval_receipt_id=approval_receipt_id,
                    status="success" if accepted_scan is not None else "failed",
                    parser_status="parsed" if accepted_scan is not None else "failed",
                    budget_json={
                        "reserved": charges,
                        "actual": actual_charges,
                        "used_after_reconciliation": prospective_used,
                    },
                    partial=False,
                    hunt_id=str(run["id"]),
                    metadata_json={
                        "hunt_action_id": str(action_id),
                        "durable_budget_reservation_id": (
                            latest_reservation.record.reservation_id
                        ),
                        "plan_id": str(plan_uuid),
                        "plan_digest": request.plan_digest,
                        "downstream": accepted_scan,
                    },
                    created_by=f"hunt_v2_shell:{hunt_id}",
                ),
            )
            receipt_id = receipt_result.get("tool_receipt", {}).get("id")
            if not receipt_id:
                raise RuntimeError("Confirmed SSH receipt was not persisted")
            terminal_record, capability_receipt = terminalize_hunt_capability(
                latest_reservation.record,
                action_digest=durable_action_digest,
                capability_name=capability_name,
                adapter_name=str(spec.adapter),
                adapter_version=str(spec.adapter_version),
                parser_version=(
                    capability_execution.parser_version
                    if capability_execution is not None
                    else spec.output_schema
                ),
                target_id=device_target_id,
                target_kind="device",
                capability_input=capability_input,
                action_status=action_status,
                actual_budget=actual_charges,
                worker_id=str(latest_reservation.record.worker_id),
                started_at=(
                    latest_reservation.record.started_at.isoformat()
                    if latest_reservation.record.started_at
                    else datetime.now(timezone.utc).isoformat()
                ),
                finished_at=datetime.now(timezone.utc).isoformat(),
                receipt_id=str(receipt_id),
                scope_receipt_id=validated_scope_receipt_id,
                approval_receipt_id=approval_receipt_id,
                result=result_summary,
            )
            reconciled_ledger = terminal_record.reconcile_consumed(current_ledger)
            if reconciled_ledger != prospective_ledger:
                raise RuntimeError(
                    "Confirmed SSH reconciliation changed during settlement"
                )
            await durable_store.persist_terminal(
                conn,
                previous=latest_reservation,
                terminal=terminal_record,
                ledger_after_settlement=reconciled_ledger,
                receipt=capability_receipt,
            )
            updated_context = _hunt_json(updated["context_pack"], {})
            updated_runtime = (
                dict(updated_context.get("device_runtime") or {})
                if isinstance(updated_context.get("device_runtime"), Mapping)
                else {}
            )
            settled_plans = []
            plan_settled = False
            for item in updated_runtime.get("shell_plans", []):
                if not isinstance(item, dict):
                    continue
                if (
                    str(item.get("plan_id")) != str(plan_uuid)
                    or item.get("queue_token") != queue_token
                    or str(item.get("confirmation_action_id") or "")
                    != str(action_id)
                ):
                    settled_plans.append(item)
                    continue
                if accepted_scan is not None:
                    settled = {
                        **{
                            key: value
                            for key, value in item.items()
                            if key not in {
                                "last_queue_error", "last_queue_receipt_id",
                            }
                        },
                        "status": "queued",
                        "scan_id": accepted_scan["scan_id"],
                        "job_id": accepted_scan["job_id"],
                        "queued_at": datetime.now(timezone.utc).isoformat(),
                        "receipt_id": str(receipt_id),
                        "budget_reservation_state": terminal_record.status,
                    }
                else:
                    settled = {
                        key: value
                        for key, value in item.items()
                        if key not in {
                            "queue_token", "confirmation_action_id",
                            "budget_reservation_id", "action_digest",
                            "scope_receipt_id",
                            "confirmed_at", "confirmed_plan_digest",
                            "confirmation_basis",
                        }
                    }
                    settled.update({
                        "status": "proposed",
                        "last_queue_error": result_summary["error"],
                        "last_queue_receipt_id": str(receipt_id),
                    })
                settled_plans.append(settled)
                plan_settled = True
            if not plan_settled:
                raise RuntimeError(
                    "Confirmed SSH plan changed before settlement"
                )
            updated_runtime["shell_plans"] = settled_plans
            updated_context["device_runtime"] = updated_runtime
            updated = await conn.fetchrow(
                """UPDATE hunt_runs
                   SET context_pack=$2,budget_used_json=$3,updated_at=NOW()
                   WHERE id=$1 RETURNING *""",
                updated["id"],
                json.dumps(updated_context, default=str),
                json.dumps(prospective_used),
            )
            action_updated = await conn.execute(
                """UPDATE hunt_actions
                   SET status=$2,result_summary=$3,receipt_id=$4,completed_at=NOW()
                   WHERE id=$1 AND hunt_run_id=$5 AND status='running'""",
                action_id,
                action_status,
                json.dumps(_arsenal_routes._redact_agent_payload(result_summary), default=str),
                _optional_uuid(str(receipt_id)),
                updated["id"],
            )
            if not str(action_updated).endswith(" 1"):
                raise RuntimeError(
                    "Confirmed SSH action changed before settlement"
                )
    if accepted_scan is None:
        if dispatch_error is not None:
            raise dispatch_error
        raise HTTPException(
            status_code=503,
            detail="Confirmed SSH job was not accepted by the device queue",
        )
    response = _hunt_public(updated)
    response["queued_scan"] = accepted_scan
    response["recovered_after_response_failure"] = bool(dispatch_error)
    return response


@router.post("/hunts/{hunt_id}/candidates")
async def create_hunt_candidate(hunt_id: str, request: HuntCandidateRequest):
    async with _pool().acquire() as conn:
        async with conn.transaction():
            run = await _hunt_run_or_404(conn, hunt_id, for_update=True)
            if run["status"] not in {"active", "awaiting_planner"}:
                raise HTTPException(status_code=409, detail=f"Hunt is {run['status']}")
            used = _hunt_json(run["budget_used_json"], {})
            budget = _hunt_json(run["budget_json"], {})
            if int(used.get("candidates") or 0) >= int(budget.get("max_candidates") or 0):
                raise HTTPException(status_code=409, detail="Hunt candidate budget exhausted")
            candidate = investigation_candidates.normalize_candidate(
                plane="device" if run["device_target_id"] else "web",
                target_id=str(run["target_id"]) if run["target_id"] else None,
                device_target_id=str(run["device_target_id"]) if run["device_target_id"] else None,
                hunt_run_id=str(run["id"]), family=request.family, locus=request.locus,
                title=request.title, claim=request.claim, severity=request.severity,
                evidence_refs=request.evidence_refs, verifier_contract_id=request.verifier_contract_id,
                source_kind="hunt_v2",
            )
            result = await investigation_candidates.upsert_candidate(
                conn, candidate, created_by=f"hunt_v2:{hunt_id}",
                observation_context={"hunt_id": hunt_id, "objective": run["objective"]},
            )
            used["candidates"] = int(used.get("candidates") or 0) + 1
            await conn.execute("UPDATE hunt_runs SET budget_used_json=$2, updated_at=NOW() WHERE id=$1", run["id"], json.dumps(used))
    return {"hunt_id": hunt_id, "candidate": result, "authoritative": False, "verified": False}


# Mirror of the fan-out `_device_verify_candidate_tool` performs. A test pins these against the
# values it actually passes, so the reservation cannot drift away from the traffic it authorizes.
_DEVICE_VERIFICATION_WEB_CONTRACTS: frozenset[str] = frozenset({"device.tls", "device.auth_bypass"})
_DEVICE_VERIFICATION_WEB_SCAN_TYPE = "standard"
_DEVICE_VERIFICATION_MAX_WEB_ORIGINS = 8


class HuntCandidateVerifyRequest(BaseModel):
    """Optional body for a candidate verification.

    ``attempt`` selects the idempotency key. Verification is expensive and can promote a finding,
    so a repeat of the same attempt must replay rather than re-execute -- but a verification the
    server *rejected before dispatch* (`invalid_workflow`: a missing principal context, an
    unapproved invariant contract, an unresolved route) never ran a proof at all, and its rejection
    was cached under a fixed key. Once the operator fixed the named cause -- registering the
    credential the error asked for, approving the contract -- the same candidate could never be
    verified again in that Hunt. Raising ``attempt`` requests a fresh, separately receipted
    execution; attempt 1 keeps the original key so existing callers replay exactly as before.
    """

    model_config = ConfigDict(extra="forbid")
    attempt: int = Field(default=1, ge=1, le=20)


@router.post("/hunts/{hunt_id}/candidates/{candidate_id}/verify")
async def verify_hunt_candidate(
    hunt_id: str, candidate_id: str,
    # A default instance rather than Optional: an `X | None` body publishes an anyOf(..., null)
    # request schema, which drops the strict `additionalProperties: false` the release contract
    # requires of every state-changing JSON write. The default keeps the body optional for callers
    # that post nothing while the published schema stays the strict model. Read-only here.
    request: HuntCandidateVerifyRequest = HuntCandidateVerifyRequest(),
):
    candidate_uuid = _uuid_or_400(candidate_id, "candidate id")
    attempt = int(request.attempt)
    suffix = "" if attempt == 1 else f":retry-{attempt}"
    action = await execute_hunt_capability(
        hunt_id,
        "candidate.verify",
        HuntCapabilityRequest(
            idempotency_key=f"candidate-verify:{candidate_uuid}{suffix}",
            input={"candidate_id": str(candidate_uuid)},
        ),
    )
    result = action.get("result") if isinstance(action.get("result"), Mapping) else {}
    verification = (
        result.get("verification")
        if isinstance(result.get("verification"), Mapping)
        else result
    )
    return {
        "hunt_id": hunt_id,
        "candidate_id": str(candidate_uuid),
        "attempt": attempt,
        "verification": verification,
        "action": action,
    }
async def _agent_tool_query_kb(target_uuid: uuid.UUID, kind: str, flt: dict[str, Any]) -> dict[str, Any]:
    try:
        limit = int(flt.get("limit"))
    except (TypeError, ValueError):
        limit = 25
    limit = max(1, min(limit, _AGENT_TOOL_MAX_QUERY_ROWS))
    path_contains = str(flt.get("path_contains") or "").strip()
    family = str(flt.get("family") or "").strip().lower()
    severity = str(flt.get("severity") or "").strip().lower()
    method = str(flt.get("method") or "").strip().upper()
    # The context pack advertises how much of the inventory is untested and how many findings are
    # already proven, so the query has to be able to express both. Without these an agent could read
    # the census and still only page the top of the priority ranking.
    test_status = str(flt.get("test_status") or "").strip().lower()
    auth_state = str(flt.get("auth_state") or "").strip().lower()
    finding_status = str(flt.get("status") or "").strip().lower()
    verified_only = bool(flt.get("verified_only"))
    rows: list[Any] = []
    async with _pool().acquire() as conn:
        if kind == "endpoints":
            rows = await conn.fetch(
                """SELECT method, path, auth_state, test_status, last_verdict, param_shape, content_type, priority_score
                   FROM target_endpoints WHERE target_id=$1 AND COALESCE(test_status,'')<>'gone'
                     AND ($2='' OR path ILIKE '%'||$2||'%') AND ($3='' OR method=$3)
                     AND ($4='' OR lower(COALESCE(test_status,''))=$4)
                     AND ($5='' OR lower(COALESCE(auth_state,''))=$5)
                   ORDER BY priority_score DESC, last_seen_at DESC LIMIT $6""",
                target_uuid, path_contains, method, test_status, auth_state, limit,
            )
        elif kind == "findings":
            rows = await conn.fetch(
                """SELECT title, severity, status, tool, url, last_verification_verdict
                   FROM findings WHERE target_id=$1 AND ($2='' OR severity=$2)
                     AND ($3='' OR lower(COALESCE(status,''))=$3)
                     AND (NOT $4::boolean OR last_verification_verdict='exploited')
                   ORDER BY last_seen_at DESC LIMIT $5""",
                target_uuid, severity, finding_status, verified_only, limit,
            )
        elif kind == "hypotheses":
            rows = await conn.fetch(
                """SELECT family, title, status, confidence, source, dedupe_key
                   FROM hypotheses WHERE target_id=$1 AND ($2='' OR lower(family)=$2)
                   ORDER BY updated_at DESC LIMIT $3""",
                target_uuid, family, limit,
            )
        elif kind == "principals":
            rows = await conn.fetch(
                """SELECT label, role, tenant_id, auth_state, is_active FROM target_principals
                   WHERE target_id=$1 AND is_active=true ORDER BY role, label LIMIT $2""",
                target_uuid, limit,
            )
        elif kind == "graph_nodes":
            rows = await conn.fetch(
                """SELECT node_type, node_key, label FROM application_graph_nodes
                   WHERE target_id=$1 ORDER BY last_seen_at DESC LIMIT $2""",
                target_uuid, limit,
            )
        elif kind == "graph_edges":
            rows = await conn.fetch(
                """SELECT src_key, edge_type, dst_key FROM application_graph_edges
                   WHERE target_id=$1 ORDER BY last_seen_at DESC LIMIT $2""",
                target_uuid, limit,
            )
        elif kind == "tool_receipts":
            rows = await conn.fetch(
                """SELECT tool_name, status, redacted_argv, created_at FROM tool_receipts
                   WHERE target_scope->>'target_id'=$1 ORDER BY created_at DESC LIMIT $2""",
                str(target_uuid), limit,
            )
        elif kind == "notes":
            rows = await conn.fetch(
                """SELECT metadata_json, created_at FROM tool_receipts
                   WHERE tool_name='agent.note' AND target_scope->>'target_id'=$1
                   ORDER BY created_at DESC LIMIT $2""",
                str(target_uuid), limit,
            )
    items = [_arsenal_routes._redact_agent_payload(_json_safe_row(row)) for row in rows]
    return {"ok": True, "kind": kind, "count": len(items), "rows": items}


class HuntCapabilityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: str = Field(
        min_length=8,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    input: dict[str, Any] = Field(default_factory=dict)


def _hunt_confirmed_shell_capability_input(
    plan: Mapping[str, Any],
    request: DeviceAgentShellConfirmRequest,
) -> dict[str, Any]:
    """Bind a confirmation without retaining its user-entered phrase."""
    return {
        "plan_id": str(plan.get("plan_id") or ""),
        "plan_digest": str(plan.get("plan_digest") or ""),
        "confirmation_phrase_sha256": hashlib.sha256(
            str(request.confirmation_phrase).encode("utf-8")
        ).hexdigest(),
        "confirm_exact_commands": bool(request.confirm_exact_commands),
        "confirm_remote_device_effects": bool(
            request.confirm_remote_device_effects
        ),
    }


async def _hunt_confirmed_shell_dispatch(
    conn: Any,
    *,
    device_target_id: Any,
    action_id: Any,
    reservation_id: str,
    action_digest: str,
) -> dict[str, Any] | None:
    """Resolve the one downstream job accepted for a confirmed SSH plan."""
    rows = await conn.fetch(
        """SELECT id, job_id, status, run_kind, target_url, options
           FROM scans
           WHERE device_target_id=$1
             AND options->'hunt_dispatch'->>'hunt_action_id'=$2
             AND options->'hunt_dispatch'->>'budget_reservation_id'=$3
             AND options->'hunt_dispatch'->>'action_digest'=$4
             AND options->'hunt_dispatch'->>'capability_name'=
                 'device.ssh.execute_confirmed'
           ORDER BY created_at DESC LIMIT 2""",
        device_target_id,
        str(action_id),
        str(reservation_id),
        str(action_digest),
    )
    if len(rows) > 1:
        raise RuntimeError(
            "Confirmed SSH action created more than one downstream scan"
        )
    if not rows:
        return None
    row = rows[0]
    if not _devices._scan_queue_handoff_confirmed(row):
        return None
    return {
        "scan_id": str(row["id"]),
        "job_id": str(row["job_id"]),
        "status": "queued",
        "run_kind": str(row["run_kind"]),
        "device_target_id": str(device_target_id),
        "target": str(row["target_url"] or ""),
        "profile": "inventory",
        "safety_profile": "authenticated_active",
        "ui_url": f"/scans/{row['id']}",
    }


def _hunt_ledger_limits(budget: Mapping[str, Any]) -> dict[str, int]:
    return {
        "agent_actions": int(budget.get("max_capability_calls") or 0),
        "active_actions": int(budget.get("max_active_actions") or 0),
        "http_requests": int(budget.get("max_http_requests") or 0),
        "tcp_ports_attempted": int(budget.get("max_tcp_ports") or 0),
        "browser_actions": int(budget.get("max_browser_actions") or 0),
        "state_changing_requests": int(budget.get("max_state_changing_requests") or 0),
        "tool_wall_seconds": int(budget.get("max_duration_seconds") or 0),
        "device_fragility_points": int(budget.get("max_device_fragility_points") or 0),
        "hosts_attempted": int(budget.get("max_hosts") or 0),
        "udp_ports_attempted": int(budget.get("max_udp_ports") or 0),
        "oob_interactions": int(budget.get("max_oob_interactions") or 0),
    }


def _hunt_nonexecuting_actual(
    requested: Mapping[str, int],
) -> dict[str, int]:
    """Charge admission while explicitly releasing every execution hold."""
    actual = {str(dimension): 0 for dimension in requested}
    if "agent_actions" in actual:
        actual["agent_actions"] = min(
            1,
            max(0, int(requested.get("agent_actions") or 0)),
        )
    return actual


async def _execute_hunt_capability_lifecycle(
    hunt_id: str,
    name: str,
    request: HuntCapabilityRequest,
    lifecycle: HuntActionLifecycle,
):
    prepared_network = None
    network_target = None
    network_policy = None
    prepared_browser = None
    browser_target = None
    device_adapter_name = None
    validated_device_input = None
    candidate_record = None
    call_approval_context = None
    spec = lifecycle.specification
    placement = lifecycle.placement
    is_network = placement == "worker_network"
    is_browser = placement == "worker_browser"
    is_http_worker = placement in {"worker_auth", "worker_http"}
    is_scanner = placement == "worker_scanner"
    is_device_control = placement == "device_control"
    is_device_http = placement == "device_http"
    is_device_queue = placement == "device_queue"
    is_device_ssh_proposal = placement == "device_ssh_proposal"
    is_device_adapter = placement in {
        "device_control", "device_http", "device_queue",
        "device_ssh_proposal",
    }
    action_id: uuid.UUID | None = None
    capability_input_digest = hashlib.sha256(json.dumps(
        request.input,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    idempotency_key_digest = hashlib.sha256(
        request.idempotency_key.encode("utf-8")
    ).hexdigest()
    admission_error: HTTPException | None = None
    admission_action_status = "running"
    admission_result_summary: dict[str, Any] = {}
    durable_store = PostgresBudgetReservationStore()
    durable_reservation = None
    durable_action_digest: str | None = None
    durable_worker_id = (
        f"api:{str(os.environ.get('HOSTNAME') or 'local')[:64]}:{os.getpid()}"
    )
    durable_lease_seconds = 120
    async with _pool().acquire() as conn:
        async with conn.transaction():
            run = await _hunt_run_or_404(conn, hunt_id, for_update=True)
            action_id = uuid.uuid5(
                uuid.UUID(str(run["id"])),
                f"hunt-capability:{request.idempotency_key}",
            )
            existing_action = await conn.fetchrow(
                """SELECT capability_name, status, input_summary, result_summary,
                          receipt_id
                   FROM hunt_actions WHERE id=$1 AND hunt_run_id=$2""",
                action_id,
                run["id"],
            )
            if existing_action is not None:
                existing_input = _hunt_json(existing_action["input_summary"], {})
                if (
                    str(existing_action["capability_name"]) != name
                    or str(existing_input.get("input_digest") or "")
                    != capability_input_digest
                    or str(existing_input.get("idempotency_key_sha256") or "")
                    != idempotency_key_digest
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="Hunt idempotency key was already used for another action",
                    )
                existing_summary = _hunt_json(
                    existing_action["result_summary"], {}
                )
                existing_status = str(existing_action["status"])
                lifecycle.mark_replayed()
                return {
                    "hunt_id": hunt_id,
                    "capability": name,
                    "action_id": str(action_id),
                    "idempotent_replay": True,
                    "status": existing_status,
                    "receipt_id": str(existing_action["receipt_id"] or "") or None,
                    "action_result": HuntActionResult(
                        hunt_id=str(run["id"]),
                        action_id=str(action_id),
                        capability_name=name,
                        target_kind=str(run["target_kind"]),
                        placement=placement,
                        status=(
                            "success"
                            if existing_status == "completed"
                            else existing_status
                        ),
                        observations=tuple(
                            dict(item)
                            for item in existing_summary.get("observations") or ()
                            if isinstance(item, Mapping)
                        ),
                        errors=(
                            (str(existing_summary.get("error")),)
                            if existing_summary.get("error")
                            else ()
                        ),
                        actual_budget=dict(
                            existing_summary.get("budget_consumed") or {}
                        ),
                        partial=bool(existing_summary.get("partial")),
                        timed_out=bool(existing_summary.get("timed_out")),
                        parser_version=str(spec.output_schema),
                    ).public_dict(),
                    "result": existing_summary,
                }
            if run["status"] not in {"active", "awaiting_planner"}:
                raise HTTPException(status_code=409, detail=f"Hunt is {run['status']}")
            policy = _hunt_json(run["policy_json"], {})
            context = _hunt_json(run["context_pack"], {})
            target_context = (
                dict(context.get("target") or {})
                if isinstance(context.get("target"), Mapping)
                else {}
            )
            if run["device_target_id"]:
                current_target = await conn.fetchrow(
                    "SELECT primary_locator, is_active FROM device_targets WHERE id=$1",
                    run["device_target_id"],
                )
                frozen_locator = str(target_context.get("locator") or "").strip()
                current_locator = str(
                    current_target["primary_locator"] if current_target else ""
                ).strip()
            else:
                current_target = await conn.fetchrow(
                    "SELECT url, is_active FROM targets WHERE id=$1", run["target_id"],
                )
                frozen_locator = str(target_context.get("url") or "").strip()
                current_locator = str(current_target["url"] if current_target else "").strip()
            if not current_target or not current_target["is_active"]:
                raise HTTPException(status_code=409, detail="Hunt target is no longer active")
            if not frozen_locator or current_locator != frozen_locator:
                raise HTTPException(
                    status_code=409,
                    detail="Hunt target locator changed after admission",
                )
            if name == "candidate.verify":
                candidate_uuid = _uuid_or_400(
                    str(request.input.get("candidate_id") or ""), "candidate id",
                )
                candidate_record = await conn.fetchrow(
                    """SELECT c.* FROM investigation_candidates c
                       WHERE c.id=$1
                         AND (($3::uuid IS NOT NULL AND c.target_id=$3) OR
                              ($4::uuid IS NOT NULL AND c.device_target_id=$4))
                         AND EXISTS (
                             SELECT 1 FROM investigation_candidate_observations o
                             WHERE o.candidate_id=c.id AND o.hunt_run_id=$2
                         )""",
                    candidate_uuid, run["id"], run["target_id"], run["device_target_id"],
                )
                if candidate_record is None:
                    raise HTTPException(
                        status_code=404,
                        detail="Candidate was not produced or observed by this Hunt",
                    )
                if str(candidate_record["status"] or "") in {
                    "verified", "refuted", "expired",
                }:
                    raise HTTPException(
                        status_code=409,
                        detail=f"Candidate is {candidate_record['status']}",
                    )
            allowed = {item["name"] for item in _hunt_public(run, include_context=False)["capabilities"]}
            if name not in allowed:
                raise HTTPException(status_code=403, detail="Capability is not allowed by this Hunt policy")
            principal_slot = (
                agent_tools.normalize_principal_slot(request.input.get("as_principal"))
                if name in {
                    "http.request", "collections.replay_safe", "auth.session.establish",
                }
                else "anonymous"
            )
            if name == "collections.replay_safe":
                principal = _hunt_managed_principal_reference(
                    _hunt_json(run["context_pack"], {}), principal_slot,
                )
                principal_slot = (
                    str(principal["principal_slot"]) if principal is not None else "anonymous"
                )
            if str(run["target_kind"]) == "device" and not name.startswith("collections."):
                device_adapter_name = str(spec.adapter).split(".")[-1]
                validated_device_input = dict(request.input)
            uses_session = bool(
                (
                    name == "http.request"
                    and request.input.get("session_ref")
                )
                or (
                    name == "authz.verify"
                    and request.input.get("primary_session_ref")
                    and request.input.get("secondary_session_ref")
                )
            )
            # Forging a client address is a distinct authority the operator granted, so a
            # call that uses it is metered and re-approved like any other active action.
            # Classifying it by the capability's static risk tier alone let anonymous
            # forged-header requests run to the HTTP ceiling without ever touching
            # max_active_actions, which breaks the multidimensional budget invariant.
            forges_identity = bool(
                agent_tools.IDENTITY_HEADERS & {
                    str(header).strip().lower()
                    for header in (request.input.get("headers") or {})
                }
            ) if isinstance(request.input.get("headers"), Mapping) else False
            # Sending a request to an operator-confirmed origin instead of the target's
            # resolved address is at least as significant as forging a header: it is the
            # act that demonstrates an edge bypass. Left on the capability's passive tier
            # it consumed no active action and was never re-approved per call.
            uses_direct_origin = bool(
                str(request.input.get("via_address") or "").strip()
            )
            requires_call_approval = (
                spec.requires_active_approval
                or principal_slot != "anonymous"
                or uses_session
                or forges_identity
                or uses_direct_origin
            )
            if requires_call_approval:
                authority_context = _hunt_json(run["context_pack"], {})
                target_context = authority_context.get("target") if isinstance(authority_context.get("target"), Mapping) else {}
                target_url = str(target_context.get("url") or target_context.get("locator") or "")
                call_approval_context = await _validate_approval_receipt_for_action(
                    conn, policy.get("approval_receipt_id"), target_url=target_url,
                    target_id=run["target_id"] or run["device_target_id"], action_name=f"hunt.capability:{name}",
                    command=name, risk_tier=(
                        "credential" if principal_slot != "anonymous" or uses_session
                        else "active" if forges_identity or uses_direct_origin
                        else str(spec.risk_tier)
                    ), always_require_receipt=True,
                    require_target_binding=True,
                    require_expiry=True, created_by=f"hunt_v2:{hunt_id}",
                )
            validated_scope_receipt_id = str(policy.get("scope_receipt_id") or "") or None
            if call_approval_context:
                current_scope_receipt_id = str(
                    call_approval_context.get("scope_receipt_id") or ""
                ) or None
                if (
                    validated_scope_receipt_id
                    and current_scope_receipt_id != validated_scope_receipt_id
                ):
                    raise HTTPException(
                        status_code=403,
                        detail="Hunt approval scope no longer matches its admitted policy",
                    )
                validated_scope_receipt_id = current_scope_receipt_id
            used = _hunt_json(run["budget_used_json"], {})
            budget = _hunt_json(run["budget_json"], {})
            if name == "candidate.verify":
                if int(used.get("verifications") or 0) >= int(
                    budget.get("max_verifications") or 0
                ):
                    raise HTTPException(
                        status_code=409, detail="Hunt verification budget exhausted",
                    )
                used["verifications"] = int(used.get("verifications") or 0) + 1
            limits = _hunt_ledger_limits(budget)
            if is_network:
                authority_context = _hunt_json(run["context_pack"], {})
                target_context = authority_context.get("target") if isinstance(authority_context.get("target"), Mapping) else {}
                target_url = str(target_context.get("url") or "")
                parsed_target = urllib.parse.urlsplit(target_url)
                root_domain = str(target_context.get("root_domain") or parsed_target.hostname or "").lower().rstrip(".")
                try:
                    network_target = TargetBinding(
                        target_id=str(run["target_id"]), target_kind=str(run["target_kind"]),
                        canonical_host=parsed_target.hostname,
                        allowed_origins=tuple(target_context.get("origins") or ()),
                        allowed_addresses=tuple(authority_context.get("authorized_target_addresses") or ()),
                        allowed_root_domains=(root_domain,) if root_domain else (),
                        environment=str(target_context.get("environment") or "unknown"),
                        scope_receipt_id=validated_scope_receipt_id,
                    )
                    network_policy = ScanPolicy(
                        active_testing=bool(policy.get("active_testing")),
                        network_discovery=bool(policy.get("network_discovery")),
                        subdomain_discovery=name == "subdomains.discover",
                        scope_receipt_id=validated_scope_receipt_id,
                        approval_receipt_id=policy.get("approval_receipt_id"),
                    )
                    prepared_network = network_capability_adapter(name).prepare(
                        target=network_target, args=request.input, policy=network_policy,
                    )
                except (CapabilityInputError, ValueError) as exc:
                    raise HTTPException(status_code=422, detail=str(exc)) from exc
                charges = {
                    key: int(value) for key, value in prepared_network.estimated_budget.items()
                    if key in limits
                }
            elif is_browser:
                authority_context = _hunt_json(run["context_pack"], {})
                target_context = (
                    authority_context.get("target")
                    if isinstance(authority_context.get("target"), Mapping)
                    else {}
                )
                target_url = str(target_context.get("url") or "")
                parsed_target = urllib.parse.urlsplit(target_url)
                root_domain = str(
                    target_context.get("root_domain")
                    or parsed_target.hostname
                    or ""
                ).lower().rstrip(".")
                try:
                    browser_target = TargetBinding(
                        target_id=str(run["target_id"]),
                        target_kind=str(run["target_kind"]),
                        canonical_host=parsed_target.hostname,
                        allowed_origins=tuple(target_context.get("origins") or ()),
                        allowed_addresses=tuple(
                            authority_context.get("authorized_target_addresses") or ()
                        ),
                        allowed_root_domains=(root_domain,) if root_domain else (),
                        environment=str(target_context.get("environment") or "unknown"),
                        scope_receipt_id=validated_scope_receipt_id,
                    )
                    prepared_browser = browser_capability_adapter(name).prepare(
                        target=browser_target,
                        base_url=target_url,
                        args=request.input,
                    )
                except (BrowserCapabilityInputError, ValueError) as exc:
                    raise HTTPException(status_code=422, detail=str(exc)) from exc
                charges = {
                    key: int(value)
                    for key, value in prepared_browser.estimated_budget.items()
                    if key in limits
                }
            else:
                charges = {
                    key: int(value) for key, value in spec.budget_cost.items() if key in limits
                }
                if name == "candidate.verify":
                    assert candidate_record is not None
                    if str(run["target_kind"]) == "device":
                        contract_id = str(
                            candidate_record["verifier_contract_id"] or ""
                        )
                        # A device verification performs no traffic itself: it queues a device scan
                        # that sweeps the inventory profile's ports and may fan out to web children
                        # with their own imported-request ceilings. A flat parent charge let a small
                        # reservation authorize all of it, so the Hunt's budget bound the parent
                        # action and nothing beneath it. Charge the complete fan-out instead, derived
                        # from the same constants it uses, so an unaffordable fan-out is refused at
                        # reservation rather than discovered as downstream traffic.
                        charges.update(device_agent.device_verification_fanout_budget(
                            contract_id=contract_id,
                            web_scan_type=_DEVICE_VERIFICATION_WEB_SCAN_TYPE,
                            max_web_origins=(
                                _DEVICE_VERIFICATION_MAX_WEB_ORIGINS
                                if contract_id in _DEVICE_VERIFICATION_WEB_CONTRACTS
                                else 0
                            ),
                        ))
                        if contract_id == "device.service_exposure":
                            locus = _hunt_json(
                                candidate_record["canonical_locus"], {}
                            )
                            transport_dimension = (
                                "udp_ports_attempted"
                                if str(locus.get("transport") or "").lower() == "udp"
                                else "tcp_ports_attempted"
                            )
                            charges[transport_dimension] = 1
                    else:
                        charges["http_requests"] = 24
                        charges["browser_actions"] = 12
                        family = family_proof.canonical_family(
                            candidate_record["family"]
                        )
                        if family in _AGENT_MUTATING_VERIFY_FAMILIES:
                            if not policy.get("allow_state_changing_http"):
                                raise HTTPException(
                                    status_code=403,
                                    detail=(
                                        "Candidate verification requires state-changing "
                                        "HTTP authority for this proof family"
                                    ),
                                )
                            charges["state_changing_requests"] = 12
                if name == "http.request" and request.input.get("follow_redirects") is True:
                    # Reserve the complete same-origin redirect envelope before the
                    # first request. The planner cannot expand this fixed server limit.
                    charges["http_requests"] = 1 + MAX_REDIRECT_HOPS
                if validated_device_input is not None and device_adapter_name is not None:
                    # An SSH proposal is control-plane-only. The exact user-
                    # confirmed execution owns device fragility; proposing an
                    # immutable plan must not consume or block on it.
                    fragility_cost = (
                        0
                        if is_device_ssh_proposal
                        else device_agent.tool_fragility_cost(
                            device_adapter_name, validated_device_input,
                        )
                    )
                    if fragility_cost:
                        charges["device_fragility_points"] = fragility_cost
                    if name == "device.service.verify":
                        transport_dimension = (
                            "udp_ports_attempted"
                            if validated_device_input.get("transport") == "udp"
                            else "tcp_ports_attempted"
                        )
                        charges.pop(
                            "tcp_ports_attempted"
                            if transport_dimension == "udp_ports_attempted"
                            else "udp_ports_attempted",
                            None,
                        )
                        charges[transport_dimension] = 1
                    if fragility_cost:
                        legacy_daily = int(await conn.fetchval(
                            """SELECT COALESCE(SUM(fragility_cost),0) FROM device_agent_actions
                               WHERE device_target_id=$1 AND outcome <> 'blocked'
                                 AND created_at >= date_trunc('day', NOW())""",
                            run["device_target_id"],
                        ) or 0)
                        hunt_daily = int(await conn.fetchval(
                            """SELECT COALESCE(SUM(COALESCE((budget_used_json->>'device_fragility_points')::int,0)),0)
                               FROM hunt_runs WHERE device_target_id=$1
                                 AND created_at >= date_trunc('day', NOW())""",
                            run["device_target_id"],
                        ) or 0)
                        if legacy_daily + hunt_daily + fragility_cost > device_agent.MAX_FRAGILITY_PER_DEVICE_DAY:
                            raise HTTPException(status_code=409, detail="Daily fragility budget for this device is exhausted")
            charges["agent_actions"] = 1
            if requires_call_approval:
                charges["active_actions"] = 1
            if is_device_adapter:
                authority_context = _hunt_json(run["context_pack"], {})
                try:
                    device_policy_state = DeviceHuntPolicyState.from_mapping(
                        authority_context.get("device_policy_state") or {}
                    )
                    device_policy_state.require_admission(
                        request_attempts=1 if is_device_http else 0,
                        scan_attempts=1 if is_device_queue else 0,
                        fragility_cost=int(
                            charges.get("device_fragility_points") or 0
                        ),
                    )
                except ValueError as exc:
                    raise HTTPException(status_code=409, detail=str(exc)) from exc
            lifecycle.advance("revalidated")
            worker_managed_budget = spec.hunt_executor == "worker_replay"
            worker_durable_budget = spec.hunt_executor in {
                "worker_network", "worker_scanner", "worker_browser",
                "worker_auth", "worker_http",
            }
            api_managed_budget = spec.hunt_executor in {
                "inline", "device_control", "device_http", "device_queue",
                "device_ssh_proposal",
            }
            durable_budget = api_managed_budget or worker_durable_budget
            if worker_managed_budget:
                durable_action_digest = hunt_capability_action_digest(
                    hunt_id=run["id"],
                    action_id=action_id,
                    capability_name=name,
                    target_kind=str(run["target_kind"]),
                    target_id=run["device_target_id"] or run["target_id"],
                    capability_input=request.input,
                    requested_budget=charges,
                    scope_receipt_id=validated_scope_receipt_id,
                    approval_receipt_id=policy.get("approval_receipt_id"),
                )
            if is_device_http:
                await conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                    f"device-http:{run['device_target_id']}",
                )
                device_http_in_flight = await conn.fetchval(
                    """SELECT EXISTS(
                           SELECT 1
                           FROM budget_reservations r
                           JOIN hunt_runs h
                             ON r.owner_kind='hunt' AND r.owner_id=h.id::text
                           WHERE h.device_target_id=$1
                             AND r.capability_name='device.http.probe'
                             AND r.status IN ('reserved','running')
                       )""",
                    run["device_target_id"],
                )
                if device_http_in_flight:
                    raise HTTPException(
                        status_code=409,
                        detail="A device HTTP probe is already in flight for this Hunt",
                    )
            if is_device_ssh_proposal:
                ssh_proposal_in_flight = await conn.fetchval(
                    """SELECT EXISTS(
                           SELECT 1 FROM budget_reservations
                           WHERE owner_kind='hunt' AND owner_id=$1
                             AND capability_name='device.ssh.propose'
                             AND status IN ('reserved','running')
                       )""",
                    str(run["id"]),
                )
                if ssh_proposal_in_flight:
                    raise HTTPException(
                        status_code=409,
                        detail="An SSH proposal is already in flight for this Hunt",
                    )
            if durable_budget:
                durable_action_digest = hunt_capability_action_digest(
                    hunt_id=run["id"],
                    action_id=action_id,
                    capability_name=name,
                    target_kind=str(run["target_kind"]),
                    target_id=run["device_target_id"] or run["target_id"],
                    capability_input=request.input,
                    requested_budget=charges,
                    scope_receipt_id=validated_scope_receipt_id,
                    approval_receipt_id=policy.get("approval_receipt_id"),
                )
                requested_reservation = DurableBudgetReservation.request(
                    owner_kind="hunt",
                    owner_id=str(run["id"]),
                    capability_name=name,
                    amounts=charges,
                )
                stored_reservation = await durable_store.create_requested(
                    conn,
                    action_id=str(action_id),
                    action_digest=durable_action_digest,
                    record=requested_reservation,
                )
                if stored_reservation.record.status != "requested":
                    raise HTTPException(
                        status_code=409,
                        detail="Hunt capability reservation is already active",
                    )
                durable_lease_seconds = hunt_capability_lease_seconds(charges)
                try:
                    reserved_record, reserved_used = (
                        stored_reservation.record.reserve_against(
                            limits=limits,
                            consumed={
                                key: int(used.get(key) or 0) for key in limits
                            },
                            lease_seconds=durable_lease_seconds,
                        )
                    )
                except BudgetExceeded as exc:
                    released = stored_reservation.record.release(
                        proof_not_started=True,
                        reason="budget_exhausted_before_execution",
                    )
                    await durable_store.persist_terminal(
                        conn,
                        previous=stored_reservation,
                        terminal=released,
                        ledger_after_settlement={
                            key: int(used.get(key) or 0) for key in limits
                        },
                        receipt=None,
                    )
                    dimension = next(iter(exc.shortages), "unknown")
                    await conn.execute(
                        "UPDATE hunt_runs SET status='budget_exhausted', "
                        "stop_reason=$2, updated_at=NOW() WHERE id=$1",
                        run["id"],
                        f"budget_exhausted:{dimension}",
                    )
                    admission_error = HTTPException(
                        status_code=409,
                        detail=f"Hunt budget exhausted: {dimension}",
                    )
                    admission_action_status = "failed"
                    admission_result_summary = {
                        "error": f"budget_exhausted:{dimension}",
                        "budget_reservation_id": released.reservation_id,
                        "budget_reservation_state": released.status,
                    }
                else:
                    durable_reservation = await durable_store.persist_transition(
                        conn,
                        previous=stored_reservation,
                        current=reserved_record,
                        ledger_after_hold=reserved_used,
                    )
                    used.update(reserved_used)
                    await conn.execute(
                        "UPDATE hunt_runs SET budget_used_json=$2, status='active', "
                        "updated_at=NOW() WHERE id=$1",
                        run["id"],
                        json.dumps(used),
                    )
                    admission_action_status = "reserved"
            elif not worker_managed_budget:
                try:
                    reserved_used = reserve_budget_snapshot(
                        limits, {key: int(used.get(key) or 0) for key in limits}, charges,
                    )
                except BudgetExceeded as exc:
                    dimension = next(iter(exc.shortages), "unknown")
                    await conn.execute(
                        "UPDATE hunt_runs SET status='budget_exhausted', stop_reason=$2, updated_at=NOW() WHERE id=$1",
                        run["id"], f"budget_exhausted:{dimension}",
                    )
                    admission_error = HTTPException(
                        status_code=409,
                        detail=f"Hunt budget exhausted: {dimension}",
                    )
                    admission_action_status = "failed"
                    admission_result_summary = {
                        "error": f"budget_exhausted:{dimension}",
                    }
                else:
                    used.update(reserved_used)
                    await conn.execute("UPDATE hunt_runs SET budget_used_json=$2, status='active', updated_at=NOW() WHERE id=$1", run["id"], json.dumps(used))
            await conn.execute(
                """INSERT INTO hunt_actions (
                       id, hunt_run_id, capability_name, status, input_summary,
                       result_summary, completed_at
                   ) VALUES ($1,$2,$3,$4,$5,$6,
                             CASE WHEN $4='failed' THEN NOW() ELSE NULL END)""",
                action_id, run["id"], name,
                admission_action_status,
                json.dumps({
                    "schema_version": "hunt-capability-input-summary/v1",
                    "input": _hunt_redacted_capability_input(name, request.input),
                    "input_digest": capability_input_digest,
                    "idempotency_key_sha256": idempotency_key_digest,
                }),
                json.dumps(admission_result_summary),
            )

    lifecycle.advance("admitted")
    assert action_id is not None
    if admission_error is not None:
        raise admission_error

    if api_managed_budget:
        if durable_reservation is None or durable_action_digest is None:
            raise HTTPException(
                status_code=500,
                detail="Hunt capability reservation was not initialized",
            )
        async with _pool().acquire() as conn:
            async with conn.transaction():
                dispatch_run = await _hunt_run_or_404(conn, hunt_id, for_update=True)
                if dispatch_run["status"] not in {
                    "active", "awaiting_planner", "budget_exhausted"
                }:
                    raise HTTPException(
                        status_code=409,
                        detail=f"Hunt is {dispatch_run['status']}",
                    )
                latest_reservation = await durable_store.load(
                    conn,
                    durable_reservation.record.reservation_id,
                    for_update=True,
                )
                if (
                    latest_reservation is None
                    or latest_reservation.record.state_digest
                    != durable_reservation.record.state_digest
                    or latest_reservation.record.status != "reserved"
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="Hunt capability reservation changed before dispatch",
                    )
                running_reservation = latest_reservation.record.start(
                    worker_id=durable_worker_id,
                    lease_seconds=durable_lease_seconds,
                )
                durable_reservation = await durable_store.persist_transition(
                    conn,
                    previous=latest_reservation,
                    current=running_reservation,
                )
                updated_action = await conn.execute(
                    """UPDATE hunt_actions
                       SET status='running', started_at=NOW()
                       WHERE id=$1 AND hunt_run_id=$2 AND status='reserved'""",
                    action_id,
                    dispatch_run["id"],
                )
                if not str(updated_action).endswith(" 1"):
                    raise HTTPException(
                        status_code=409,
                        detail="Hunt capability action changed before dispatch",
                    )

    lifecycle.advance("dispatching")
    context = _hunt_json(run["context_pack"], {})

    def inline_web_target_binding() -> TargetBinding:
        target_context = (
            dict(context.get("target") or {})
            if isinstance(context.get("target"), Mapping)
            else {}
        )
        target_url = str(target_context.get("url") or "")
        parsed_target = urllib.parse.urlsplit(target_url)
        root_domain = str(
            target_context.get("root_domain")
            or parsed_target.hostname
            or ""
        ).lower().rstrip(".")
        return TargetBinding(
            target_id=str(run["target_id"]),
            target_kind=str(run["target_kind"]),
            canonical_host=parsed_target.hostname,
            allowed_origins=tuple(target_context.get("origins") or ()),
            allowed_addresses=tuple(
                str(item)
                for item in context.get("authorized_target_addresses") or ()
                if str(item)
            ),
            allowed_root_domains=(root_domain,) if root_domain else (),
            environment=str(target_context.get("environment") or "unknown"),
            scope_receipt_id=validated_scope_receipt_id,
        )

    def inline_device_target_binding() -> TargetBinding:
        target_context = (
            dict(context.get("target") or {})
            if isinstance(context.get("target"), Mapping)
            else {}
        )
        locator = str(target_context.get("locator") or "").strip()
        return TargetBinding(
            target_id=str(run["device_target_id"]),
            target_kind="device",
            canonical_host=locator,
            environment=str(target_context.get("environment") or "unknown"),
            scope_receipt_id=validated_scope_receipt_id,
        )

    def inline_hunt_target_binding() -> TargetBinding:
        return (
            inline_device_target_binding()
            if str(run["target_kind"]) == "device"
            else inline_web_target_binding()
        )

    async def dispatch_registered_adapter(
        adapter: Any,
        *,
        target: TargetBinding,
        requested_budget: Mapping[str, int],
        adapter_managed_cancellation: bool = False,
    ) -> Any:
        """Execute a local adapter through the same native Hunt dispatcher."""
        action_request = HuntActionRequest(
            hunt_id=str(run["id"]),
            action_id=str(action_id),
            capability_name=name,
            target=target,
            capability_input=request.input,
            requested_budget=requested_budget,
            reservation_id=(
                durable_reservation.record.reservation_id
                if durable_reservation is not None
                else None
            ),
            action_digest=durable_action_digest,
        )
        factory = RegisteredHuntAdapterFactory({
            spec.adapter: lambda _spec, _request: adapter,
        })
        # Prime once before dispatch: the executor's pre-execution barrier is the only chance to
        # stop an adapter that never heartbeats, and a Hunt cancelled while this action queued
        # must not reach the target at all.
        watch = HuntCancellationWatch(_pool, run["id"])
        await watch.refresh(force=True)
        return await HUNT_ACTION_DISPATCHER.execute(
            action_request,
            factory,
            heartbeat=watch.heartbeat(),
            cancelled=watch.cancelled,
            adapter_managed_cancellation=adapter_managed_cancellation,
        )

    async def inspect_bound_collections() -> dict[str, Any]:
        refs = [
            dict(item)
            for item in context.get("request_collections") or []
            if isinstance(item, Mapping)
        ]
        return {
            "ok": True,
            "collections": refs[:200],
            "count": len(refs),
            "secret_values_visible": False,
        }

    device_adapter_state: dict[str, Any] | None = None
    if is_device_adapter:
        try:
            native_device_policy = DeviceHuntPolicyState.from_mapping(
                context.get("device_policy_state") or {}
            )
        except ValueError as exc:
            # Historical device-agent state is readable through its legacy
            # routes, but it never becomes executable authority for V2 Hunt.
            raise HTTPException(
                status_code=409,
                detail="Native device Hunt policy state is unavailable",
            ) from exc
        device_adapter_state = native_device_policy.adapter_state(
            credential_refs=[
                dict(item)
                for item in context.get("credential_refs") or []
                if isinstance(item, Mapping)
            ],
            collection_refs=[
                dict(item)
                for item in context.get("request_collections") or []
                if isinstance(item, Mapping)
            ],
            runtime=(
                context.get("device_runtime")
                if isinstance(context.get("device_runtime"), Mapping)
                else {}
            ),
            allow_state_changing_requests=bool(
                policy.get("allow_state_changing_http")
            ),
        )

    device_adapter_state_before = (
        copy.deepcopy(device_adapter_state)
        if device_adapter_state is not None
        else {}
    )
    execution_started = time.perf_counter()
    status, result = "failed", {}
    capability_execution = None
    try:
        if name == "candidate.verify":
            assert candidate_record is not None

            async def verify_hunt_candidate_operation() -> dict[str, Any]:
                verification = await _execute_hunt_candidate_verification(
                    run=run,
                    context=context,
                    policy=policy,
                    candidate_uuid=_uuid_or_400(
                        str(request.input.get("candidate_id") or ""), "candidate id",
                    ),
                )
                return {
                    "ok": True,
                    "status": "success",
                    "candidate_id": str(request.input["candidate_id"]),
                    "verification": verification,
                }

            candidate_adapter = ControlPlaneExecutionAdapter(
                specification=spec,
                operation=verify_hunt_candidate_operation,
                requested_budget=durable_reservation.record.requested,
                redacted_execution=_hunt_redacted_capability_input(
                    name, request.input,
                ),
                blocked_exceptions=(HTTPException,),
                conservative_full_budget=True,
            )
            capability_execution = await dispatch_registered_adapter(
                candidate_adapter,
                target=inline_hunt_target_binding(),
                requested_budget=durable_reservation.record.requested,
            )
            result = candidate_adapter.result
            if candidate_adapter.blocked_exception is not None:
                raise candidate_adapter.blocked_exception
        elif name == "collections.inspect":
            collection_adapter = ControlPlaneExecutionAdapter(
                specification=spec,
                operation=inspect_bound_collections,
                requested_budget=durable_reservation.record.requested,
                redacted_execution={},
                blocked_exceptions=(HTTPException,),
            )
            capability_execution = await dispatch_registered_adapter(
                collection_adapter,
                target=inline_hunt_target_binding(),
                requested_budget=durable_reservation.record.requested,
            )
            result = collection_adapter.result
        elif name == "collections.select":
            collection_adapter = ControlPlaneExecutionAdapter(
                specification=spec,
                operation=lambda: _hunt_select_collection(
                    run, context, request.input,
                ),
                requested_budget=durable_reservation.record.requested,
                redacted_execution=_hunt_redacted_capability_input(
                    name, request.input,
                ),
                blocked_exceptions=(HTTPException,),
            )
            capability_execution = await dispatch_registered_adapter(
                collection_adapter,
                target=inline_hunt_target_binding(),
                requested_budget=durable_reservation.record.requested,
            )
            result = collection_adapter.result
            if collection_adapter.blocked_exception is not None:
                raise collection_adapter.blocked_exception
        elif name == "collections.replay_safe":
            if durable_action_digest is None:
                raise RuntimeError("Replay action digest was not initialized")
            result = await _enqueue_hunt_replay_capability(
                run,
                context,
                request.input,
                action_id=action_id,
                action_digest=durable_action_digest,
            )
        elif str(run["target_kind"]) == "device":
            assert device_adapter_name is not None and validated_device_input is not None
            device_state = device_adapter_state
            if not isinstance(device_state, dict):
                raise HTTPException(
                    status_code=409,
                    detail="Native device Hunt adapter state is unavailable",
                )
            queue_correlation_token = None
            if is_device_queue:
                if durable_reservation is None or durable_action_digest is None:
                    raise RuntimeError(
                        "Device queue reservation disappeared before dispatch"
                    )
                queue_correlation_token = _devices._HUNT_DEVICE_QUEUE_CORRELATION.set({
                    "schema_version": "hunt-device-dispatch/v1",
                    "hunt_id": str(run["id"]),
                    "hunt_action_id": str(action_id),
                    "budget_reservation_id": (
                        durable_reservation.record.reservation_id
                    ),
                    "action_digest": durable_action_digest,
                    "capability_name": name,
                })
            try:
                device_adapter = DeviceExecutionAdapter(
                    specification=spec,
                    operation=lambda: _devices._execute_device_capability_operation(
                        run_id=run["id"],
                        device_target_id=run["device_target_id"],
                        safety_profile=str(
                            policy.get("device_fragility_profile")
                            or "safe_remote"
                        ),
                        approval_receipt_id=policy.get("approval_receipt_id"),
                        state=device_state,
                        name=device_adapter_name,
                        args=validated_device_input,
                    ),
                    requested_budget=(
                        durable_reservation.record.requested
                        if durable_reservation is not None
                        else charges
                    ),
                    redacted_execution=_hunt_redacted_capability_input(
                        name, validated_device_input,
                    ),
                    state=device_state,
                    blocked_exceptions=(HTTPException,),
                )
                capability_execution = await dispatch_registered_adapter(
                    device_adapter,
                    target=inline_device_target_binding(),
                    requested_budget=(
                        durable_reservation.record.requested
                        if durable_reservation is not None
                        else charges
                    ),
                )
                result = device_adapter.result
                if device_adapter.blocked_exception is not None:
                    raise device_adapter.blocked_exception
            finally:
                if queue_correlation_token is not None:
                    _devices._HUNT_DEVICE_QUEUE_CORRELATION.reset(
                        queue_correlation_token
                    )
        elif is_http_worker:
            if durable_reservation is None or durable_action_digest is None:
                raise RuntimeError(
                    "HTTP capability reservation was not initialized"
                )
            result = await _enqueue_canonical_http_capability(
                capability_name=name,
                capability_input=request.input,
                expected_budget=durable_reservation.record.requested,
                timeout_ms=int(spec.default_timeout_ms),
                hunt_id=str(run["id"]),
                action_id=str(action_id),
                reservation_id=durable_reservation.record.reservation_id,
                action_digest=durable_action_digest,
            )
        elif is_browser:
            if (
                durable_reservation is None
                or durable_action_digest is None
                or prepared_browser is None
                or browser_target is None
            ):
                raise RuntimeError(
                    "Browser capability reservation was not initialized"
                )
            result = await _enqueue_canonical_browser_capability(
                capability_name=name,
                capability_input=request.input,
                expected_input_digest=prepared_browser.input_digest,
                expected_budget=prepared_browser.estimated_budget,
                timeout_ms=max(
                    1_000,
                    int(
                        prepared_browser.estimated_budget.get(
                            "tool_wall_seconds"
                        ) or 1
                    ) * 1_000,
                ),
                hunt_id=str(run["id"]),
                action_id=str(action_id),
                reservation_id=durable_reservation.record.reservation_id,
                action_digest=durable_action_digest,
            )
        elif is_network:
            assert prepared_network is not None and network_target is not None and network_policy is not None
            if durable_reservation is None or durable_action_digest is None:
                raise RuntimeError("Network capability reservation was not initialized")
            result = await _enqueue_canonical_network_capability(
                capability_name=name, capability_input=request.input,
                expected_input_digest=prepared_network.input_digest,
                expected_budget=prepared_network.estimated_budget,
                timeout_ms=max(1_000, int(prepared_network.estimated_budget.get("tool_wall_seconds") or 1) * 1_000),
                hunt_id=str(run["id"]), action_id=str(action_id),
                reservation_id=durable_reservation.record.reservation_id,
                action_digest=durable_action_digest,
            )
        elif is_scanner:
            if durable_reservation is None or durable_action_digest is None:
                raise RuntimeError(
                    "Scanner capability reservation was not initialized"
                )
            result = await _enqueue_canonical_scanner_capability(
                capability_name=name,
                capability_input=request.input,
                timeout_ms=int(spec.default_timeout_ms),
                hunt_id=str(run["id"]),
                action_id=str(action_id),
                reservation_id=durable_reservation.record.reservation_id,
                action_digest=durable_action_digest,
            )
        elif name == "tls.inspect":
            tls_target = inline_web_target_binding()
            tls_budget = (
                durable_reservation.record.requested
                if durable_reservation is not None
                else charges
            )
            tls_adapter = TlsInspectionExecutionAdapter(
                specification=spec,
                operation=lambda: inspect_tls_origin(
                    str(context["target"]["url"]),
                    target=tls_target,
                    timeout_seconds=int(
                        tls_budget.get("tool_wall_seconds") or 1
                    ),
                ),
                requested_budget=tls_budget,
                redacted_execution=_hunt_redacted_capability_input(
                    name, request.input,
                ),
            )
            capability_execution = await dispatch_registered_adapter(
                tls_adapter,
                target=tls_target,
                requested_budget=tls_budget,
            )
            result = tls_adapter.result
        else:
            raise HTTPException(status_code=422, detail="Capability adapter is not executable")
        if capability_execution is not None:
            status = (
                "completed"
                if capability_execution.status == "success"
                else capability_execution.status
            )
        elif result.get("status") == "cancelled":
            status = "cancelled"
        elif result.get("partial") or result.get("status") == "partial":
            status = "partial"
        else:
            status = "completed" if result.get("ok") or result.get("status") in {"success", "queued"} else "failed"
    except HTTPException:
        status = "blocked"
        raise
    except Exception as exc:
        status = "failed"
        result = {"ok": False, "error": f"capability_fault:{type(exc).__name__}"}
    finally:
        lifecycle.advance("persisting")
        async with _pool().acquire() as conn:
            receipt_id = None
            receipt_payload = locals().get("result", {})
            device_queue_state_advanced = bool(
                is_device_queue
                and int(
                    (device_adapter_state or {}).get("scans_queued") or 0
                )
                > int(
                    device_adapter_state_before.get("scans_queued")
                    or 0
                )
            )
            device_queue_enqueued = device_queue_state_advanced
            if is_device_queue:
                correlated_scans = await conn.fetch(
                    """SELECT id, job_id, status, run_kind, options
                       FROM scans
                       WHERE device_target_id=$1
                         AND options->'hunt_dispatch'->>'hunt_action_id'=$2
                         AND options->'hunt_dispatch'->>'capability_name'=$3
                       ORDER BY created_at DESC LIMIT 2""",
                    run["device_target_id"],
                    str(action_id),
                    name,
                )
                if len(correlated_scans) > 1:
                    raise RuntimeError(
                        "Device queue action created more than one downstream scan"
                    )
                correlated_scan = correlated_scans[0] if correlated_scans else None
                device_queue_enqueued = bool(
                    correlated_scan
                    and _devices._scan_queue_handoff_confirmed(correlated_scan)
                )
                if device_queue_state_advanced and not device_queue_enqueued:
                    raise RuntimeError(
                        "Device queue reported success without a downstream scan"
                    )
                if device_queue_enqueued and not device_queue_state_advanced:
                    device_state = dict(device_adapter_state or {})
                    device_state["scans_queued"] = (
                        int(device_state.get("scans_queued") or 0) + 1
                    )
                    device_adapter_state = device_state
                    recovered_queue = {
                        "scan_id": str(correlated_scan["id"]),
                        "job_id": str(correlated_scan["job_id"]),
                        "status": "queued",
                        "run_kind": str(correlated_scan["run_kind"]),
                        "device_target_id": str(run["device_target_id"]),
                    }
                    result = {
                        "ok": True,
                        "queued": recovered_queue,
                        "partial": True,
                        "audit_warning": (
                            "Downstream device job was queued before response "
                            "finalization failed"
                        ),
                    }
                    receipt_payload = result
                    status = "partial"
            proposed_ssh_plan: dict[str, Any] | None = None
            if is_device_ssh_proposal:
                try:
                    proposed_ssh_plan = _hunt_device_ssh_proposal_delta(
                        device_adapter_state_before,
                        device_adapter_state or {},
                        receipt_payload if isinstance(receipt_payload, Mapping) else {},
                        hunt_id=run["id"],
                        device_target_id=run["device_target_id"],
                    )
                except (TypeError, ValueError):
                    logger.exception(
                        "SSH proposal did not produce one receipt-bound immutable plan",
                        extra={"hunt_id": hunt_id, "action_id": str(action_id)},
                    )
                    status = "failed"
                    result = {
                        "ok": False,
                        "error": "ssh_proposal_receipt_mismatch",
                    }
                    receipt_payload = result
            device_ssh_plan_proposed = proposed_ssh_plan is not None
            device_http_attempted = bool(
                is_device_http
                and int(
                    (device_adapter_state or {}).get(
                        "device_http_requests_used"
                    )
                    or 0
                )
                > int(
                    device_adapter_state_before.get(
                        "device_http_requests_used"
                    )
                    or 0
                )
            )
            actual_charges: dict[str, int] = {"agent_actions": 1}
            if requires_call_approval:
                actual_charges["active_actions"] = 1
            measured = (
                receipt_payload.get("budget_consumed")
                if isinstance(receipt_payload, dict) and isinstance(receipt_payload.get("budget_consumed"), Mapping)
                else {}
            )
            for dimension, amount in measured.items():
                if dimension in charges:
                    actual_charges[dimension] = min(int(charges[dimension]), max(0, int(amount)))
            if capability_execution is not None:
                actual_charges = dict(capability_execution.actual_budget)
            elapsed_wall = max(0, math.ceil(time.perf_counter() - execution_started))
            if (
                api_managed_budget
                and capability_execution is None
                and (status != "blocked" or device_http_attempted)
                and "tool_wall_seconds" in charges
            ):
                actual_charges["tool_wall_seconds"] = min(
                    int(charges["tool_wall_seconds"]), max(1, elapsed_wall),
                )
            if (
                is_device_queue
                and device_queue_enqueued
            ):
                for dimension in (
                    "tcp_ports_attempted",
                    "udp_ports_attempted",
                    "device_fragility_points",
                ):
                    if dimension in charges:
                        actual_charges[dimension] = int(charges[dimension])
            if status == "blocked":
                actual_charges = _hunt_blocked_actual(
                    charges,
                    actual_charges,
                    executed=capability_execution is not None,
                    enqueued=bool(device_queue_enqueued),
                    device_http_attempted=bool(device_http_attempted),
                    elapsed_wall=elapsed_wall,
                )
            if (
                is_device_queue
                and not device_queue_enqueued
            ):
                actual_charges = _hunt_nonexecuting_actual(charges)
            elif (
                is_device_ssh_proposal
                and not device_ssh_plan_proposed
            ):
                actual_charges = _hunt_nonexecuting_actual(charges)
            elif is_device_ssh_proposal:
                actual_charges["tool_wall_seconds"] = min(
                    int(charges.get("tool_wall_seconds") or 0),
                    max(1, elapsed_wall),
                )
            elif is_device_http:
                actual_charges["http_requests"] = min(
                    1 if device_http_attempted else 0,
                    int(charges.get("http_requests") or 0),
                )
                actual_charges["device_fragility_points"] = min(
                    1 if device_http_attempted else 0,
                    int(charges.get("device_fragility_points") or 0),
                )
            elif name == "http.request" and capability_execution is None:
                followed = max(
                    0,
                    min(
                        MAX_REDIRECT_HOPS,
                        int(
                            (receipt_payload.get("hops_followed") or 0)
                            if isinstance(receipt_payload, Mapping) else 0
                        ),
                    ),
                )
                actual_charges["http_requests"] = min(
                    int(charges.get("http_requests") or 0), 1 + followed,
                )
            elif name == "collections.replay_safe" and isinstance(receipt_payload, dict):
                actual_charges["http_requests"] = min(
                    int(charges.get("http_requests") or 0), max(0, int(receipt_payload.get("replayed") or 0)),
                )
                actual_charges["tool_wall_seconds"] = min(int(charges.get("tool_wall_seconds") or 0), elapsed_wall)
            if is_device_adapter and isinstance(device_adapter_state, dict):
                before_device_state = dict(device_adapter_state_before)
                device_adapter_state["fragility_used"] = (
                    int(before_device_state.get("fragility_used") or 0)
                    + int(actual_charges.get("device_fragility_points") or 0)
                )
                if is_device_http and device_http_attempted:
                    device_adapter_state["health_observed"] = True
                    device_adapter_state["health_failed"] = status in {
                        "failed", "blocked"
                    }
            reconciled_used = dict(used)
            settlement_status = "not_attempted"
            is_partial = bool(
                isinstance(receipt_payload, dict)
                and (receipt_payload.get("partial") or receipt_payload.get("status") == "partial")
            )
            receipt_capability_input = _hunt_redacted_capability_input(
                name,
                request.input,
            )
            receipt_contract_payload = (
                dict(receipt_payload)
                if isinstance(receipt_payload, Mapping)
                else {}
            )
            if capability_execution is not None:
                normalized_observations = [
                    dict(item) for item in capability_execution.observations
                ]
                receipt_contract_payload["receipt_observations"] = (
                    normalized_observations
                )
                if isinstance(receipt_payload, dict):
                    # The action summary powers idempotent API/CLI/UI replays;
                    # keep the same normalized, content-free observations as
                    # the immutable capability receipt.
                    receipt_payload["observations"] = normalized_observations
                    receipt_payload["partial"] = bool(
                        capability_execution.partial
                    )
                    receipt_payload["timed_out"] = bool(
                        capability_execution.timed_out
                    )
                if (
                    capability_execution.errors
                    and not receipt_contract_payload.get("error")
                ):
                    # Keep the bounded public guard reason in the durable action
                    # so an idempotent replay and the Hunt UI explain why a
                    # capability was blocked.  Adapter faults are already
                    # normalized to non-sensitive type-only errors.
                    receipt_contract_payload["error"] = str(
                        capability_execution.errors[0]
                    )[:500]
                    if isinstance(receipt_payload, dict):
                        receipt_payload["error"] = receipt_contract_payload[
                            "error"
                        ]
            downstream_receipt: dict[str, Any] = {}
            if is_device_queue:
                queued_result = (
                    dict(receipt_contract_payload.get("queued") or {})
                    if isinstance(receipt_contract_payload.get("queued"), Mapping)
                    else {}
                )
                if device_queue_enqueued and queued_result.get("scan_id"):
                    downstream_receipt = {
                        "scan_id": str(queued_result["scan_id"]),
                        "job_id": str(queued_result.get("job_id") or "") or None,
                        "run_kind": str(queued_result.get("run_kind") or "") or None,
                    }
                    receipt_contract_payload["receipt_observations"] = [{
                        "kind": "scan_receipt",
                        "status": "queued",
                        **downstream_receipt,
                    }]
            ssh_plan_receipt: dict[str, Any] = {}
            if (
                is_device_ssh_proposal
                and proposed_ssh_plan is not None
            ):
                ssh_plan_receipt = {
                    "plan_id": str(proposed_ssh_plan["plan_id"]),
                    "plan_digest": str(proposed_ssh_plan["plan_digest"]),
                    "requires_user_confirmation": True,
                }
                receipt_contract_payload["receipt_observations"] = [{
                    "kind": "immutable_shell_plan",
                    "status": "proposed",
                    **ssh_plan_receipt,
                }]
            if api_managed_budget:
                if durable_reservation is None or durable_action_digest is None:
                    raise RuntimeError(
                        "Hunt capability reservation disappeared before settlement"
                    )
                async with conn.transaction():
                    locked = await _hunt_run_or_404(conn, hunt_id, for_update=True)
                    current_used = _hunt_json(locked["budget_used_json"], {})
                    merged_device_context = None
                    if is_device_adapter:
                        merge_device_context = (
                            _merge_hunt_device_ssh_proposal_context
                            if (
                                is_device_ssh_proposal
                                and proposed_ssh_plan is not None
                            )
                            else _merge_hunt_device_queue_context
                            if is_device_queue
                            else _merge_hunt_device_http_context
                            if is_device_http
                            else _merge_hunt_device_control_context
                        )
                        merged_device_context, evidence_ref_map = (
                            merge_device_context(
                                _hunt_json(locked["context_pack"], {}),
                                device_adapter_state_before,
                                device_adapter_state or {},
                            )
                        )
                        if (
                            isinstance(receipt_payload, dict)
                            and str(receipt_payload.get("evidence_ref") or "")
                            in evidence_ref_map
                        ):
                            receipt_payload["evidence_ref"] = evidence_ref_map[
                                str(receipt_payload["evidence_ref"])
                            ]
                    latest_reservation = await durable_store.load(
                        conn,
                        durable_reservation.record.reservation_id,
                        for_update=True,
                    )
                    if (
                        latest_reservation is None
                        or latest_reservation.record.state_digest
                        != durable_reservation.record.state_digest
                        or latest_reservation.record.status != "running"
                        or latest_reservation.record.worker_id != durable_worker_id
                    ):
                        raise RuntimeError(
                            "Hunt capability reservation changed before settlement"
                        )
                    current_ledger = {
                        key: int(current_used.get(key) or 0) for key in limits
                    }
                    prospective_ledger = reconcile_budget_snapshot(
                        current_ledger,
                        latest_reservation.record.requested,
                        actual_charges,
                    )
                    prospective_used = dict(current_used)
                    prospective_used.update(prospective_ledger)
                    receipt_result = await _arsenal_routes._record_tool_receipt(
                        conn,
                        _arsenal_routes.ToolReceiptRequest(
                            tool_name=str(spec.adapter),
                            capability_name=name,
                            adapter_name=str(spec.adapter),
                            adapter_version=str(spec.adapter_version),
                            redacted_argv=[receipt_capability_input],
                            target_scope={
                                "target_kind": str(run["target_kind"]),
                                "target_id": str(
                                    run["device_target_id"] or run["target_id"]
                                ),
                            },
                            scope_receipt_id=validated_scope_receipt_id,
                            approval_receipt_id=policy.get("approval_receipt_id"),
                            status=(
                                "success"
                                if status in {"completed", "partial"}
                                else "failed"
                            ),
                            parser_status=(
                                "partial"
                                if is_partial
                                else "parsed"
                                if status == "completed"
                                else "failed"
                            ),
                            budget_json={
                                "reserved": charges,
                                "actual": actual_charges,
                                "used_after_reconciliation": prospective_used,
                            },
                            partial=is_partial,
                            hunt_id=str(run["id"]),
                            metadata_json={
                                "hunt_action_id": str(action_id),
                                "result_status": status,
                                "durable_budget_reservation_id": (
                                    latest_reservation.record.reservation_id
                                ),
                                "downstream": downstream_receipt or None,
                                "ssh_plan": ssh_plan_receipt or None,
                            },
                            created_by=f"hunt_v2:{hunt_id}",
                        ),
                    )
                    receipt_id = receipt_result.get("tool_receipt", {}).get("id")
                    if not receipt_id:
                        raise RuntimeError(
                            "Hunt capability receipt was not persisted"
                        )
                    terminal_record, capability_receipt = (
                        terminalize_hunt_capability(
                            latest_reservation.record,
                            action_digest=durable_action_digest,
                            capability_name=name,
                            adapter_name=str(spec.adapter),
                            adapter_version=str(spec.adapter_version),
                            parser_version=(
                                capability_execution.parser_version
                                if capability_execution is not None
                                else None
                            ),
                            target_id=(
                                run["device_target_id"] or run["target_id"]
                            ),
                            target_kind=str(run["target_kind"]),
                            capability_input=receipt_capability_input,
                            action_status=status,
                            actual_budget=actual_charges,
                            worker_id=durable_worker_id,
                            started_at=(
                                latest_reservation.record.started_at.isoformat()
                                if latest_reservation.record.started_at
                                else datetime.now(timezone.utc).isoformat()
                            ),
                            finished_at=datetime.now(timezone.utc).isoformat(),
                            receipt_id=str(receipt_id),
                            scope_receipt_id=validated_scope_receipt_id,
                            approval_receipt_id=policy.get(
                                "approval_receipt_id"
                            ),
                            result=(
                                receipt_contract_payload
                            ),
                        )
                    )
                    reconciled_ledger = terminal_record.reconcile_consumed(
                        current_ledger
                    )
                    if reconciled_ledger != prospective_ledger:
                        raise RuntimeError(
                            "Hunt capability reconciliation changed during settlement"
                        )
                    durable_reservation = await durable_store.persist_terminal(
                        conn,
                        previous=latest_reservation,
                        terminal=terminal_record,
                        ledger_after_settlement=reconciled_ledger,
                        receipt=capability_receipt,
                    )
                    current_used.update(reconciled_ledger)
                    reconciled_used = current_used
                    if merged_device_context is not None:
                        await conn.execute(
                            "UPDATE hunt_runs SET budget_used_json=$2, "
                            "context_pack=$3, updated_at=NOW() WHERE id=$1",
                            locked["id"],
                            json.dumps(current_used),
                            json.dumps(merged_device_context, default=str),
                        )
                    else:
                        await conn.execute(
                            "UPDATE hunt_runs SET budget_used_json=$2, "
                            "updated_at=NOW() WHERE id=$1",
                            locked["id"],
                            json.dumps(current_used),
                        )
                    if isinstance(receipt_payload, dict):
                        receipt_payload["receipt_id"] = str(receipt_id)
                        receipt_payload["budget_reservation_id"] = (
                            terminal_record.reservation_id
                        )
                        receipt_payload["budget_reservation_state"] = (
                            terminal_record.status
                        )
                        receipt_payload["durable_budget_settled"] = True
                        receipt_payload["budget_consumed"] = dict(
                            terminal_record.actual
                        )
                        receipt_payload["budget_accounting"] = (
                            _hunt_budget_accounting(
                                terminal_record.requested,
                                terminal_record.actual,
                                reconciled_used,
                                charge_basis=(
                                    "conservative_full_reservation"
                                    if name == "candidate.verify"
                                    else "capability_reported_settlement"
                                ),
                                settlement_status="succeeded",
                                reservation_id=terminal_record.reservation_id,
                            )
                        )
                    updated_action = await conn.execute(
                        """UPDATE hunt_actions
                           SET status=$2, result_summary=$3, receipt_id=$4,
                               completed_at=NOW()
                           WHERE id=$1 AND hunt_run_id=$5 AND status='running'""",
                        action_id,
                        status,
                        json.dumps(
                            _arsenal_routes._redact_agent_payload(receipt_payload), default=str
                        ),
                        _optional_uuid(str(receipt_id)),
                        locked["id"],
                    )
                    if not str(updated_action).endswith(" 1"):
                        raise RuntimeError(
                            "Hunt capability action changed before settlement"
                        )
            elif worker_durable_budget:
                if (
                    isinstance(receipt_payload, dict)
                    and receipt_payload.get("durable_budget_settled") is True
                ):
                    if durable_reservation is None or durable_action_digest is None:
                        raise RuntimeError(
                            "Network capability reservation disappeared after dispatch"
                        )
                    async with conn.transaction():
                        stored = await durable_store.load(
                            conn,
                            durable_reservation.record.reservation_id,
                            for_update=True,
                        )
                        action = await conn.fetchrow(
                            """SELECT status, receipt_id FROM hunt_actions
                               WHERE id=$1 AND hunt_run_id=$2 FOR UPDATE""",
                            action_id,
                            run["id"],
                        )
                        stored_receipt = (
                            dict(stored.receipt or {}) if stored is not None else {}
                        )
                        receipt_id = str(
                            receipt_payload.get("receipt_id") or ""
                        ) or None
                        if (
                            stored is None
                            or not stored.record.terminal
                            or stored.action_digest != durable_action_digest
                            or str(receipt_payload.get("budget_reservation_id") or "")
                            != stored.record.reservation_id
                            or str(receipt_payload.get("budget_reservation_state") or "")
                            != stored.record.status
                            or str(stored_receipt.get("receipt_id") or "")
                            != str(receipt_id or "")
                            or action is None
                            or str(action["status"])
                            not in {"completed", "partial", "blocked", "cancelled", "failed"}
                            or str(action["receipt_id"] or "")
                            != str(receipt_id or "")
                        ):
                            raise RuntimeError(
                                "Network capability settlement is not internally consistent"
                            )
                # The worker owns every durable transition and the atomic
                # reservation/receipt/ledger/action settlement. An API timeout
                # deliberately leaves the live lease for the worker or sweeper.
            else:
                try:
                    async with conn.transaction():
                        locked = await _hunt_run_or_404(conn, hunt_id, for_update=True)
                        current_used = _hunt_json(locked["budget_used_json"], {})
                        if worker_managed_budget:
                            # The worker already replaced its exact hold with measured
                            # usage in the same transaction as the canonical receipt,
                            # or still owns the live reservation after an API timeout.
                            reconciled_used = current_used
                            settlement_status = "worker_managed"
                        else:
                            current_ledger = {
                                key: int(current_used.get(key) or 0)
                                for key in limits
                            }
                            reconciled_ledger = reconcile_budget_snapshot(
                                current_ledger, charges, actual_charges,
                            )
                            current_used.update(reconciled_ledger)
                            await conn.execute(
                                "UPDATE hunt_runs SET budget_used_json=$2, "
                                "updated_at=NOW() WHERE id=$1",
                                locked["id"], json.dumps(current_used),
                            )
                            reconciled_used = current_used
                            settlement_status = "succeeded"
                except Exception:
                    settlement_status = "failed"
                    logger.exception(
                        "Failed to reconcile Hunt capability budget",
                        extra={"hunt_id": hunt_id, "action_id": str(action_id)},
                    )
                try:
                    receipt_result = await _arsenal_routes._record_tool_receipt(conn, _arsenal_routes.ToolReceiptRequest(
                        tool_name=str(spec.adapter),
                        capability_name=name,
                        adapter_name=str(spec.adapter),
                        adapter_version=str(spec.adapter_version),
                        redacted_argv=[request.input],
                        target_scope={
                            "target_kind": str(run["target_kind"]),
                            "target_id": str(run["device_target_id"] or run["target_id"]),
                        },
                        approval_receipt_id=policy.get("approval_receipt_id"),
                        status="success" if status in {"completed", "partial"} else "failed",
                        parser_status="partial" if is_partial else "parsed" if status == "completed" else "failed",
                        budget_json={
                            "reserved": charges, "actual": actual_charges,
                            "used_after_reconciliation": reconciled_used,
                        },
                        partial=is_partial,
                        hunt_id=str(run["id"]),
                        metadata_json={
                            "hunt_action_id": str(action_id),
                            "result_status": status,
                            "durable_budget_reservation_id": (
                                receipt_payload.get("reservation_id")
                                if isinstance(receipt_payload, dict) else None
                            ),
                        },
                        created_by=f"hunt_v2:{hunt_id}",
                    ))
                    receipt_id = receipt_result.get("tool_receipt", {}).get("id")
                except Exception:
                    logger.exception("Failed to record Hunt capability receipt", extra={"hunt_id": hunt_id, "action_id": str(action_id)})
                if isinstance(receipt_payload, dict):
                    receipt_payload["budget_consumed"] = dict(actual_charges)
                    receipt_payload["budget_accounting"] = _hunt_budget_accounting(
                        charges,
                        actual_charges,
                        reconciled_used,
                        charge_basis=(
                            "conservative_full_reservation"
                            if name == "candidate.verify"
                            else "capability_reported_settlement"
                        ),
                        settlement_status=settlement_status,
                        reservation_id=(
                            durable_reservation.record.reservation_id
                            if durable_reservation is not None else None
                        ),
                    )
                await conn.execute(
                    """UPDATE hunt_actions SET status=$2, result_summary=$3, receipt_id=$4, completed_at=NOW() WHERE id=$1""",
                    action_id, status, json.dumps(_arsenal_routes._redact_agent_payload(receipt_payload), default=str),
                    _optional_uuid(receipt_id) if receipt_id else None,
                )
        lifecycle.advance("settled")
    canonical_action_result = (
        capability_execution.public_dict()
        if capability_execution is not None
        else HuntActionResult(
            hunt_id=str(run["id"]),
            action_id=str(action_id),
            capability_name=name,
            target_kind=str(run["target_kind"]),
            placement=placement,
            status=(
                "success" if status == "completed" else str(status)
            ),
            observations=tuple(
                dict(item)
                for item in (
                    result.get("observations")
                    or (result.get("typed_output") or {}).get("records")
                    or ()
                )
                if isinstance(item, Mapping)
            ),
            errors=(
                (str(result.get("error")),)
                if isinstance(result, Mapping) and result.get("error")
                else ()
            ),
            actual_budget=(
                dict(result.get("budget_consumed") or {})
                if isinstance(result, Mapping)
                else {}
            ),
            partial=bool(
                isinstance(result, Mapping) and result.get("partial")
            ),
            timed_out=bool(
                isinstance(result, Mapping) and result.get("timed_out")
            ),
            execution_started=any(
                int(amount or 0) > 0
                for dimension, amount in (
                    (result.get("budget_consumed") or {}).items()
                    if isinstance(result, Mapping)
                    and isinstance(result.get("budget_consumed"), Mapping)
                    else ()
                )
                if dimension not in {"agent_actions", "active_actions"}
            ),
            parser_version=str(
                ((result.get("typed_output") or {}).get("parser") or spec.output_schema)
                if isinstance(result, Mapping)
                else spec.output_schema
            ),
            redacted_execution=_hunt_redacted_capability_input(
                name, request.input,
            ),
        ).public_dict()
    )
    return {
        "hunt_id": hunt_id,
        "capability": name,
        "action_id": str(action_id),
        "idempotent_replay": False,
        "action_result": canonical_action_result,
        "result": result,
    }


async def _enqueue_canonical_network_capability(
    *, capability_name: str, capability_input: Mapping[str, Any],
    expected_input_digest: str, expected_budget: Mapping[str, int],
    timeout_ms: int, hunt_id: str, action_id: str, reservation_id: str,
    action_digest: str,
) -> dict[str, Any]:
    """Queue declarative canonical work; the worker independently reconstructs its argv."""
    redis_client = get_redis()
    job_id = str(uuid.uuid4())
    result_key = f"agent_tool_result:{job_id}"
    cancel_key = f"agent_tool_cancel:{job_id}"
    # A worker-placed job polls this key, and its id exists only here, so a Hunt cancellation can
    # reach it only if the id is recorded against the Hunt now.
    await record_cancellable_job_durable(_pool(), redis_client, hunt_id, job_id)
    payload = {
        "job_id": job_id, "type": "canonical_network_capability",
        "capability_name": capability_name, "capability_input": dict(capability_input),
        "expected_input_digest": expected_input_digest,
        "expected_budget": {str(k): int(v) for k, v in expected_budget.items()},
        "hunt_id": str(hunt_id), "action_id": str(action_id),
        "budget_reservation_id": str(reservation_id),
        "action_digest": str(action_digest),
        "submitted_at": utc_now_iso(), "_base_queue_name": _get("AGENT_TOOL_QUEUE_NAME"),
    }
    redis_client.hset(f"job:{job_id}", mapping={
        "status": "queued", "current_phase": "canonical_capability_queued",
        "tool": capability_name,
    })
    redis_client.expire(f"job:{job_id}", max(3600, math.ceil(timeout_ms / 1000) + 300))
    enqueue_job(redis_client, _get("AGENT_TOOL_QUEUE_NAME"), payload)
    deadline = asyncio.get_running_loop().time() + timeout_ms / 1000.0 + 30.0
    try:
        while asyncio.get_running_loop().time() < deadline:
            raw = redis_client.get(result_key)
            if raw is not None:
                redis_client.delete(result_key)
                value = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                parsed = json.loads(value)
                if not isinstance(parsed, dict):
                    raise RuntimeError("canonical capability worker returned a malformed result")
                return parsed
            await asyncio.sleep(0.2)
    except asyncio.CancelledError:
        redis_client.set(cancel_key, "1", ex=max(60, math.ceil(timeout_ms / 1000) + 30))
        raise
    redis_client.set(cancel_key, "1", ex=max(60, math.ceil(timeout_ms / 1000) + 30))
    return {
        "status": "timeout", "error": "worker_result_timeout", "partial": False,
        "typed_output": {"parser_status": "failed", "records": [], "record_count": 0},
        "budget_consumed": {},
    }


async def _enqueue_canonical_http_capability(
    *,
    capability_name: str,
    capability_input: Mapping[str, Any],
    expected_budget: Mapping[str, int],
    timeout_ms: int,
    hunt_id: str,
    action_id: str,
    reservation_id: str,
    action_digest: str,
) -> dict[str, Any]:
    """Queue opaque session/HTTP work without credentials or target authority."""
    redis_client = get_redis()
    job_id = str(uuid.uuid4())
    result_key = f"agent_tool_result:{job_id}"
    cancel_key = f"agent_tool_cancel:{job_id}"
    await record_cancellable_job_durable(_pool(), redis_client, hunt_id, job_id)
    payload = {
        "job_id": job_id,
        "type": "canonical_http_capability",
        "capability_name": capability_name,
        "capability_input": dict(capability_input),
        "expected_budget": {
            str(key): int(value) for key, value in expected_budget.items()
        },
        "hunt_id": str(hunt_id),
        "action_id": str(action_id),
        "budget_reservation_id": str(reservation_id),
        "action_digest": str(action_digest),
        "submitted_at": utc_now_iso(),
        "_base_queue_name": _get("AGENT_TOOL_QUEUE_NAME"),
    }
    redis_client.hset(
        f"job:{job_id}",
        mapping={
            "status": "queued",
            "current_phase": "canonical_http_capability_queued",
            "tool": capability_name,
        },
    )
    redis_client.expire(
        f"job:{job_id}", max(3600, math.ceil(timeout_ms / 1000) + 300),
    )
    enqueue_job(redis_client, _get("AGENT_TOOL_QUEUE_NAME"), payload)
    deadline = asyncio.get_running_loop().time() + timeout_ms / 1000.0 + 30.0
    try:
        while asyncio.get_running_loop().time() < deadline:
            raw = redis_client.get(result_key)
            if raw is not None:
                redis_client.delete(result_key)
                value = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                parsed = json.loads(value)
                if not isinstance(parsed, dict):
                    raise RuntimeError(
                        "canonical HTTP worker returned a malformed result"
                    )
                return parsed
            await asyncio.sleep(0.2)
    except asyncio.CancelledError:
        redis_client.set(
            cancel_key, "1", ex=max(60, math.ceil(timeout_ms / 1000) + 30),
        )
        raise
    redis_client.set(
        cancel_key, "1", ex=max(60, math.ceil(timeout_ms / 1000) + 30),
    )
    return {
        "status": "timeout",
        "error": "worker_result_timeout",
        "partial": False,
        "budget_consumed": {},
        "durable_budget_settled": False,
    }


async def _enqueue_canonical_browser_capability(
    *, capability_name: str, capability_input: Mapping[str, Any],
    expected_input_digest: str, expected_budget: Mapping[str, int],
    timeout_ms: int, hunt_id: str, action_id: str, reservation_id: str,
    action_digest: str,
) -> dict[str, Any]:
    """Queue browser work carrying identity and digests, never target authority."""
    redis_client = get_redis()
    job_id = str(uuid.uuid4())
    result_key = f"agent_tool_result:{job_id}"
    cancel_key = f"agent_tool_cancel:{job_id}"
    await record_cancellable_job_durable(_pool(), redis_client, hunt_id, job_id)
    payload = {
        "job_id": job_id,
        "type": "canonical_browser_capability",
        "capability_name": capability_name,
        "capability_input": dict(capability_input),
        "expected_input_digest": expected_input_digest,
        "expected_budget": {
            str(key): int(value) for key, value in expected_budget.items()
        },
        "hunt_id": str(hunt_id),
        "action_id": str(action_id),
        "budget_reservation_id": str(reservation_id),
        "action_digest": str(action_digest),
        "submitted_at": utc_now_iso(),
        "_base_queue_name": _get("AGENT_TOOL_QUEUE_NAME"),
    }
    redis_client.hset(
        f"job:{job_id}",
        mapping={
            "status": "queued",
            "current_phase": "canonical_browser_capability_queued",
            "tool": capability_name,
        },
    )
    redis_client.expire(
        f"job:{job_id}", max(3600, math.ceil(timeout_ms / 1000) + 300),
    )
    enqueue_job(redis_client, _get("AGENT_TOOL_QUEUE_NAME"), payload)
    deadline = asyncio.get_running_loop().time() + timeout_ms / 1000.0 + 30.0
    try:
        while asyncio.get_running_loop().time() < deadline:
            raw = redis_client.get(result_key)
            if raw is not None:
                redis_client.delete(result_key)
                value = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                parsed = json.loads(value)
                if not isinstance(parsed, dict):
                    raise RuntimeError(
                        "canonical browser worker returned a malformed result"
                    )
                return parsed
            await asyncio.sleep(0.2)
    except asyncio.CancelledError:
        redis_client.set(
            cancel_key, "1", ex=max(60, math.ceil(timeout_ms / 1000) + 30),
        )
        raise
    redis_client.set(
        cancel_key, "1", ex=max(60, math.ceil(timeout_ms / 1000) + 30),
    )
    return {
        "status": "timeout",
        "error": "worker_result_timeout",
        "partial": False,
        "typed_output": {
            "parser_status": "failed", "records": [], "record_count": 0,
        },
        "budget_consumed": {},
    }


async def _enqueue_canonical_scanner_capability(
    *, capability_name: str, capability_input: Mapping[str, Any],
    timeout_ms: int, hunt_id: str, action_id: str, reservation_id: str,
    action_digest: str,
) -> dict[str, Any]:
    """Queue a canonical external scanner without queue-carried target authority."""
    redis_client = get_redis()
    job_id = str(uuid.uuid4())
    result_key = f"agent_tool_result:{job_id}"
    cancel_key = f"agent_tool_cancel:{job_id}"
    await record_cancellable_job_durable(_pool(), redis_client, hunt_id, job_id)
    payload = {
        "job_id": job_id,
        "type": "canonical_scanner_capability",
        "capability_name": capability_name,
        "capability_input": dict(capability_input),
        "hunt_id": str(hunt_id),
        "action_id": str(action_id),
        "budget_reservation_id": str(reservation_id),
        "action_digest": str(action_digest),
        "submitted_at": utc_now_iso(),
        "_base_queue_name": _get("AGENT_TOOL_QUEUE_NAME"),
    }
    redis_client.hset(
        f"job:{job_id}",
        mapping={
            "status": "queued",
            "current_phase": "canonical_scanner_capability_queued",
            "tool": capability_name,
        },
    )
    redis_client.expire(
        f"job:{job_id}",
        max(3600, math.ceil(timeout_ms / 1000) + 300),
    )
    enqueue_job(redis_client, _get("AGENT_TOOL_QUEUE_NAME"), payload)
    deadline = asyncio.get_running_loop().time() + timeout_ms / 1000.0 + 30.0
    try:
        while asyncio.get_running_loop().time() < deadline:
            raw = redis_client.get(result_key)
            if raw is not None:
                redis_client.delete(result_key)
                value = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                parsed = json.loads(value)
                if not isinstance(parsed, dict):
                    raise RuntimeError(
                        "canonical scanner capability worker returned a malformed result"
                    )
                return parsed
            await asyncio.sleep(0.2)
    except asyncio.CancelledError:
        redis_client.set(
            cancel_key,
            "1",
            ex=max(60, math.ceil(timeout_ms / 1000) + 30),
        )
        raise
    redis_client.set(
        cancel_key,
        "1",
        ex=max(60, math.ceil(timeout_ms / 1000) + 30),
    )
    return {
        "status": "timeout",
        "error": "worker_result_timeout",
        "partial": False,
        "typed_output": {
            "parser_status": "failed",
            "records": [],
            "record_count": 0,
        },
        "budget_consumed": {},
    }


def _hunt_json(value: Any, default: Any) -> Any:
    decoded = _decode_json_value(value)
    return decoded if isinstance(decoded, type(default)) else default


def _merge_hunt_device_control_context(
    persisted_context: Mapping[str, Any],
    execution_context_before: Mapping[str, Any],
    execution_context_after: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Merge one registered device adapter into typed V2 device Hunt state."""
    merged = copy.deepcopy(dict(persisted_context or {}))
    persisted_runtime = (
        copy.deepcopy(dict(merged.get("device_runtime") or {}))
        if isinstance(merged.get("device_runtime"), Mapping)
        else {}
    )
    before_state = _hunt_device_adapter_execution_state(
        execution_context_before
    )
    after_state = _hunt_device_adapter_execution_state(execution_context_after)
    before_evidence = (
        dict(before_state.get("evidence") or {})
        if isinstance(before_state.get("evidence"), Mapping)
        else {}
    )
    after_evidence = (
        dict(after_state.get("evidence") or {})
        if isinstance(after_state.get("evidence"), Mapping)
        else {}
    )
    persisted_evidence = (
        copy.deepcopy(dict(persisted_runtime.get("evidence") or {}))
        if isinstance(persisted_runtime.get("evidence"), Mapping)
        else {}
    )
    next_sequence = max(1, int(persisted_runtime.get("next_evidence_ref") or 1))
    for reference in persisted_evidence:
        match = re.fullmatch(r"devref_(\d+)", str(reference))
        if match:
            next_sequence = max(next_sequence, int(match.group(1)) + 1)

    remapped: dict[str, str] = {}
    for reference, payload in after_evidence.items():
        if reference in before_evidence and before_evidence[reference] == payload:
            continue
        assigned = str(reference)
        if assigned in persisted_evidence:
            while f"devref_{next_sequence}" in persisted_evidence:
                next_sequence += 1
            assigned = f"devref_{next_sequence}"
            next_sequence += 1
        persisted_evidence[assigned] = copy.deepcopy(payload)
        remapped[str(reference)] = assigned

    persisted_runtime.update({
        "schema_version": "hunt-device-runtime/v2",
        "evidence": persisted_evidence,
    })
    persisted_runtime["next_evidence_ref"] = max(
        next_sequence,
        int(persisted_runtime.get("next_evidence_ref") or 1),
    )
    policy_state = DeviceHuntPolicyState.from_mapping(
        merged.get("device_policy_state") or {}
    )
    fragility_delta = max(
        0,
        int(after_state.get("fragility_used") or 0)
        - int(before_state.get("fragility_used") or 0),
    )
    policy_state = policy_state.reconcile_adapter_state(
        before_state,
        after_state,
        actual_fragility=fragility_delta,
        health_failed=bool(after_state.get("health_failed")),
    )
    merged["device_policy_state"] = policy_state.public_dict()
    merged["device_runtime"] = persisted_runtime
    merged.pop("device_state", None)
    return merged, remapped


def _merge_hunt_device_http_context(
    persisted_context: Mapping[str, Any],
    execution_context_before: Mapping[str, Any],
    execution_context_after: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Merge a device HTTP result through the typed policy state."""
    return _merge_hunt_device_control_context(
        persisted_context,
        execution_context_before,
        execution_context_after,
    )


def _merge_hunt_device_queue_context(
    persisted_context: Mapping[str, Any],
    execution_context_before: Mapping[str, Any],
    execution_context_after: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Merge a queued device result through the typed policy state."""
    return _merge_hunt_device_control_context(
        persisted_context,
        execution_context_before,
        execution_context_after,
    )


def _merge_hunt_device_ssh_proposal_context(
    persisted_context: Mapping[str, Any],
    execution_context_before: Mapping[str, Any],
    execution_context_after: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Append one immutable SSH proposal while preserving concurrent device state."""
    merged, remapped = _merge_hunt_device_control_context(
        persisted_context,
        execution_context_before,
        execution_context_after,
    )
    persisted_runtime = dict(merged.get("device_runtime") or {})
    before_state = _hunt_device_adapter_execution_state(
        execution_context_before
    )
    after_state = _hunt_device_adapter_execution_state(execution_context_after)
    before_plan_ids = {
        str(item.get("plan_id") or "")
        for item in before_state.get("shell_plans") or []
        if isinstance(item, Mapping) and item.get("plan_id")
    }
    appended = [
        copy.deepcopy(dict(item))
        for item in after_state.get("shell_plans") or []
        if isinstance(item, Mapping)
        and str(item.get("plan_id") or "") not in before_plan_ids
    ]
    persisted_plans = [
        copy.deepcopy(dict(item))
        for item in persisted_runtime.get("shell_plans") or []
        if isinstance(item, Mapping)
    ]
    persisted_by_id = {
        str(item.get("plan_id") or ""): item
        for item in persisted_plans
        if item.get("plan_id")
    }
    active_signatures = {
        str(item.get("proposal_signature") or "")
        for item in persisted_plans
        if item.get("status") in {"proposed", "queueing", "queued"}
        and item.get("proposal_signature")
    }
    for plan in appended:
        plan_id = str(plan.get("plan_id") or "")
        signature = str(plan.get("proposal_signature") or "")
        if not plan_id or not signature:
            raise ValueError("SSH proposal is missing its immutable identity")
        existing = persisted_by_id.get(plan_id)
        if existing is not None:
            if existing != plan:
                raise ValueError("SSH proposal identity collided during settlement")
            continue
        if signature in active_signatures:
            raise ValueError("Equivalent SSH proposal appeared during settlement")
        persisted_plans.append(plan)
        persisted_by_id[plan_id] = plan
        active_signatures.add(signature)
    persisted_runtime["shell_plans"] = persisted_plans[-10:]
    merged["device_runtime"] = persisted_runtime
    return merged, remapped


def _hunt_device_ssh_proposal_delta(
    execution_context_before: Mapping[str, Any],
    execution_context_after: Mapping[str, Any],
    result: Mapping[str, Any],
    *,
    hunt_id: Any,
    device_target_id: Any,
) -> dict[str, Any] | None:
    """Return the one validated plan appended by an inert SSH proposal."""
    before_state = _hunt_device_adapter_execution_state(
        execution_context_before
    )
    after_state = _hunt_device_adapter_execution_state(execution_context_after)
    before_plan_ids = {
        str(item.get("plan_id") or "")
        for item in before_state.get("shell_plans") or []
        if isinstance(item, Mapping) and item.get("plan_id")
    }
    appended = [
        dict(item)
        for item in after_state.get("shell_plans") or []
        if isinstance(item, Mapping)
        and str(item.get("plan_id") or "") not in before_plan_ids
    ]
    if not appended:
        return None
    if len(appended) != 1:
        raise ValueError("SSH proposal appended more than one immutable plan")
    plan = device_shell.validate_shell_plan(appended[0])
    if not str(plan.get("proposal_signature") or ""):
        raise ValueError("SSH proposal is missing its immutable identity")
    if (
        str(plan.get("run_id") or "") != str(hunt_id)
        or str(plan.get("device_target_id") or "") != str(device_target_id)
        or str(plan.get("status") or "") != "proposed"
    ):
        raise ValueError("SSH proposal scope or state does not match the Hunt")
    if (
        result.get("ok") is not True
        or result.get("requires_user_confirmation") is not True
    ):
        raise ValueError("SSH proposal result is not confirmation-gated")
    returned_plan = result.get("plan")
    if not isinstance(returned_plan, Mapping) or (
        str(returned_plan.get("plan_id") or "") != str(plan["plan_id"])
        or str(returned_plan.get("plan_digest") or "")
        != str(plan["plan_digest"])
    ):
        raise ValueError("SSH proposal result does not match the appended plan")
    return plan


def _hunt_redacted_capability_input(
    capability_name: str,
    capability_input: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the bounded planner/audit projection of one capability input."""
    redacted = _arsenal_routes._redact_agent_payload(dict(capability_input or {}))
    if isinstance(redacted, dict) and redacted.get("path"):
        redacted["path"] = _devices._redact_hunt_path_query(redacted["path"])
    return redacted if isinstance(redacted, dict) else {}


async def _hunt_select_collection(run: Any, context: Mapping[str, Any], values: Mapping[str, Any]) -> dict[str, Any]:
    selector = _hunt_collection_selector(values, hard_limit=200)
    async with _pool().acquire() as conn:
        row, ref = await _hunt_bound_collection(
            conn, run, context, values.get("collection_id")
        )
        index_rows = await conn.fetch(
            """SELECT request_id, ordinal, folder, name, method, redacted_url, normalized_path,
                      body_mode, auth_type, tags_json, safe_method, supported
               FROM request_collection_requests WHERE collection_id=$1 ORDER BY ordinal LIMIT 20000""",
            row["id"],
        )
    base_selected = _select_request_collection_index_rows(
        index_rows, _hunt_bound_selector(ref, hard_limit=2_000),
    )
    selected = []
    ids, folders = set(selector.request_ids), set(selector.folders)
    methods, tags = set(selector.methods), set(selector.tags)
    for item in base_selected:
        if ids and item.get("request_id") not in ids:
            continue
        if folders and item.get("folder") not in folders:
            continue
        if methods and item.get("method") not in methods:
            continue
        if tags and not tags.intersection(str(tag) for tag in item.get("tags") or []):
            continue
        if not selector.matches_path(str(item.get("normalized_path") or "")):
            continue
        selected.append(item)
        if len(selected) >= selector.limit:
            break
    return {"ok": True, "collection_id": str(row["id"]), "requests": selected,
            "selection_id": ref.get("selection_id"),
            "count": len(selected), "secret_values_visible": False}


def _hunt_managed_principal_reference(
    context: Mapping[str, Any], value: Any,
) -> dict[str, Any] | None:
    try:
        return select_hunt_principal_reference(context, value)
    except CredentialReferenceError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


async def _enqueue_hunt_replay_capability(
    run: Any,
    context: Mapping[str, Any],
    values: Mapping[str, Any],
    *,
    action_id: uuid.UUID,
    action_digest: str,
) -> dict[str, Any]:
    """Place replay on a worker that executes the shared execute_replay_plan engine."""
    selector = _hunt_collection_selector(values, hard_limit=25)
    principal = _hunt_managed_principal_reference(
        context, values.get("as_principal"),
    )
    async with _pool().acquire() as conn:
        row, ref = await _hunt_bound_collection(
            conn, run, context, values.get("collection_id")
        )
        if not ref.get("selection_id"):
            raise HTTPException(
                status_code=403,
                detail="Safe replay requires a saved request collection selection",
            )
        if str(ref.get("replay_policy") or "") == "discovery_only":
            raise HTTPException(
                status_code=403,
                detail="This request collection selection is discovery-only",
            )
        index_rows = await conn.fetch(
            """SELECT request_id, ordinal, folder, name, method, redacted_url,
                      normalized_path, body_mode, auth_type, tags_json,
                      safe_method, supported
               FROM request_collection_requests
               WHERE collection_id=$1 ORDER BY ordinal LIMIT 20000""",
            row["id"],
        )
    base_selected = _select_request_collection_index_rows(
        index_rows, _hunt_bound_selector(ref, hard_limit=25),
    )
    narrowed_ids = set(selector.request_ids)
    narrowed_folders = set(selector.folders)
    narrowed_methods = set(selector.methods)
    narrowed_tags = set(selector.tags)
    replay_ids = [
        str(item["request_id"]) for item in base_selected
        if (not narrowed_ids or str(item["request_id"]) in narrowed_ids)
        and (not narrowed_folders or str(item.get("folder") or "") in narrowed_folders)
        and (not narrowed_methods or str(item["method"]) in narrowed_methods)
        and (
            not narrowed_tags
            or narrowed_tags.intersection(str(tag) for tag in item.get("tags") or [])
        )
        and selector.matches_path(str(item.get("normalized_path") or ""))
    ][:selector.limit]
    if not replay_ids:
        raise HTTPException(status_code=422, detail="Safe replay selection is empty")
    redis_client = get_redis()
    job_id = str(uuid.uuid4())
    await record_cancellable_job_durable(_pool(), redis_client, str(run["id"]), job_id)
    reservation_id = str(uuid.uuid4())
    result_key = f"agent_tool_result:{job_id}"
    timeout_seconds = 60
    payload = {
        "job_id": job_id,
        "type": "request_collection_replay",
        "hunt_id": str(run["id"]),
        "action_id": str(action_id),
        "action_digest": action_digest,
        "reservation_id": reservation_id,
        "collection_id": str(row["id"]),
        "expected_payload_sha256": str(row["payload_sha256"] or ""),
        "binding_id": ref.get("binding_id"),
        "selection_id": ref.get("selection_id"),
        "selection_digest": ref.get("selection_digest"),
        "environment_id": ref.get("environment_id"),
        "expected_environment_sha256": ref.get("environment_sha256"),
        "allowed_origins": list(ref.get("allowed_origins") or []),
        "replay_policy": ref.get("replay_policy"),
        "selector": {
            "request_ids": replay_ids,
            "methods": [],
            "path_regex": None,
            "limit": len(replay_ids),
        },
        "tool_wall_seconds": timeout_seconds,
        "submitted_at": utc_now_iso(),
        "_base_queue_name": _get("AGENT_TOOL_QUEUE_NAME"),
    }
    if principal is not None:
        payload.update({
            "credential_profile_id": principal["profile_id"],
            "principal_slot": principal["principal_slot"],
            "expected_profile_version": principal["profile_version"],
        })
    redis_client.hset(f"job:{job_id}", mapping={
        "status": "queued",
        "current_phase": "request_collection_replay_queued",
        "tool": "collections.replay_safe",
    })
    redis_client.expire(f"job:{job_id}", timeout_seconds + 300)
    enqueue_job(redis_client, _get("AGENT_TOOL_QUEUE_NAME"), payload)
    deadline = asyncio.get_running_loop().time() + timeout_seconds + 30
    try:
        while asyncio.get_running_loop().time() < deadline:
            raw = redis_client.get(result_key)
            if raw is not None:
                redis_client.delete(result_key)
                text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                parsed = json.loads(text)
                if not isinstance(parsed, dict):
                    raise RuntimeError("request replay worker returned a malformed result")
                parsed.setdefault("collection_id", str(row["id"]))
                return parsed
            await asyncio.sleep(0.2)
    except asyncio.CancelledError:
        # The worker owns durable settlement and must finish even if the API caller
        # disconnects after dispatch.
        raise
    return {
        "status": "timeout",
        "error": "worker_result_timeout",
        "collection_id": str(row["id"]),
        "reservation_id": reservation_id,
        "durable_budget_settled": False,
        "observations": [],
        "budget_consumed": {},
    }


async def _execute_hunt_candidate_verification(
    *,
    run: Mapping[str, Any],
    context: Mapping[str, Any],
    policy: Mapping[str, Any],
    candidate_uuid: uuid.UUID,
) -> dict[str, Any]:
    """Execute the server-owned verifier after canonical action admission."""
    if run["device_target_id"]:
        try:
            native_device_policy = DeviceHuntPolicyState.from_mapping(
                context.get("device_policy_state") or {}
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=409,
                detail="Native device Hunt policy state is unavailable",
            ) from exc
        state = native_device_policy.adapter_state(
            credential_refs=[
                dict(item)
                for item in context.get("credential_refs") or []
                if isinstance(item, Mapping)
            ],
            collection_refs=[
                dict(item)
                for item in context.get("request_collections") or []
                if isinstance(item, Mapping)
            ],
            runtime=(
                context.get("device_runtime")
                if isinstance(context.get("device_runtime"), Mapping)
                else {}
            ),
            allow_state_changing_requests=bool(
                policy.get("allow_state_changing_http")
            ),
        )
        result = await _devices._device_verify_candidate_tool(
            run_id=run["id"], device_target_id=run["device_target_id"],
            safety_profile=str(policy.get("device_fragility_profile") or "authenticated_active"),
            approval_receipt_id=policy["approval_receipt_id"], state=state,
            candidate_id=str(candidate_uuid), reason="Hunt V2 deterministic verification",
        )
    else:
        result = await _verify_suspected_finding_workflow(
            candidate_uuid,
            str(policy["approval_receipt_id"]),
            created_by=f"hunt_v2:{run['id']}",
        )
    return result


_AGENT_MUTATING_VERIFY_FAMILIES: frozenset[str] = frozenset({"mass_assignment", "field_constraint", "workflow"})
def _hunt_device_adapter_execution_state(value: Mapping[str, Any]) -> dict[str, Any]:
    """Read a transient adapter state without making it persisted Hunt context.

    The nested ``device_state`` form is accepted only for historical helper
    callers and migration tests. New Hunt execution passes the typed transient
    ``hunt-device-adapter-state/v2`` mapping directly.
    """
    legacy = value.get("device_state")
    if isinstance(legacy, Mapping):
        return dict(legacy)
    if value.get("schema_version") == "hunt-device-adapter-state/v2":
        return dict(value)
    return {}


def _hunt_collection_selector(values: Mapping[str, Any], *, hard_limit: int) -> RequestSelector:
    try:
        return RequestSelector(
            request_ids=tuple(str(item) for item in values.get("request_ids") or [])[:2_000],
            folders=tuple(str(item) for item in values.get("folders") or [])[:200],
            methods=tuple(str(item) for item in values.get("methods") or [])[:20],
            path_regex=str(values.get("path_regex") or "").strip() or None,
            tags=tuple(str(item) for item in values.get("tags") or [])[:200],
            safe_methods_only=True,
            limit=max(1, min(int(values.get("limit") or hard_limit), hard_limit)),
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


async def _hunt_bound_collection(
    conn: Any, run: Any, context: Mapping[str, Any], collection_id: Any,
) -> tuple[Any, dict[str, Any]]:
    collection_uuid = _uuid_or_400(str(collection_id or ""), "request collection id")
    refs = [
        dict(item) for item in context.get("request_collections") or []
        if isinstance(item, Mapping)
    ]
    ref = next((
        item for item in refs
        if str(item.get("collection_id") or "") == str(collection_uuid)
        or str(item.get("selection_id") or "") == str(collection_uuid)
    ), None)
    if ref is None:
        raise HTTPException(status_code=403, detail="Request collection is not bound to this Hunt")
    actual_collection_uuid = _uuid_or_400(
        str(ref.get("collection_id") or ""), "bound request collection id",
    )
    row = await conn.fetchrow(
        """SELECT * FROM request_collections WHERE id=$1 AND is_active=true
           AND (($2::uuid IS NOT NULL AND target_id=$2) OR
                ($3::uuid IS NOT NULL AND device_target_id=$3))""",
        actual_collection_uuid, run["target_id"], run["device_target_id"],
    )
    if not row:
        raise HTTPException(status_code=404, detail="Bound request collection is unavailable")
    if str(row.get("payload_sha256") or "") != str(ref.get("payload_sha256") or ""):
        raise HTTPException(
            status_code=409,
            detail="Bound request collection changed after Hunt admission",
        )
    return row, ref


def _hunt_bound_selector(ref: Mapping[str, Any], *, hard_limit: int) -> RequestCollectionSelection:
    try:
        selector = RequestCollectionSelection.from_mapping(
            ref.get("selector") if isinstance(ref.get("selector"), Mapping) else {}
        )
    except RequestCollectionContractError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return RequestCollectionSelection(
        request_ids=selector.request_ids,
        folders=selector.folders,
        methods=selector.methods,
        path_regex=selector.path_regex,
        tags=selector.tags,
        safe_methods_only=True,
        max_requests=min(selector.max_requests, hard_limit),
    )
