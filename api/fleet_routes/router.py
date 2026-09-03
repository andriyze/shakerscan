"""Fleet node and broker transport routes.

Extracted verbatim from the api.py monolith. Owns joined worker-node lifecycle
(join tokens, join, state, heartbeat, scale, drain/resume, credential rotation
and revocation) and the outbound-only broker transport a remote node uses to
lease, heartbeat, settle, cancel, and report canonical scan actions and jobs.

Named ``fleet_routes`` rather than ``fleet`` because ``api/fleet.py`` already
occupies that flat module name once both are copied into the runtime image.

Collaborators that are still hubs inside api.py are injected by the composition
root as lazily-resolved callables.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import socket
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import time
from typing import Any, Callable, Literal, Mapping, Optional
import urllib.parse
import uuid

import asyncpg
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

try:
    from api_utils import (
        SEVERITY_ORDER, _clean_string_list, _content_free_hash, _direct_query_value,
        _int_or_none, _iso_or_none, _json_safe_row, _optional_uuid, _parse_iso_datetime,
        _record_map, _row_value, _uuid_or_400, utc_now, utc_now_iso,
    )
    from operator_auth import _fleet_bearer_credential, _require_fleet_operator
    import asm_inventory
    import parallel_scan
    from artifact_storage import ArtifactStorageError, object_key as artifact_object_key, store_bytes as store_artifact_bytes, upsert_manifest as upsert_artifact_manifest
    from constants import resolve_or_consume_budget
    from fastapi.responses import JSONResponse
    from fleet import FleetAuthenticationError, FleetBootstrapConfig, FleetConfigurationError, FleetConflictError, FleetEnrollmentError, authenticate_node as _authenticate_fleet_node, consume_connection_bundle as _consume_fleet_connection_bundle, create_join_token as _create_fleet_join_token, distribute_worker_count as _distribute_fleet_worker_count, enroll_node as _enroll_fleet_node, generate_secret as _generate_fleet_secret, hash_secret as _hash_fleet_secret, public_node as _public_fleet_node, record_heartbeat as _record_fleet_heartbeat, record_node_event as _record_fleet_node_event, revoke_join_token as _revoke_fleet_join_token, socket_peer_is_overlay as _fleet_peer_is_overlay
    from job_queue import DEFAULT_WORKER_TOOL_COMMANDS, QueueLease, acknowledge_lease, enqueue_job, heartbeat_lease, lease_job, qualified_route_queues, stream_key
    from pathlib import Path
    from retest_contract import parse_json_field
    from runtime.credential_resolver import CredentialResolutionError, WorkerCredentialResolver, validate_worker_credential_authority
    from runtime.models import TargetBinding
    from runtime.observation_store import PostgresObservationManifestStore
    from runtime.receipts import CapabilityReceipt
    from runtime.request_collection_store import RequestCollectionContractError, RequestCollectionSelection, request_collection_selection_digest
    from runtime.scan_credentials import ScanCredentialError, bind_resolved_scan_credential, scan_credential_resolution_capability
    from runtime.sealed_inputs import SealedInputError, seal_private_input, validate_sealed_input_public_key
    from scan.action_plan import ScanActionPlanCompiler, ScanActionPlanError, credential_profile_action_refs, request_collection_action_refs, interactive_auth_input_action_ids
    from scan.action_store import PostgresScanActionStore
    from scan.authorization import ActionAuthorityDecision, revalidate_scan_action_authority
    from scan.broker_execution import BrokerScanExecutionError, heartbeat_broker_scan_execution, settle_broker_scan_execution
    from scan.budget_allocator import ScanBudgetAllocationError, allocate_scan_action_plan
    from scan.collection_replay import EXECUTABLE_REPLAY_POLICIES, ScanCollectionReplayContractError, narrow_replay_plan_to_request_manifest, scan_replay_authorization, scan_replay_selector
    from scan.continuation import ContinuationBudgetCeiling, reconciled_continuation_ceiling, ScanContinuationError, amended_scan_plan_revision, build_discovery_continuation_manifests, merge_scan_action_continuation
    from scan.contracts import SCAN_AUTHENTICATION_KEYS
    from scan.execution_backend import ActionAlreadyTerminal, ActionLease, ActionLeaseLost, PostgresScanExecutionBackend, ScanExecutionBackendError
    from scan.executor import build_native_scan_execution
    from scan.job_runtime import CanonicalScanJobMaterializationError, materialize_canonical_scan_job
    from scan.jobs import CanonicalScanJob, CanonicalScanJobError, SCAN_JOB_SCHEMA
    from scan.manifest_store import PostgresScanManifestStore, ScanManifestStoreError
    from scan.operational_metrics import record_operational_event
    from scan.private_inputs import BROKER_PRIVATE_SCAN_INPUT_SCHEMA, private_replay_plan_payload
    from scan.private_state import SCAN_PRIVATE_STATE_KEY_OPTION
    from scan.work_manifests import ScanWorkManifestError, ScanWorkManifestReference, build_request_candidate_manifest, unique_work_manifest_reference_dicts, work_manifest_references_in
    from scan.worker_dispatch import is_deterministic_dast, prepare_worker_dispatch
    from scanner_tools.request_replay import build_selected_replay_plan
    from secret_store import decrypt_secret
    from serialization import _decode_json_value, _json_object, _str_list, row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from ..api_utils import (
        SEVERITY_ORDER, _clean_string_list, _content_free_hash, _direct_query_value,
        _int_or_none, _iso_or_none, _json_safe_row, _optional_uuid, _parse_iso_datetime,
        _record_map, _row_value, _uuid_or_400, utc_now, utc_now_iso,
    )
    from ..operator_auth import _fleet_bearer_credential, _require_fleet_operator
    from .. import asm_inventory
    from .. import parallel_scan
    from ..artifact_storage import ArtifactStorageError, object_key as artifact_object_key, store_bytes as store_artifact_bytes, upsert_manifest as upsert_artifact_manifest
    from scanner.constants import resolve_or_consume_budget
    from fastapi.responses import JSONResponse
    from ..fleet import FleetAuthenticationError, FleetBootstrapConfig, FleetConfigurationError, FleetConflictError, FleetEnrollmentError, authenticate_node as _authenticate_fleet_node, consume_connection_bundle as _consume_fleet_connection_bundle, create_join_token as _create_fleet_join_token, distribute_worker_count as _distribute_fleet_worker_count, enroll_node as _enroll_fleet_node, generate_secret as _generate_fleet_secret, hash_secret as _hash_fleet_secret, public_node as _public_fleet_node, record_heartbeat as _record_fleet_heartbeat, record_node_event as _record_fleet_node_event, revoke_join_token as _revoke_fleet_join_token, socket_peer_is_overlay as _fleet_peer_is_overlay
    from ..job_queue import DEFAULT_WORKER_TOOL_COMMANDS, QueueLease, acknowledge_lease, enqueue_job, heartbeat_lease, lease_job, qualified_route_queues, stream_key
    from pathlib import Path
    from ..retest_contract import parse_json_field
    from ..runtime.credential_resolver import CredentialResolutionError, WorkerCredentialResolver, validate_worker_credential_authority
    from ..runtime.models import TargetBinding
    from ..runtime.observation_store import PostgresObservationManifestStore
    from ..runtime.receipts import CapabilityReceipt
    from ..runtime.request_collection_store import RequestCollectionContractError, RequestCollectionSelection, request_collection_selection_digest
    from ..runtime.scan_credentials import ScanCredentialError, bind_resolved_scan_credential, scan_credential_resolution_capability
    from ..runtime.sealed_inputs import SealedInputError, seal_private_input, validate_sealed_input_public_key
    from ..scan.action_plan import ScanActionPlanCompiler, ScanActionPlanError, credential_profile_action_refs, request_collection_action_refs, interactive_auth_input_action_ids
    from ..scan.action_store import PostgresScanActionStore
    from ..scan.authorization import ActionAuthorityDecision, revalidate_scan_action_authority
    from ..scan.broker_execution import BrokerScanExecutionError, heartbeat_broker_scan_execution, settle_broker_scan_execution
    from ..scan.budget_allocator import ScanBudgetAllocationError, allocate_scan_action_plan
    from ..scan.collection_replay import EXECUTABLE_REPLAY_POLICIES, ScanCollectionReplayContractError, narrow_replay_plan_to_request_manifest, scan_replay_authorization, scan_replay_selector
    from ..scan.continuation import ContinuationBudgetCeiling, ScanContinuationError, amended_scan_plan_revision, build_discovery_continuation_manifests, merge_scan_action_continuation
    from ..scan.contracts import SCAN_AUTHENTICATION_KEYS
    from ..scan.execution_backend import ActionAlreadyTerminal, ActionLease, ActionLeaseLost, PostgresScanExecutionBackend, ScanExecutionBackendError
    from ..scan.executor import build_native_scan_execution
    from ..scan.job_runtime import CanonicalScanJobMaterializationError, materialize_canonical_scan_job
    from ..scan.jobs import CanonicalScanJob, CanonicalScanJobError, SCAN_JOB_SCHEMA
    from ..scan.manifest_store import PostgresScanManifestStore, ScanManifestStoreError
    from ..scan.operational_metrics import record_operational_event
    from ..scan.private_inputs import BROKER_PRIVATE_SCAN_INPUT_SCHEMA, private_replay_plan_payload
    from ..scan.private_state import SCAN_PRIVATE_STATE_KEY_OPTION
    from ..scan.work_manifests import ScanWorkManifestError, ScanWorkManifestReference, build_request_candidate_manifest, unique_work_manifest_reference_dicts, work_manifest_references_in
    from ..scan.worker_dispatch import is_deterministic_dast, prepare_worker_dispatch
    from scanner.scanner_tools.request_replay import build_selected_replay_plan
    from ..secret_store import decrypt_secret
    from ..serialization import _decode_json_value, _json_object, _str_list, row_to_dict


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


def configure_fleet_router(
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

# Hub collaborators that still live in api.py, injected and resolved lazily.
def get_redis(*a: Any, **k: Any) -> Any:
    return _dep("get_redis")(*a, **k)


def _int_env(*a: Any, **k: Any) -> Any:
    return _dep("int_env")(*a, **k)


def _results_dir() -> Any:
    return _dep("results_dir")()


async def health(*a: Any, **k: Any) -> Any:
    return await _dep("health")(*a, **k)


import logging

logger = logging.getLogger("shakerscan.api.fleet")
QUEUE_NAME = os.environ.get("SCAN_QUEUE_NAME", "scan_jobs")
HEARTBEAT_TIMEOUT_MINUTES = int(os.environ.get("FLEET_HEARTBEAT_TIMEOUT_MINUTES", "10"))

@router.post("/fleet/acceptance/lease-probe")
async def run_fleet_acceptance_lease_probe(request: Request):
    """Run the content-free lease failure probe inside the control plane."""
    _require_fleet_operator(request)
    try:
        return await asyncio.to_thread(_fleet_acceptance_lease_probe)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"fleet lease probe failed: {type(exc).__name__}") from exc


@router.post("/fleet/join-tokens")
async def create_fleet_join_token(body: FleetJoinTokenRequest, request: Request, response: Response):
    """Mint a bounded worker enrollment token; the raw value is returned once."""
    _require_fleet_operator(request)
    response.headers["Cache-Control"] = "no-store"
    try:
        async with _pool().acquire() as conn:
            result = await _create_fleet_join_token(
                conn,
                role=body.role,
                transport=body.transport,
                ttl_seconds=body.ttl_seconds,
                max_uses=body.max_uses,
            )
        return result
    except FleetEnrollmentError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/fleet/join-tokens/{token_id}")
async def revoke_fleet_join_token(token_id: uuid.UUID, request: Request):
    """Revoke the remaining uses of an enrollment token without receiving its secret."""
    _require_fleet_operator(request)
    async with _pool().acquire() as conn:
        revoked = await _revoke_fleet_join_token(conn, token_id=str(token_id))
    if not revoked:
        raise HTTPException(status_code=404, detail="active join token was not found")
    return {"token_id": str(token_id), "revoked": True}


@router.post("/fleet/nodes/join")
async def join_fleet_node(body: FleetNodeJoinRequest, request: Request, response: Response):
    """Exchange one bounded token use for bootstrap data and a unique node identity."""
    _require_fleet_https(request)
    _require_fleet_join_rate_limit(request)
    response.headers["Cache-Control"] = "no-store"
    try:
        if body.transport == "broker":
            worker_image = str(os.environ.get("FLEET_WORKER_IMAGE_DIGEST") or "").strip()
            config = FleetBootstrapConfig(
                overlay_cidr="",
                control_plane_overlay_url="",
                control_plane_wireguard_public_key="",
                control_plane_wireguard_endpoint="",
                worker_image_digest=worker_image,
                desired_worker_count=_int_env("FLEET_DESIRED_WORKER_COUNT", 1),
            )
            ca_certificate = None
        else:
            config = _fleet_bootstrap_config()
            ca_certificate = _fleet_ca_certificate_pem()
        async with _pool().acquire() as conn:
            async with conn.transaction():
                result = await _enroll_fleet_node(
                    conn,
                    token=body.token,
                    name=body.name,
                    hostname=body.hostname,
                    region=body.region,
                    wireguard_public_key=body.wireguard_public_key,
                    transport=body.transport,
                    labels=body.labels,
                    capacity=body.capacity,
                    build_fingerprint=body.build_fingerprint,
                    config=config,
                )
        if ca_certificate:
            result["fleet_ca_certificate_pem"] = ca_certificate
        return result
    except FleetConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except FleetEnrollmentError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FleetConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/fleet/nodes")
async def list_fleet_nodes(request: Request):
    _require_fleet_operator(request)
    stale_after = max(60, _int_env("FLEET_HEARTBEAT_TIMEOUT_SECONDS", HEARTBEAT_TIMEOUT_MINUTES * 60))
    async with _pool().acquire() as conn:
        rows = await conn.fetch("SELECT * FROM nodes ORDER BY created_at ASC")
    nodes = [_public_fleet_node(row, stale_after_seconds=stale_after) for row in rows]
    active_nodes = [node for node in nodes if node.get("status") != "disabled"]
    return {
        "nodes": nodes,
        "stale_after_seconds": stale_after,
        "reconciliation_mode": (
            "manual" if os.environ.get("FLEET_RECONCILE_MODE", "systemd").strip().lower() == "manual"
            else "automatic"
        ),
        "summary": {
            "total_nodes": len(nodes),
            "active_nodes": len(active_nodes),
            "healthy_nodes": sum(node.get("status") == "healthy" for node in active_nodes),
            "unhealthy_nodes": sum(node.get("status") == "unhealthy" for node in active_nodes),
            "stale_nodes": sum(node.get("status") == "stale" for node in active_nodes),
            "draining_nodes": sum(node.get("status") == "draining" for node in active_nodes),
            "desired_workers": sum(int(node.get("desired_worker_count") or 0) for node in active_nodes),
            "active_workers": sum(int(node.get("active_worker_count") or 0) for node in active_nodes),
            "state_drift_nodes": sum(not bool(node.get("state_current")) for node in active_nodes),
            "wireguard_connection_pending_nodes": sum(
                bool(node.get("wireguard_connection_pending")) for node in active_nodes
            ),
            "image_drift_nodes": sum(
                int(node.get("active_worker_count") or 0) > 0 and not bool(node.get("image_current"))
                for node in active_nodes
            ),
        },
    }


@router.post("/fleet/scale")
async def scale_fleet_workers(body: FleetScaleRequest, request: Request):
    """Set one fleet-wide worker target and distribute it by reported capacity."""
    _require_fleet_operator(request)
    stale_after = max(60, _int_env("FLEET_HEARTBEAT_TIMEOUT_SECONDS", HEARTBEAT_TIMEOUT_MINUTES * 60))
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=stale_after)
    async with _pool().acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock($1)", 8_675_311)
            rows = await conn.fetch(
                "SELECT * FROM nodes WHERE status <> 'disabled' ORDER BY created_at ASC FOR UPDATE"
            )
            if any(bool(row.get("rollout_in_progress")) for row in rows):
                raise HTTPException(
                    status_code=409,
                    detail="fleet scaling is paused while a node image rollout is in progress",
                )
            eligible = [
                row for row in rows
                if not bool(row.get("drain"))
                and row.get("last_heartbeat_at") is not None
                and row.get("last_heartbeat_at") >= cutoff
            ]
            if body.desired_worker_count > 0 and not eligible:
                raise HTTPException(status_code=409, detail="no healthy schedulable fleet nodes are available")
            try:
                allocations = _distribute_fleet_worker_count(eligible, body.desired_worker_count)
            except (FleetEnrollmentError, FleetConflictError) as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            changes: list[dict[str, Any]] = []
            for row in rows:
                node_id = str(row["id"])
                desired = int(allocations.get(node_id, 0))
                previous = int(row.get("desired_worker_count") or 0)
                if desired == previous:
                    continue
                updated = await conn.fetchrow(
                    """
                    UPDATE nodes
                    SET desired_worker_count=$2,
                        desired_state_version=desired_state_version + 1,
                        desired_state_changed_at=NOW(),
                        updated_at=NOW()
                    WHERE id=$1 AND status <> 'disabled'
                    RETURNING desired_state_version
                    """,
                    row["id"],
                    desired,
                )
                if not updated:
                    raise HTTPException(status_code=409, detail="fleet changed while scaling")
                await _record_fleet_node_event(
                    conn,
                    node_id=row["id"],
                    event_type="worker_target_changed",
                    actor_type="operator",
                    details={
                        "scope": "fleet",
                        "previous_worker_count": previous,
                        "desired_worker_count": desired,
                        "desired_state_version": int(updated["desired_state_version"]),
                    },
                )
                changes.append({
                    "node_id": node_id,
                    "name": str(row.get("name") or node_id),
                    "previous_worker_count": previous,
                    "desired_worker_count": desired,
                })
            await _record_fleet_node_event(
                conn,
                node_id=None,
                event_type="fleet_worker_target_changed",
                actor_type="operator",
                details={
                    "desired_worker_count": body.desired_worker_count,
                    "eligible_node_count": len(eligible),
                    "allocations": allocations,
                },
            )
    return {
        "desired_worker_count": body.desired_worker_count,
        "eligible_node_count": len(eligible),
        "allocations": [
            {
                "node_id": str(row["id"]),
                "name": str(row.get("name") or row["id"]),
                "desired_worker_count": int(allocations.get(str(row["id"]), 0)),
            }
            for row in rows
        ],
        "changed_nodes": changes,
    }


@router.get("/fleet/nodes/{node_id}/activity")
async def get_fleet_node_activity(request: Request, node_id: str, limit: int = Query(50, ge=1, le=200)):
    """Recent durable scan/shard attribution for one fleet node."""
    _require_fleet_operator(request)
    try:
        parsed_id = uuid.UUID(node_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="node not found") from exc
    async with _pool().acquire() as conn:
        exists = await conn.fetchval("SELECT EXISTS(SELECT 1 FROM nodes WHERE id = $1)", parsed_id)
        if not exists:
            raise HTTPException(status_code=404, detail="node not found")
        rows = await conn.fetch(
            """
            SELECT id, parent_scan_id, target_url, scan_type, run_kind, scan_role,
                   shard_index, shard_count, status, progress, current_phase,
                   worker_id, execution_context, created_at, started_at, completed_at
            FROM scans
            WHERE executing_node_id = $1
            ORDER BY COALESCE(started_at, created_at) DESC
            LIMIT $2
            """,
            parsed_id,
            limit,
        )
    return {"node_id": node_id, "scans": [row_to_dict(row) for row in rows], "limit": limit}


@router.get("/fleet/nodes/{node_id}/events")
async def get_fleet_node_events(request: Request, node_id: str, limit: int = Query(50, ge=1, le=200)):
    """Read the bounded durable lifecycle/audit trail for one fleet node."""
    _require_fleet_operator(request)
    try:
        parsed_id = uuid.UUID(node_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="node not found") from exc
    async with _pool().acquire() as conn:
        exists = await conn.fetchval("SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$1)", parsed_id)
        if not exists:
            raise HTTPException(status_code=404, detail="node not found")
        rows = await conn.fetch(
            """
            SELECT id, node_id, event_type, actor_type, severity, details, created_at
            FROM fleet_node_events
            WHERE node_id=$1
            ORDER BY created_at DESC
            LIMIT $2
            """,
            parsed_id,
            limit,
        )
    events = []
    for row in rows:
        event = row_to_dict(row)
        event["details"] = parse_json_field(event.get("details")) or {}
        events.append(event)
    return {"node_id": node_id, "events": events, "limit": limit}


@router.get("/fleet/nodes/{node_id}/state")
async def get_fleet_node_state(node_id: str, request: Request):
    """Node-agent pull endpoint for desired state; authenticated with node identity."""
    _require_fleet_https(request)
    credential = _fleet_bearer_credential(request)
    try:
        async with _pool().acquire() as conn:
            async with conn.transaction():
                node = await _authenticate_fleet_node(conn, node_id=node_id, credential=credential)
        return {
            "node_id": str(node["id"]),
            "desired_worker_count": int(node.get("desired_worker_count") or 0),
            "drain": bool(node.get("drain")),
            "desired_state_version": int(node.get("desired_state_version") or 1),
            "applied_state_version": int(node.get("applied_state_version") or 0),
            "worker_image_digest": node.get("worker_image_digest"),
            "rollout_in_progress": bool(node.get("rollout_in_progress")),
            "desired_state_changed_at": (
                node.get("desired_state_changed_at").isoformat()
                if node.get("desired_state_changed_at")
                and hasattr(node.get("desired_state_changed_at"), "isoformat")
                else node.get("desired_state_changed_at")
            ),
            "status": node.get("status"),
        }
    except FleetAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@router.patch("/fleet/nodes/{node_id}/state")
async def update_fleet_node_state(node_id: str, body: FleetDesiredStateRequest, request: Request):
    """Operator desired-state action consumed asynchronously by the node agent."""
    _require_fleet_operator(request)
    if body.desired_worker_count is None and body.drain is None and body.worker_image_digest is None:
        raise HTTPException(
            status_code=422,
            detail="desired_worker_count, drain, or worker_image_digest is required",
        )
    try:
        parsed_id = uuid.UUID(node_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="node not found") from exc
    async with _pool().acquire() as conn:
        async with conn.transaction():
            before = await conn.fetchrow(
                "SELECT * FROM nodes WHERE id=$1 AND status <> 'disabled' FOR UPDATE",
                parsed_id,
            )
            if not before:
                raise HTTPException(status_code=404, detail="node not found or disabled")
            row = await conn.fetchrow(
                """
                UPDATE nodes
                SET desired_worker_count = COALESCE($2, desired_worker_count),
                    drain = CASE
                        WHEN $4::text IS NOT NULL AND $4 IS DISTINCT FROM worker_image_digest THEN true
                        WHEN rollout_in_progress AND $3 IS FALSE THEN true
                        ELSE COALESCE($3, drain)
                    END,
                    worker_image_digest = COALESCE($4, worker_image_digest),
                    rollout_in_progress = CASE
                        WHEN $4::text IS NOT NULL AND $4 IS DISTINCT FROM worker_image_digest THEN true
                        ELSE rollout_in_progress
                    END,
                    desired_state_version = desired_state_version + 1,
                    desired_state_changed_at = NOW(),
                    status = CASE
                        WHEN ($4::text IS NOT NULL AND $4 IS DISTINCT FROM worker_image_digest)
                             OR rollout_in_progress
                             OR COALESCE($3, drain) THEN 'draining'
                        WHEN status = 'draining' THEN 'joining'
                        ELSE status
                    END,
                    updated_at = NOW()
                WHERE id = $1 AND status <> 'disabled'
                RETURNING *
                """,
                parsed_id,
                body.desired_worker_count,
                body.drain,
                body.worker_image_digest,
            )
            await _record_fleet_node_event(
                conn,
                node_id=parsed_id,
                event_type="desired_state_updated",
                actor_type="operator",
                details={
                    "previous_worker_count": int(before.get("desired_worker_count") or 0),
                    "desired_worker_count": int(row.get("desired_worker_count") or 0),
                    "previous_drain": bool(before.get("drain")),
                    "drain": bool(row.get("drain")),
                    "worker_image_changed": before.get("worker_image_digest") != row.get("worker_image_digest"),
                    "worker_image_digest": row.get("worker_image_digest"),
                    "rollout_in_progress": bool(row.get("rollout_in_progress")),
                    "desired_state_version": int(row.get("desired_state_version") or 0),
                },
            )
    if not row:
        raise HTTPException(status_code=404, detail="node not found or disabled")
    return _public_fleet_node(row, stale_after_seconds=HEARTBEAT_TIMEOUT_MINUTES * 60)


@router.post("/fleet/nodes/{node_id}/heartbeat")
async def heartbeat_fleet_node(node_id: str, body: FleetHeartbeatRequest, request: Request):
    _require_fleet_https(request)
    credential = _fleet_bearer_credential(request)
    try:
        async with _pool().acquire() as conn:
            async with conn.transaction():
                before = await _authenticate_fleet_node(conn, node_id=node_id, credential=credential)
                result = await _record_fleet_heartbeat(
                    conn,
                    node_id=node_id,
                    active_worker_count=body.active_worker_count,
                    capacity=body.capacity,
                    build_fingerprint=body.build_fingerprint,
                    active_worker_image_digest=body.active_worker_image_digest,
                    agent_version=body.agent_version,
                    applied_state_version=body.applied_state_version,
                    last_error=body.last_error,
                    egress_ip=body.egress_ip,
                )
                if body.rollout_complete:
                    completed = await conn.fetchrow(
                        """
                        UPDATE nodes
                        SET rollout_in_progress = false,
                            drain = false,
                            desired_state_version = desired_state_version + 1,
                            desired_state_changed_at = NOW(),
                            status = 'joining',
                            updated_at = NOW()
                        WHERE id = $1
                          AND status <> 'disabled'
                          AND rollout_in_progress
                          AND worker_image_digest = active_worker_image_digest
                        RETURNING *
                        """,
                        uuid.UUID(node_id),
                    )
                    if completed:
                        result = completed
                        await _record_fleet_node_event(
                            conn,
                            node_id=node_id,
                            event_type="image_rollout_completed",
                            actor_type="node",
                            details={
                                "worker_image_digest": body.active_worker_image_digest,
                                "active_worker_count": body.active_worker_count,
                                "applied_state_version": body.applied_state_version,
                            },
                        )
                status_changed = str(before.get("status") or "") != str(result.get("status") or "")
                worker_count_changed = int(before.get("active_worker_count") or 0) != body.active_worker_count
                version_changed = int(before.get("applied_state_version") or 0) != body.applied_state_version
                error_changed = bool(before.get("last_error")) != bool(body.last_error)
                image_changed = str(before.get("active_worker_image_digest") or "") != str(body.active_worker_image_digest or "")
                if status_changed or worker_count_changed or version_changed or error_changed or image_changed:
                    await _record_fleet_node_event(
                        conn,
                        node_id=node_id,
                        event_type="node_state_reported",
                        actor_type="node",
                        severity="error" if body.last_error else "info",
                        details={
                            "status": result.get("status"),
                            "active_worker_count": body.active_worker_count,
                            "applied_state_version": body.applied_state_version,
                            "active_worker_image_digest": body.active_worker_image_digest,
                            "last_error_present": bool(body.last_error),
                            "capacity": body.capacity,
                            "egress_ip": body.egress_ip,
                        },
                    )
        return _public_fleet_node(result, stale_after_seconds=HEARTBEAT_TIMEOUT_MINUTES * 60)
    except FleetAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except FleetEnrollmentError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (FleetConflictError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/fleet/broker/nodes/{node_id}/lease")
async def lease_broker_job(node_id: str, body: BrokerLeaseRequest, request: Request):
    """Lease one executable scan to an outbound-only HTTPS worker."""
    node = await _broker_authenticated_node(node_id, request, require_schedulable=True)
    parsed_node_id = uuid.UUID(node_id)
    async with _pool().acquire() as conn:
        await conn.execute(
            """
            UPDATE broker_job_leases
            SET status='lost', completed_at=NOW()
            WHERE node_id=$1 AND worker_id=$2 AND status='leased' AND lease_expires_at < NOW()
            """,
            parsed_node_id,
            body.worker_id,
        )
        active = await conn.fetchval(
            """
            SELECT EXISTS(
                SELECT 1 FROM broker_job_leases
                WHERE node_id=$1 AND worker_id=$2 AND status='leased'
            )
            """,
            parsed_node_id,
            body.worker_id,
        )
    if active:
        raise HTTPException(status_code=409, detail="worker already owns an active broker lease")

    redis_client = get_redis()
    labels = _broker_node_labels(node)
    queue_names = [QUEUE_NAME, *qualified_route_queues(redis_client, [QUEUE_NAME], worker_labels=labels)]
    consumer_name = f"broker:{node_id}:{body.worker_id}"[:250]
    lease = await asyncio.to_thread(
        lease_job,
        redis_client,
        queue_names,
        consumer_name=consumer_name,
        block_ms=body.wait_seconds * 1000,
        visibility_timeout_ms=BROKER_LEASE_SECONDS * 1000,
    )
    if lease is None:
        return Response(status_code=204)
    if lease.legacy:
        try:
            legacy_payload = json.loads(lease.payload)
            enqueue_job(redis_client, lease.queue_name, legacy_payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        return Response(status_code=204)
    try:
        payload = json.loads(lease.payload)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        await asyncio.to_thread(acknowledge_lease, redis_client, lease)
        raise HTTPException(status_code=500, detail="broker encountered malformed queued work") from exc
    if not isinstance(payload, dict):
        await asyncio.to_thread(acknowledge_lease, redis_client, lease)
        raise HTTPException(status_code=500, detail="broker encountered malformed queued work")
    queued_payload = copy.deepcopy(payload)
    canonical_materialized: dict[str, Any] | None = None
    job_type = str(payload.get("type") or "scan")
    if job_type not in {"scan", parallel_scan.SHARD_JOB_TYPE}:
        requeued_payload = dict(payload)
        if job_type in {parallel_scan.PLAN_JOB_TYPE, parallel_scan.MERGE_JOB_TYPE}:
            # These orchestration jobs require the control plane's DB/Redis
            # access. A broker may see a pre-upgrade/base-queue copy, so move
            # it to the local-only route instead of requeueing it forever on
            # the remote route.
            requeued_payload["placement"] = {"node_scope": "local"}
        enqueue_job(
            redis_client,
            str(payload.get("_base_queue_name") or QUEUE_NAME),
            requeued_payload,
        )
        await asyncio.to_thread(acknowledge_lease, redis_client, lease)
        return Response(status_code=204)
    if lease.delivery_attempts > BROKER_MAX_DELIVERY_ATTEMPTS:
        try:
            exhausted_scan_id = uuid.UUID(str(payload.get("scan_id") or ""))
        except ValueError:
            exhausted_scan_id = None
        if exhausted_scan_id:
            message = f"HTTPS broker delivery exhausted after {lease.delivery_attempts} attempts"
            async with _pool().acquire() as conn:
                await _fail_broker_scan_and_reconcile_parent(
                    conn,
                    scan_id=exhausted_scan_id,
                    phase="queue_delivery_failed",
                    message=message,
                    redis_client=redis_client,
                )
        await asyncio.to_thread(acknowledge_lease, redis_client, lease)
        return Response(status_code=204)
    try:
        candidate_scan_id = uuid.UUID(str(payload.get("scan_id") or ""))
    except ValueError:
        # Broker execution is Scan-only. A malformed owner must never bypass the
        # durable Scan lookup, target match, and execution-authority projection.
        await asyncio.to_thread(acknowledge_lease, redis_client, lease)
        return Response(status_code=204)
    async with _pool().acquire() as conn:
        state = await conn.fetchrow(
            """
            SELECT child.status, child.target_url, parent.status AS parent_status
            FROM scans child
            LEFT JOIN scans parent ON parent.id=child.parent_scan_id
            WHERE child.id=$1
            """,
            candidate_scan_id,
        )
    if not state or str(state["status"]) in {"completed", "failed", "cancelled"} or str(state.get("parent_status") or "") == "cancelled":
        await asyncio.to_thread(acknowledge_lease, redis_client, lease)
        return Response(status_code=204)
    if payload.get("schema_version") == SCAN_JOB_SCHEMA:
        try:
            canonical_materialized = await _materialize_control_plane_scan_job_v2(payload)
        except HTTPException as exc:
            async with _pool().acquire() as conn:
                await _fail_broker_scan_and_reconcile_parent(
                    conn,
                    scan_id=candidate_scan_id,
                    phase="scope_revalidation_failed",
                    message=str(exc.detail),
                    redis_client=redis_client,
                )
            await asyncio.to_thread(acknowledge_lease, redis_client, lease)
            return Response(status_code=204)
    execution_target = (
        canonical_materialized.get("target")
        if canonical_materialized is not None else payload.get("target")
    )
    target_matches = _broker_target_key(execution_target) == _broker_target_key(
        state.get("target_url")
    )
    if canonical_materialized is not None:
        materialized_options = canonical_materialized.get("options")
        target_matches = target_matches or bool(
            isinstance(materialized_options, Mapping)
            and materialized_options.get("target_scheme_inferred")
            and _broker_target_authority(execution_target)
            == _broker_target_authority(state.get("target_url"))
        )
    if not target_matches:
        async with _pool().acquire() as conn:
            await _fail_broker_scan_and_reconcile_parent(
                conn,
                scan_id=candidate_scan_id,
                phase="scope_revalidation_failed",
                message="queued target does not match the durable scan target",
                redis_client=redis_client,
            )
        await asyncio.to_thread(acknowledge_lease, redis_client, lease)
        return Response(status_code=204)

    broker_candidate_plan = None
    broker_requires_private_inputs = False
    if (
        canonical_materialized is not None
        and is_deterministic_dast(canonical_materialized.get("options"))
        and candidate_scan_id is not None
    ):
        async with _pool().acquire() as conn:
            broker_candidate_plan = await PostgresScanActionStore().load_plan(
                conn, scan_id=str(candidate_scan_id),
            )
        broker_requires_private_inputs = bool(
            broker_candidate_plan is not None
            and _broker_action_plan_requires_local_private_inputs(
                broker_candidate_plan,
            )
        )
        if broker_requires_private_inputs and not body.private_input_public_key:
            local_payload = dict(queued_payload)
            local_payload["placement"] = {"node_scope": "local"}
            enqueue_job(
                redis_client,
                str(local_payload.get("_base_queue_name") or QUEUE_NAME),
                local_payload,
            )
            await asyncio.to_thread(acknowledge_lease, redis_client, lease)
            return Response(status_code=204)

    private_input_probe = canonical_materialized or payload
    if (
        _broker_job_has_private_inputs(private_input_probe)
        and not broker_requires_private_inputs
    ):
        # Legacy/non-canonical execution has no action-bound sealed-input
        # contract.  Keep it local instead of placing credentials or exact
        # imported requests in an HTTPS broker lease response.
        local_payload = dict(queued_payload)
        local_payload["placement"] = {"node_scope": "local"}
        enqueue_job(
            redis_client,
            str(local_payload.get("_base_queue_name") or QUEUE_NAME),
            local_payload,
        )
        await asyncio.to_thread(acknowledge_lease, redis_client, lease)
        return Response(status_code=204)

    slot_id = _broker_slot_id(str(lease.stream_key), str(lease.message_id))
    broker_cap = await _broker_active_scan_cap()
    if not _broker_take_or_refresh_slot(redis_client, slot_id, cap=broker_cap):
        enqueue_job(
            redis_client,
            str(queued_payload.get("_base_queue_name") or QUEUE_NAME),
            queued_payload,
        )
        await asyncio.to_thread(acknowledge_lease, redis_client, lease)
        return Response(status_code=204)

    raw_token = _generate_fleet_secret("bjl_")
    payload_hash = hashlib.sha256(lease.payload.encode("utf-8")).hexdigest()
    scan_id = candidate_scan_id
    expires_at = utc_now() + timedelta(seconds=BROKER_LEASE_SECONDS)
    budget_reservation: dict[str, Any] | None = None
    durable_scan_execution: dict[str, Any] | None = None
    durable_scan_terminal = None
    scan_action_plan_payload: dict[str, Any] | None = None
    scan_action_plan_revision_payload: dict[str, Any] | None = None
    action_worker_id: str | None = None
    private_scan_inputs: dict[str, Any] | None = None
    row = None
    if canonical_materialized is not None:
        payload = _broker_execution_projection(canonical_materialized)
    async with _pool().acquire() as conn, conn.transaction():
        if broker_requires_private_inputs:
            payload = await _hydrate_broker_job_options(conn, payload)
        budget_reservation = await _broker_reserve_request_budget(conn, redis_client, payload)
        if budget_reservation is None:
            await _mark_broker_budget_wait(conn, payload)
        if (
            budget_reservation is not None
            and canonical_materialized is not None
            and is_deterministic_dast(payload.get("options"))
        ):
            normalized_options, scan_admission = prepare_worker_dispatch(
                payload.get("options") or {}
            )
            if not scan_admission.canonical or scan_admission.plan is None:
                raise HTTPException(
                    status_code=409,
                    detail="broker Scan lost canonical execution authority",
                )
            try:
                action_store = PostgresScanActionStore()
                persisted_action_plan = await action_store.load_plan(
                    conn, scan_id=str(payload.get("scan_id") or ""),
                )
                persisted_plan_revision = await action_store.load_plan_revision(
                    conn, scan_id=str(payload.get("scan_id") or ""),
                )
            except Exception as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            native_execution = build_native_scan_execution(
                scan_admission.plan, normalized_options,
            )
            if (
                persisted_action_plan is None
                or persisted_plan_revision is None
                or persisted_plan_revision.plan_digest
                != persisted_action_plan.plan_digest
                or persisted_action_plan.execution_plan_digest
                != native_execution.execution_plan.digest
                or persisted_action_plan.target_binding_digest
                != native_execution.target_binding.digest
            ):
                raise HTTPException(
                    status_code=409,
                    detail="broker Scan action plan conflicts with runtime authority",
                )
            broker_candidate_plan = persisted_action_plan
            scan_action_plan_payload = persisted_action_plan.canonical_dict()
            scan_action_plan_revision_payload = (
                persisted_plan_revision.canonical_dict()
            )
            action_worker_id = f"broker:{body.worker_id}"
        if budget_reservation is not None:
            await conn.execute(
                """
                UPDATE broker_job_leases
                SET status='lost', completed_at=NOW()
                WHERE stream_key=$1 AND message_id=$2
                  AND status='leased' AND lease_expires_at < NOW()
                """,
                lease.stream_key,
                lease.message_id,
            )
            row = await conn.fetchrow(
                """
                INSERT INTO broker_job_leases (
                    node_id, worker_id, queue_name, stream_key, message_id, consumer_name,
                    lease_token_hash, payload_sha256, budget_reservation, job_id, scan_id,
                    delivery_attempts, lease_expires_at
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13)
                ON CONFLICT (stream_key, message_id) DO UPDATE
                SET node_id=EXCLUDED.node_id,
                    worker_id=EXCLUDED.worker_id,
                    consumer_name=EXCLUDED.consumer_name,
                    lease_token_hash=EXCLUDED.lease_token_hash,
                    status='leased',
                    delivery_attempts=EXCLUDED.delivery_attempts,
                    lease_expires_at=EXCLUDED.lease_expires_at,
                    last_heartbeat_at=NOW(),
                    completed_at=NULL
                WHERE broker_job_leases.status IN ('lost','failed','cancelled')
                RETURNING id
                """,
                parsed_node_id,
                body.worker_id,
                lease.queue_name,
                lease.stream_key,
                lease.message_id,
                consumer_name,
                _hash_fleet_secret(raw_token, "broker-job-lease"),
                payload_hash,
                json.dumps(budget_reservation),
                str(payload.get("job_id") or "") or None,
                scan_id,
                lease.delivery_attempts,
                expires_at,
            )
        if row and scan_id:
            execution_context = {
                "node_id": node_id,
                "node_name": str(node.get("name") or "") or None,
                "worker_id": f"broker:{body.worker_id}",
                "worker_build_fingerprint": str(node.get("build_fingerprint") or "") or None,
                "worker_image_digest": str(node.get("active_worker_image_digest") or node.get("worker_image_digest") or "") or None,
                "node_agent_version": str(node.get("agent_version") or "") or None,
                "region": str(node.get("region") or "") or None,
                "egress_ip": str(node.get("egress_ip") or "") or None,
                "transport": "broker",
                "credential_scope": "broker_job_lease",
                "lease_id": str(row["id"]),
            }
            await conn.execute(
                """
                UPDATE scans
                SET executing_node_id=$2,
                    worker_id=$3,
                    execution_context=$4::jsonb,
                    status='running',
                    started_at=COALESCE(started_at, NOW()),
                    current_phase='broker_execution',
                    progress=GREATEST(progress, 5)
                WHERE id=$1 AND status IN ('pending','queued','running')
                """,
                scan_id,
                parsed_node_id,
                f"broker:{body.worker_id}",
                json.dumps(execution_context, sort_keys=True, separators=(",", ":")),
            )
        if row:
            await _record_fleet_node_event(
                conn,
                node_id=parsed_node_id,
                event_type="broker_lease_started",
                actor_type="broker",
                details={
                    "lease_id": str(row["id"]),
                    "scan_id": str(scan_id) if scan_id else None,
                    "worker_id": body.worker_id,
                    "delivery_attempts": lease.delivery_attempts,
                    "queue_name": lease.queue_name,
                },
            )
        if row and broker_requires_private_inputs:
            if (
                broker_candidate_plan is None
                or action_worker_id is None
                or not body.private_input_public_key
            ):
                raise HTTPException(
                    status_code=409,
                    detail="broker private Scan input authority is incomplete",
                )
            payload, private_payload = await _build_broker_private_scan_payload(
                conn,
                payload=payload,
                plan=broker_candidate_plan,
                lease_id=str(row["id"]),
                worker_id=action_worker_id,
                expires_at=expires_at,
            )
            authority = {
                "lease_id": str(row["id"]),
                "worker_id": action_worker_id,
                "plan_digest": broker_candidate_plan.plan_digest,
                "target_binding_digest": (
                    broker_candidate_plan.target_binding_digest
                ),
                "expires_at": expires_at.isoformat(),
            }
            try:
                private_scan_inputs = seal_private_input(
                    private_payload,
                    recipient_public_key=body.private_input_public_key,
                    authority=authority,
                )
            except SealedInputError as exc:
                raise HTTPException(
                    status_code=409,
                    detail="broker private Scan inputs could not be sealed",
                ) from exc
    if budget_reservation is None:
        _broker_release_slot(redis_client, slot_id)
        if durable_scan_terminal is not None:
            if durable_scan_terminal.record.status == "committed" and scan_id:
                async with _pool().acquire() as conn:
                    prior_result = await conn.fetchrow(
                        """
                        SELECT l.id AS lease_id, l.budget_reservation,
                               r.id AS result_id
                        FROM broker_job_leases l
                        JOIN broker_job_results r ON r.lease_id=l.id
                        WHERE l.scan_id=$1
                          AND l.status IN ('submitted','ingesting','completed','failed')
                        ORDER BY r.submitted_at DESC
                        LIMIT 1
                        """,
                        scan_id,
                    )
                if prior_result:
                    ingest_payload = copy.deepcopy(queued_payload)
                    if ingest_payload.get("schema_version") == SCAN_JOB_SCHEMA:
                        materialized = await _materialize_control_plane_scan_job_v2(
                            ingest_payload, revalidate_dns=False,
                        )
                        ingest_payload = _broker_execution_projection(materialized)
                    ingest_payload["_broker_result_id"] = str(prior_result["result_id"])
                    ingest_payload["_broker_lease_id"] = str(prior_result["lease_id"])
                    ingest_payload = _control_plane_broker_ingest_payload(
                        ingest_payload
                    )
                    prior_rate = parse_json_field(
                        prior_result.get("budget_reservation")
                    ) or {}
                    if isinstance(prior_rate, dict) and prior_rate:
                        ingest_options = dict(ingest_payload.get("options") or {})
                        ingest_options["request_budget_mode"] = str(
                            prior_rate.get("request_budget_mode") or "enforce"
                        )
                        ingest_options["custom_budget"] = dict(
                            prior_rate.get("custom_budget") or {}
                        )
                        ingest_options["request_budget_reserved"] = max(
                            0, int(prior_rate.get("granted") or 0),
                        )
                        if prior_rate.get("root_domain"):
                            ingest_options["request_budget_domain"] = str(
                                prior_rate["root_domain"]
                            )
                        ingest_payload["options"] = ingest_options
                        ingest_payload["domain_rate_reserved"] = max(
                            0, int(prior_rate.get("granted") or 0),
                        )
                    enqueue_job(
                        redis_client, BROKER_INGEST_QUEUE_NAME, ingest_payload,
                    )
                    async with _pool().acquire() as conn:
                        await conn.execute(
                            "UPDATE broker_job_leases "
                            "SET ingest_enqueued_at=COALESCE(ingest_enqueued_at, NOW()) "
                            "WHERE id=$1",
                            prior_result["lease_id"],
                        )
            if durable_scan_terminal.record.status != "committed" and scan_id:
                async with _pool().acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE scans
                        SET status='failed', progress=100,
                            current_phase='budget_reservation_failed',
                            error_message='deterministic Scan budget reservation failed',
                            completed_at=NOW()
                        WHERE id=$1 AND status IN ('pending','queued','running')
                        """,
                        scan_id,
                    )
            await asyncio.to_thread(
                acknowledge_lease, redis_client, lease,
            )
            return Response(status_code=204)
        enqueue_job(
            redis_client,
            str(queued_payload.get("_base_queue_name") or QUEUE_NAME),
            queued_payload,
        )
        await asyncio.to_thread(acknowledge_lease, redis_client, lease)
        return Response(status_code=204)
    if not row:
        _broker_release_slot(redis_client, slot_id)
        raise HTTPException(status_code=409, detail="queue message already has an active broker lease")
    if payload.get("job_id"):
        redis_client.hset(
            f"job:{payload['job_id']}",
            mapping={
                "status": "running",
                "scan_id": str(payload.get("scan_id") or ""),
                "current_phase": "broker_execution",
                "progress": "5",
                "heartbeat": utc_now_iso(),
                "broker_node_id": node_id,
                "broker_worker_id": body.worker_id,
            },
        )
        redis_client.expire(f"job:{payload['job_id']}", 86400)
    return JSONResponse(
        content={
            "lease_id": str(row["id"]),
            "lease_token": raw_token,
            "lease_expires_at": expires_at.isoformat(),
            "heartbeat_interval_seconds": max(10, BROKER_LEASE_SECONDS // 3),
            "job": payload,
            "scan_execution": durable_scan_execution,
            "scan_action_plan": scan_action_plan_payload,
            "scan_action_plan_revision": scan_action_plan_revision_payload,
            "action_worker_id": action_worker_id,
            "private_scan_inputs": private_scan_inputs,
        },
        headers={"Cache-Control": "no-store"},
    )


@router.post("/fleet/broker/nodes/{node_id}/leases/{lease_id}/actions/{action_id}/lease")
async def lease_broker_scan_action(
    node_id: str,
    lease_id: str,
    action_id: str,
    body: BrokerActionAuthorityRequest,
    request: Request,
):
    await _broker_authenticated_node(node_id, request)
    if action_id != body.action_id:
        raise HTTPException(status_code=409, detail="broker action path differs from body")
    async with _pool().acquire() as conn, conn.transaction():
        _row, plan, job, action, backend = await _broker_action_context(
            conn,
            node_id=node_id,
            lease_id=lease_id,
            job_lease_token=body.job_lease_token,
            worker_id=body.worker_id,
            plan_digest=body.plan_digest,
            action_id=body.action_id,
            action_digest=body.action_digest,
        )
        existing = await backend.load_result_with_connection(
            conn, action.action_id,
        )
        if existing is not None:
            return JSONResponse(
                status_code=208,
                content={"detail": "broker Scan action is already terminal"},
            )
        if await backend.cancellation_requested_with_connection(conn):
            try:
                await backend.cancel_action_with_connection(
                    conn, action,
                )
            except ScanExecutionBackendError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            return JSONResponse(
                status_code=208,
                content={"detail": "broker Scan action was cancelled before execution"},
            )
        await _revalidate_broker_action_authority(
            conn, action=action, canonical_job=job,
        )
        try:
            action_lease = await backend.acquire_action_with_connection(
                conn, action,
            )
        except ActionAlreadyTerminal:
            return JSONResponse(
                status_code=208,
                content={"detail": "broker Scan action is already terminal"},
            )
        except ScanExecutionBackendError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"action_lease": action_lease.remote_payload()}


@router.post("/fleet/broker/nodes/{node_id}/leases/{lease_id}/actions/{action_id}/cancel")
async def cancel_broker_scan_action(
    node_id: str,
    lease_id: str,
    action_id: str,
    body: BrokerActionAuthorityRequest,
    request: Request,
):
    """Settle a broker action after cancellation without issuing a lease."""
    await _broker_authenticated_node(node_id, request)
    if action_id != body.action_id:
        raise HTTPException(
            status_code=409, detail="broker action path differs from body",
        )
    async with _pool().acquire() as conn, conn.transaction():
        _row, _plan, _job, action, backend = await _broker_action_context(
            conn,
            node_id=node_id,
            lease_id=lease_id,
            job_lease_token=body.job_lease_token,
            worker_id=body.worker_id,
            plan_digest=body.plan_digest,
            action_id=body.action_id,
            action_digest=body.action_digest,
        )
        try:
            stored = await backend.cancel_action_with_connection(conn, action)
        except ScanExecutionBackendError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"result": stored.canonical_dict()}


@router.post("/fleet/broker/nodes/{node_id}/leases/{lease_id}/actions/{action_id}/heartbeat")
async def heartbeat_broker_scan_action(
    node_id: str,
    lease_id: str,
    action_id: str,
    body: BrokerActionLeaseRequest,
    request: Request,
):
    await _broker_authenticated_node(node_id, request)
    if action_id != body.action_id:
        raise HTTPException(status_code=409, detail="broker action path differs from body")
    async with _pool().acquire() as conn:
        _row, plan, job, action, backend = await _broker_action_context(
            conn,
            node_id=node_id,
            lease_id=lease_id,
            job_lease_token=body.job_lease_token,
            worker_id=body.worker_id,
            plan_digest=body.plan_digest,
            action_id=body.action_id,
            action_digest=body.action_digest,
        )
    action_lease = _broker_submitted_action_lease(
        body.action_lease, plan=plan, action=action, worker_id=body.worker_id,
    )
    try:
        await backend.heartbeat(action_lease)
    except (ActionLeaseLost, ScanExecutionBackendError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": "running"}


@router.post("/fleet/broker/nodes/{node_id}/leases/{lease_id}/actions/{action_id}/result")
async def settle_broker_scan_action(
    node_id: str,
    lease_id: str,
    action_id: str,
    body: BrokerActionResultRequest,
    request: Request,
):
    await _broker_authenticated_node(node_id, request)
    if action_id != body.action_id:
        raise HTTPException(status_code=409, detail="broker action path differs from body")
    async with _pool().acquire() as conn:
        _row, plan, job, action, backend = await _broker_action_context(
            conn,
            node_id=node_id,
            lease_id=lease_id,
            job_lease_token=body.job_lease_token,
            worker_id=body.worker_id,
            plan_digest=body.plan_digest,
            action_id=body.action_id,
            action_digest=body.action_digest,
        )
    action_lease = _broker_submitted_action_lease(
        body.action_lease, plan=plan, action=action, worker_id=body.worker_id,
    )
    try:
        receipt = CapabilityReceipt.from_dict(body.receipt)
        if (
            receipt.worker_id != body.worker_id
            or receipt.target_id != job.target.target_id
            or receipt.scope_receipt_id != job.target.scope_receipt_id
            or receipt.approval_receipt_id
            != job.execution_plan.policy.approval_receipt_id
        ):
            raise ValueError("broker action receipt authority changed")
        stored = await backend.settle(action_lease, receipt)
    except (ValueError, ActionLeaseLost, ScanExecutionBackendError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"result": stored.canonical_dict()}


@router.post("/fleet/broker/nodes/{node_id}/leases/{lease_id}/actions/{action_id}/status")
async def get_broker_scan_action_status(
    node_id: str,
    lease_id: str,
    action_id: str,
    body: BrokerActionAuthorityRequest,
    request: Request,
):
    await _broker_authenticated_node(node_id, request)
    if action_id != body.action_id:
        raise HTTPException(status_code=409, detail="broker action path differs from body")
    async with _pool().acquire() as conn:
        _row, _plan, _job, action, backend = await _broker_action_context(
            conn,
            node_id=node_id,
            lease_id=lease_id,
            job_lease_token=body.job_lease_token,
            worker_id=body.worker_id,
            plan_digest=body.plan_digest,
            action_id=body.action_id,
            action_digest=body.action_digest,
        )
    stored = await backend.load_result(action.action_id)
    return {"result": stored.canonical_dict() if stored is not None else None}


@router.post("/fleet/broker/nodes/{node_id}/leases/{lease_id}/actions/{action_id}/observations")
async def get_broker_scan_action_observations(
    node_id: str,
    lease_id: str,
    action_id: str,
    body: BrokerActionAuthorityRequest,
    request: Request,
):
    await _broker_authenticated_node(node_id, request)
    if action_id != body.action_id:
        raise HTTPException(status_code=409, detail="broker action path differs from body")
    async with _pool().acquire() as conn:
        _row, plan, _job, action, backend = await _broker_action_context(
            conn,
            node_id=node_id,
            lease_id=lease_id,
            job_lease_token=body.job_lease_token,
            worker_id=body.worker_id,
            plan_digest=body.plan_digest,
            action_id=body.action_id,
            action_digest=body.action_digest,
        )
        stored = await backend.load_result_with_connection(
            conn, action.action_id,
        )
        if stored is None:
            raise HTTPException(status_code=409, detail="broker action is not terminal")
        if stored.observation_manifest_ref is None:
            return {"observations": []}
        observations = await PostgresObservationManifestStore().load(
            conn,
            reference=stored.observation_manifest_ref,
            scan_id=plan.scan_id,
            action_id=action.action_id,
        )
    if observations is None:
        raise HTTPException(
            status_code=409, detail="broker action observation manifest is unavailable",
        )
    return {"observations": [dict(item) for item in observations]}


@router.post(
    "/fleet/broker/nodes/{node_id}/leases/{lease_id}"
    "/actions/{action_id}/work-manifest"
)
async def get_broker_scan_action_work_manifest(
    node_id: str,
    lease_id: str,
    action_id: str,
    body: BrokerActionWorkManifestRequest,
    request: Request,
):
    """Return one exact, value-free work manifest authorized by an action."""
    await _broker_authenticated_node(node_id, request)
    if action_id != body.action_id:
        raise HTTPException(status_code=409, detail="broker action path differs from body")
    try:
        requested = ScanWorkManifestReference.from_dict(body.manifest_ref)
    except (ScanWorkManifestError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=409,
            detail="broker work manifest reference is invalid",
        ) from exc
    async with _pool().acquire() as conn:
        _row, plan, _job, action, _backend = await _broker_action_context(
            conn,
            node_id=node_id,
            lease_id=lease_id,
            job_lease_token=body.job_lease_token,
            worker_id=body.worker_id,
            plan_digest=body.plan_digest,
            action_id=body.action_id,
            action_digest=body.action_digest,
        )
        if requested not in _broker_action_work_manifest_references(action):
            raise HTTPException(
                status_code=409,
                detail="broker work manifest is absent from immutable action authority",
            )
        try:
            manifest = await PostgresScanManifestStore().load(
                conn,
                manifest_id=requested.manifest_id,
                scan_id=plan.scan_id,
                expected_kind=requested.kind,
                expected_digest=requested.manifest_digest,
                expected_target_binding_digest=plan.target_binding_digest,
            )
        except ScanManifestStoreError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    if manifest is None or manifest.reference() != requested:
        raise HTTPException(
            status_code=409, detail="broker work manifest is unavailable",
        )
    return {"manifest": manifest.canonical_dict()}


@router.post("/fleet/broker/nodes/{node_id}/leases/{lease_id}/continuation")
async def continue_broker_scan_action_plan(
    node_id: str,
    lease_id: str,
    body: BrokerScanContinuationRequest,
    request: Request,
):
    """Apply the one preallocated discovery-derived Scan continuation."""
    await _broker_authenticated_node(node_id, request)
    async with _pool().acquire() as conn, conn.transaction():
        lease_row = await _broker_lease_row(
            conn,
            node_id=node_id,
            lease_id=lease_id,
            lease_token=body.job_lease_token,
        )
        if str(lease_row.get("status") or "") != "leased":
            raise HTTPException(
                status_code=409,
                detail=f"broker lease is {lease_row['status']}",
            )
        if (
            lease_row.get("lease_expires_at") is None
            or lease_row["lease_expires_at"] <= utc_now()
        ):
            raise HTTPException(status_code=410, detail="broker job lease expired")
        if body.worker_id != f"broker:{str(lease_row.get('worker_id') or '')}":
            raise HTTPException(
                status_code=409,
                detail="broker continuation worker differs from job lease",
            )
        scan_id = str(lease_row.get("scan_id") or "")
        if not scan_id:
            raise HTTPException(status_code=409, detail="broker job has no Scan owner")
        action_store = PostgresScanActionStore()
        allocation = await action_store.load_continuation_allocation(
            conn, scan_id=scan_id,
        )
        if (
            allocation is None
            or allocation.allocation_digest != body.allocation_digest
            or allocation.parent_plan_digest != body.plan_digest
        ):
            raise HTTPException(
                status_code=409,
                detail="broker continuation allocation authority changed",
            )
        current_plan = await action_store.load_plan(conn, scan_id=scan_id)
        if current_plan is None:
            raise HTTPException(
                status_code=409, detail="broker Scan action plan is unavailable",
            )
        scan_row = await conn.fetchrow(
            """
            SELECT status, target_id, target_url, options, scan_job_payload,
                   scan_continuation_applied_at
            FROM scans WHERE id=$1
            """,
            uuid.UUID(scan_id),
        )
        if not scan_row or str(scan_row.get("status") or "") in {
            "cancelled", "cancelling",
        }:
            raise HTTPException(status_code=409, detail="broker Scan is cancelled")
        raw_job = parse_json_field(scan_row.get("scan_job_payload")) or {}
        try:
            canonical_job = CanonicalScanJob.from_payload(raw_job)
        except CanonicalScanJobError as exc:
            raise HTTPException(
                status_code=409, detail="broker Scan job authority is invalid",
            ) from exc
        if (
            canonical_job.scan_id != allocation.scan_id
            or canonical_job.execution_plan.digest
            != allocation.execution_plan_digest
            or canonical_job.target.digest != allocation.target_binding_digest
        ):
            raise HTTPException(
                status_code=409,
                detail="broker continuation job authority changed",
            )
        options = parse_json_field(scan_row.get("options")) or {}
        options["_continuation_target_url"] = str(scan_row.get("target_url") or "")
        if current_plan.plan_digest == allocation.parent_plan_digest:
            target_active = await conn.fetchval(
                "SELECT is_active FROM targets WHERE id=$1",
                uuid.UUID(str(canonical_job.target.target_id)),
            )
            if target_active is not True:
                raise HTTPException(
                    status_code=409, detail="broker Scan target is inactive",
                )
            amended, revision, continuation_options = (
                await _materialize_broker_scan_continuation(
                    conn,
                    parent_plan=current_plan,
                    canonical_job=canonical_job,
                    options=options,
                    allocation=allocation,
                    worker_id=body.worker_id,
                )
            )
        else:
            if (
                scan_row.get("scan_continuation_applied_at") is None
                or tuple(
                    action.action_id
                    for action in current_plan.actions[:len(allocation.parent_action_ids)]
                ) != allocation.parent_action_ids
                or current_plan.actions[-1].action_id != "finalize.report"
            ):
                raise HTTPException(
                    status_code=409,
                    detail="broker Scan plan changed outside continuation authority",
                )
            amended = current_plan
            revision = await action_store.load_plan_revision(
                conn, scan_id=scan_id,
            )
            if revision is None or revision.plan_digest != amended.plan_digest:
                raise HTTPException(
                    status_code=409,
                    detail="broker Scan continuation revision is unavailable",
                )
            continuation_options = {
                key: options[key]
                for key in (
                    "endpoint_manifest_id", "endpoint_manifest_ref",
                    "candidate_manifest_ref", "request_candidate_manifest_ref",
                    "scan_continuation_plan_digest",
                    "scan_plan_revision",
                )
                if key in options
            }
    return {
        "plan": amended.canonical_dict(),
        "options": continuation_options,
        "allocation_digest": allocation.allocation_digest,
        "plan_revision": revision.canonical_dict(),
    }


@router.post("/fleet/broker/nodes/{node_id}/leases/{lease_id}/cancel-status")
async def get_broker_scan_cancel_status(
    node_id: str,
    lease_id: str,
    body: BrokerActionCancelStatusRequest,
    request: Request,
):
    await _broker_authenticated_node(node_id, request)
    async with _pool().acquire() as conn:
        _row, _plan, _job, _action, backend = await _broker_action_context(
            conn,
            node_id=node_id,
            lease_id=lease_id,
            job_lease_token=body.job_lease_token,
            worker_id=body.worker_id,
            plan_digest=body.plan_digest,
        )
        cancel_requested = await backend.cancellation_requested_with_connection(
            conn,
        )
    return {"cancel_requested": cancel_requested}


@router.post("/fleet/broker/nodes/{node_id}/leases/{lease_id}/heartbeat")
async def heartbeat_broker_job(
    node_id: str,
    lease_id: str,
    body: BrokerLeaseHeartbeatRequest,
    request: Request,
):
    await _broker_authenticated_node(node_id, request)
    async with _pool().acquire() as conn:
        row = await _broker_lease_row(
            conn,
            node_id=node_id,
            lease_id=lease_id,
            lease_token=body.lease_token,
        )
    if str(row["status"]) != "leased":
        raise HTTPException(status_code=409, detail=f"broker lease is {row['status']}")
    slot_id = _broker_slot_id(str(row["stream_key"]), str(row["message_id"]))
    broker_cap = await _broker_active_scan_cap()
    if not _broker_take_or_refresh_slot(get_redis(), slot_id, cap=broker_cap):
        raise HTTPException(status_code=409, detail="broker fleet admission slot was lost")
    owned = await asyncio.to_thread(
        heartbeat_lease,
        get_redis(),
        _queue_lease_from_broker_row(row),
        str(row["consumer_name"]),
    )
    if not owned:
        _broker_release_slot(get_redis(), slot_id)
        async with _pool().acquire() as conn:
            await conn.execute(
                "UPDATE broker_job_leases SET status='lost', completed_at=NOW() WHERE id=$1",
                row["id"],
            )
        raise HTTPException(status_code=409, detail="broker queue lease ownership was lost")
    expires_at = utc_now() + timedelta(seconds=BROKER_LEASE_SECONDS)
    async with _pool().acquire() as conn, conn.transaction():
        row = await _broker_lease_row(
            conn,
            node_id=node_id,
            lease_id=lease_id,
            lease_token=body.lease_token,
            for_update=True,
        )
        reservation = parse_json_field(row.get("budget_reservation")) or {}
        durable_execution = (
            reservation.get("durable_scan_execution")
            if isinstance(reservation, dict) else None
        )
        if isinstance(durable_execution, Mapping):
            try:
                await heartbeat_broker_scan_execution(
                    conn,
                    metadata=durable_execution,
                    lease_seconds=BROKER_LEASE_SECONDS,
                )
            except BrokerScanExecutionError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
        scan_status = None
        if row.get("scan_id"):
            scan_status = await conn.fetchval("SELECT status FROM scans WHERE id=$1", row["scan_id"])
            if body.phase is not None or body.progress is not None:
                await conn.execute(
                    """
                    UPDATE scans
                    SET current_phase=COALESCE($2, current_phase),
                        progress=COALESCE($3, progress)
                    WHERE id=$1 AND status='running'
                    """,
                    row["scan_id"],
                    body.phase,
                    body.progress,
                )
        await conn.execute(
            """
            UPDATE broker_job_leases
            SET lease_expires_at=$2, last_heartbeat_at=NOW()
            WHERE id=$1 AND status='leased'
            """,
            row["id"],
            expires_at,
        )
    if row.get("job_id"):
        redis_client = get_redis()
        mapping = {"heartbeat": utc_now_iso(), "status": "running"}
        if body.phase is not None:
            mapping["current_phase"] = body.phase
        if body.progress is not None:
            mapping["progress"] = str(body.progress)
        redis_client.hset(f"job:{row['job_id']}", mapping=mapping)
        if body.log_lines:
            key = f"scan:{row['scan_id']}:logs"
            redis_client.rpush(key, *body.log_lines)
            redis_client.ltrim(key, -1000, -1)
            redis_client.expire(key, 86400)
    return {
        "lease_id": lease_id,
        "lease_expires_at": expires_at.isoformat(),
        "cancel_requested": str(scan_status or "") == "cancelled",
    }


@router.post("/fleet/broker/nodes/{node_id}/leases/{lease_id}/result", status_code=202)
async def submit_broker_job_result(
    node_id: str,
    lease_id: str,
    body: BrokerResultRequest,
    request: Request,
):
    await _broker_authenticated_node(node_id, request)
    result_payload = copy.deepcopy(body.result)
    async with _pool().acquire() as conn:
        async with conn.transaction():
            row = await _broker_lease_row(
                conn,
                node_id=node_id,
                lease_id=lease_id,
                lease_token=body.lease_token,
                for_update=True,
            )
            if str(row["status"]) not in {"leased", "submitted", "ingesting", "completed", "failed", "cancelled"}:
                raise HTTPException(status_code=409, detail=f"broker lease is {row['status']}")
            if (
                str(row["status"]) == "leased"
                and row.get("lease_expires_at") is not None
                and row["lease_expires_at"] < utc_now()
            ):
                raise HTTPException(
                    status_code=409,
                    detail="broker lease expired before result submission",
                )
            if row.get("scan_id") and str(result_payload.get("scan_id") or "") != str(row["scan_id"]):
                raise HTTPException(
                    status_code=409,
                    detail="broker result does not match its Scan lease",
                )
            if row.get("job_id") and str(result_payload.get("job_id") or "") != str(row["job_id"]):
                raise HTTPException(
                    status_code=409,
                    detail="broker result does not match its job lease",
                )
            reservation = parse_json_field(row.get("budget_reservation")) or {}
            durable_execution = (
                reservation.get("durable_scan_execution")
                if isinstance(reservation, dict) else None
            )
            if isinstance(durable_execution, Mapping):
                try:
                    _settled, execution_summary = (
                        await settle_broker_scan_execution(
                            conn,
                            metadata=durable_execution,
                            result=result_payload,
                        )
                    )
                except BrokerScanExecutionError as exc:
                    raise HTTPException(status_code=409, detail=str(exc)) from exc
                # This field is part of the immutable result hash. Keep it
                # stable when the same result is submitted again.
                execution_summary["idempotent_redelivery"] = False
                result_payload["deterministic_scan_execution"] = execution_summary
            encoded = json.dumps(
                result_payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            if len(encoded) > BROKER_MAX_RESULT_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="broker result exceeds configured size limit",
                )
            result_hash = hashlib.sha256(encoded).hexdigest()
            result_row = await conn.fetchrow(
                """
                INSERT INTO broker_job_results (lease_id, result_sha256, result)
                VALUES ($1,$2,$3::jsonb)
                ON CONFLICT (lease_id) DO UPDATE
                SET result_sha256=broker_job_results.result_sha256
                WHERE broker_job_results.result_sha256=EXCLUDED.result_sha256
                RETURNING id, result_sha256
                """,
                row["id"],
                result_hash,
                encoded.decode("utf-8"),
            )
            if not result_row:
                raise HTTPException(status_code=409, detail="a different result was already submitted")
            await conn.execute(
                "UPDATE broker_job_leases SET status='submitted' WHERE id=$1 AND status='leased'",
                row["id"],
            )
            if str(row["status"]) == "leased":
                await _record_fleet_node_event(
                    conn,
                    node_id=node_id,
                    event_type="broker_result_submitted",
                    actor_type="broker",
                    details={
                        "lease_id": lease_id,
                        "scan_id": str(row.get("scan_id") or "") or None,
                        "result_sha256": result_hash,
                    },
                )

    if str(row["status"]) != "leased":
        record_operational_event(get_redis(), "broker_duplicate_result")

    if row.get("ingest_enqueued_at"):
        redis_client = get_redis()
        await asyncio.to_thread(
            acknowledge_lease,
            redis_client,
            _queue_lease_from_broker_row(row),
        )
        _broker_release_slot(
            redis_client,
            _broker_slot_id(str(row["stream_key"]), str(row["message_id"])),
        )
        return {"lease_id": lease_id, "result_id": str(result_row["id"]), "status": "submitted"}

    redis_client = get_redis()
    raw_rows = redis_client.xrange(str(row["stream_key"]), min=str(row["message_id"]), max=str(row["message_id"]))
    if not raw_rows:
        raise HTTPException(status_code=409, detail="broker queue message is no longer available")
    fields = raw_rows[0][1]
    raw_payload = fields.get("payload") or fields.get(b"payload")
    try:
        job_payload = json.loads(raw_payload)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="broker queue payload cannot be recovered") from exc
    if isinstance(job_payload, Mapping) and job_payload.get("schema_version") == SCAN_JOB_SCHEMA:
        materialized = await _materialize_control_plane_scan_job_v2(
            job_payload, revalidate_dns=False,
        )
        job_payload = _broker_execution_projection(materialized)
    job_payload["_broker_result_id"] = str(result_row["id"])
    job_payload["_broker_lease_id"] = lease_id
    job_payload = _control_plane_broker_ingest_payload(job_payload)
    reservation = parse_json_field(row.get("budget_reservation")) or {}
    if isinstance(reservation, dict) and reservation:
        options = dict(job_payload.get("options") or {})
        options["request_budget_mode"] = str(reservation.get("request_budget_mode") or "enforce")
        options["custom_budget"] = dict(reservation.get("custom_budget") or {})
        options["request_budget_reserved"] = max(0, int(reservation.get("granted") or 0))
        if reservation.get("root_domain"):
            options["request_budget_domain"] = str(reservation["root_domain"])
        job_payload["options"] = options
        job_payload["domain_rate_reserved"] = max(0, int(reservation.get("granted") or 0))
    enqueue_job(redis_client, BROKER_INGEST_QUEUE_NAME, job_payload)
    async with _pool().acquire() as conn:
        await conn.execute(
            "UPDATE broker_job_leases SET ingest_enqueued_at=NOW() WHERE id=$1",
            row["id"],
        )
    acknowledged = await asyncio.to_thread(
        acknowledge_lease,
        redis_client,
        _queue_lease_from_broker_row(row),
    )
    if not acknowledged:
        raise HTTPException(status_code=409, detail="broker queue lease could not be acknowledged")
    _broker_release_slot(
        redis_client,
        _broker_slot_id(str(row["stream_key"]), str(row["message_id"])),
    )
    return {"lease_id": lease_id, "result_id": str(result_row["id"]), "status": "submitted"}


@router.put("/fleet/broker/nodes/{node_id}/leases/{lease_id}/artifacts")
async def upload_broker_job_artifact(
    node_id: str,
    lease_id: str,
    request: Request,
    artifact_type: str = Query(..., pattern=r"^(checkpoint|diagnostic|screenshot|attachment)$"),
    filename: str = Query(..., min_length=1, max_length=180),
    shard_index: Optional[int] = Query(default=None, ge=0),
):
    """Upload one lease-bound artifact without exposing object-store credentials."""
    await _broker_authenticated_node(node_id, request)
    lease_token = str(request.headers.get("x-shakerscan-lease-token") or "").strip()
    if len(lease_token) < 32:
        raise HTTPException(status_code=401, detail="broker lease token is required")
    async with _pool().acquire() as conn:
        row = await _broker_lease_row(
            conn,
            node_id=node_id,
            lease_id=lease_id,
            lease_token=lease_token,
        )
        if str(row["status"]) not in {"leased", "submitted", "ingesting"}:
            raise HTTPException(status_code=409, detail=f"broker lease is {row['status']}")
        scan_row = await conn.fetchrow(
            "SELECT parent_scan_id, shard_index FROM scans WHERE id=$1",
            row["scan_id"],
        )
    raw = await request.body()
    max_artifact_bytes = max(
        1_048_576,
        int(os.environ.get("SHAKERSCAN_BROKER_MAX_ARTIFACT_BYTES", str(32 * 1024 * 1024))),
    )
    if len(raw) > max_artifact_bytes:
        raise HTTPException(status_code=413, detail="broker artifact exceeds configured size limit")
    if not raw:
        raise HTTPException(status_code=422, detail="broker artifact is empty")
    safe_filename = Path(filename).name
    effective_shard = shard_index
    if effective_shard is None and scan_row and scan_row.get("shard_index") is not None:
        effective_shard = int(scan_row["shard_index"])
    content_type = str(request.headers.get("content-type") or "application/octet-stream").split(";", 1)[0]
    try:
        descriptor = await asyncio.to_thread(
            store_artifact_bytes,
            raw,
            results_dir=_results_dir(),
            scan_id=str(row["scan_id"]),
            artifact_type=artifact_type,
            shard_index=effective_shard,
            filename=safe_filename,
            content_type=content_type,
        )
        artifact_key = artifact_object_key(
            scan_id=str(row["scan_id"]),
            artifact_type=artifact_type,
            shard_index=effective_shard,
            filename=safe_filename,
        )
        async with _pool().acquire() as conn:
            manifest = await upsert_artifact_manifest(
                conn,
                scan_id=str(row["scan_id"]),
                parent_scan_id=str(scan_row["parent_scan_id"]) if scan_row and scan_row.get("parent_scan_id") else None,
                shard_index=effective_shard,
                artifact_type=artifact_type,
                artifact_key=artifact_key,
                descriptor=descriptor,
                metadata={"broker_lease_id": lease_id, "filename": safe_filename},
                executing_node_id=node_id,
            )
    except (ArtifactStorageError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"broker artifact persistence failed: {exc}") from exc
    return {
        "artifact_id": str(manifest["id"]),
        "content_sha256": descriptor["content_sha256"],
        "size_bytes": descriptor["size_bytes"],
        "url": f"/scans/{row['scan_id']}/artifacts/{manifest['id']}",
    }


@router.post("/fleet/nodes/{node_id}/connection-bundle")
async def get_fleet_connection_bundle(node_id: str, request: Request):
    """Deliver shared-store credentials once, only to an authenticated overlay peer."""
    _require_fleet_https(request)
    credential = _fleet_bearer_credential(request)
    peer = getattr(getattr(request, "client", None), "host", None)
    try:
        config = _fleet_bootstrap_config()
        if not _fleet_peer_is_overlay(peer, config.overlay_cidr):
            raise HTTPException(status_code=403, detail="connection bundle is available only over the fleet overlay")
        bundle = _fleet_connection_bundle()  # validate before committing one-time consumption
        async with _pool().acquire() as conn:
            async with conn.transaction():
                await _authenticate_fleet_node(conn, node_id=node_id, credential=credential)
                await _consume_fleet_connection_bundle(conn, node_id=node_id)
                await _record_fleet_node_event(
                    conn,
                    node_id=node_id,
                    event_type="connection_bundle_delivered",
                    actor_type="node",
                    details={"transport": "overlay", "delivered_once": True},
                )
        return JSONResponse(
            content={"node_id": node_id, "bundle": bundle, "delivered_once": True},
            headers={"Cache-Control": "no-store"},
        )
    except FleetConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except FleetAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except FleetConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/fleet/nodes/{node_id}/credentials/rotate")
async def rotate_fleet_node_credential(node_id: str, request: Request, response: Response):
    """Operator lifecycle action: revoke current credentials and return one replacement once."""
    _require_fleet_operator(request)
    response.headers["Cache-Control"] = "no-store"
    try:
        parsed_id = uuid.UUID(node_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="node not found") from exc
    raw_credential = _generate_fleet_secret("ssn_")
    async with _pool().acquire() as conn:
        async with conn.transaction():
            node = await conn.fetchrow("SELECT id FROM nodes WHERE id = $1 AND status <> 'disabled' FOR UPDATE", parsed_id)
            if not node:
                raise HTTPException(status_code=404, detail="node not found or disabled")
            version = await conn.fetchval(
                "SELECT COALESCE(MAX(credential_version), 0) + 1 FROM node_credentials WHERE node_id = $1",
                parsed_id,
            )
            await conn.execute(
                "UPDATE node_credentials SET revoked_at = NOW() WHERE node_id = $1 AND revoked_at IS NULL",
                parsed_id,
            )
            await conn.execute(
                """
                UPDATE nodes
                SET connection_bundle_delivered_at = NULL, updated_at = NOW()
                WHERE id = $1
                """,
                parsed_id,
            )
            await conn.execute(
                """
                INSERT INTO node_credentials (node_id, credential_hash, credential_version)
                VALUES ($1, $2, $3)
                """,
                parsed_id,
                _hash_fleet_secret(raw_credential, "node-credential"),
                int(version),
            )
            await _record_fleet_node_event(
                conn,
                node_id=parsed_id,
                event_type="node_credential_rotated",
                actor_type="operator",
                details={"credential_version": int(version)},
            )
    return {"node_id": node_id, "node_credential": raw_credential, "credential_version": int(version)}


@router.post("/fleet/nodes/{node_id}/revoke")
async def revoke_fleet_node(node_id: str, request: Request):
    """Disable a node and revoke every durable credential."""
    _require_fleet_operator(request)
    try:
        parsed_id = uuid.UUID(node_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="node not found") from exc
    async with _pool().acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                UPDATE nodes
                SET status = 'disabled', drain = true, active_worker_count = 0, updated_at = NOW()
                WHERE id = $1 RETURNING id
                """,
                parsed_id,
            )
            if not row:
                raise HTTPException(status_code=404, detail="node not found")
            await conn.execute(
                "UPDATE node_credentials SET revoked_at = COALESCE(revoked_at, NOW()) WHERE node_id = $1",
                parsed_id,
            )
            await _record_fleet_node_event(
                conn,
                node_id=parsed_id,
                event_type="node_revoked",
                actor_type="operator",
                severity="warning",
                details={"credentials_revoked": True},
            )
    return {"node_id": node_id, "status": "disabled", "credentials_revoked": True}


@router.get("/fleet/public-health", include_in_schema=False)
async def fleet_public_health():
    """Content-minimal health projection for the managed public gateway."""
    result = await health()
    return {"status": result.get("status", "degraded")}
BROKER_INGEST_QUEUE_NAME = os.environ.get("BROKER_INGEST_QUEUE_NAME", "broker_ingest_jobs")


BROKER_MAX_DELIVERY_ATTEMPTS = max(1, int(os.environ.get("SHAKERSCAN_QUEUE_MAX_DELIVERY_ATTEMPTS", "5")))


BROKER_MAX_RESULT_BYTES = max(1_048_576, int(os.environ.get("SHAKERSCAN_BROKER_MAX_RESULT_BYTES", str(64 * 1024 * 1024))))


class FleetJoinTokenRequest(BaseModel):
    role: str = Field(default="worker", pattern="^worker$")
    transport: str = Field(default="overlay", pattern="^(overlay|broker)$")
    ttl_seconds: int = Field(default=3600, ge=60, le=604800)
    max_uses: int = Field(default=1, ge=1, le=128)


class FleetNodeJoinRequest(BaseModel):
    token: str = Field(min_length=20, max_length=256)
    name: str = Field(min_length=1, max_length=128)
    hostname: Optional[str] = Field(default=None, max_length=255)
    region: Optional[str] = Field(default=None, max_length=128)
    transport: str = Field(default="overlay", pattern="^(overlay|broker)$")
    wireguard_public_key: Optional[str] = Field(default=None, min_length=40, max_length=64)
    labels: dict[str, Any] = Field(default_factory=dict)
    capacity: dict[str, Any] = Field(default_factory=dict)
    build_fingerprint: Optional[str] = Field(default=None, max_length=256)


class FleetHeartbeatRequest(BaseModel):
    active_worker_count: int = Field(default=0, ge=0, le=128)
    capacity: dict[str, Any] = Field(default_factory=dict)
    build_fingerprint: Optional[str] = Field(default=None, max_length=256)
    active_worker_image_digest: Optional[str] = Field(default=None, max_length=512)
    agent_version: Optional[str] = Field(default=None, max_length=64)
    applied_state_version: int = Field(default=0, ge=0)
    last_error: Optional[str] = Field(default=None, max_length=2000)
    egress_ip: Optional[str] = Field(default=None, max_length=64)
    rollout_complete: bool = False


class FleetDesiredStateRequest(BaseModel):
    desired_worker_count: Optional[int] = Field(default=None, ge=0, le=128)
    drain: Optional[bool] = None
    worker_image_digest: Optional[str] = Field(default=None, max_length=512)

    @field_validator("worker_image_digest")
    @classmethod
    def _validate_worker_image_digest(cls, value):
        if value is None:
            return None
        candidate = value.strip()
        image_name, separator, digest = candidate.rpartition("@sha256:")
        if (
            not separator
            or not image_name
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest.lower())
        ):
            raise ValueError("worker_image_digest must be digest-pinned")
        return candidate


class FleetScaleRequest(BaseModel):
    desired_worker_count: int = Field(ge=0, le=16_384)


class BrokerLeaseRequest(BaseModel):
    worker_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    wait_seconds: int = Field(default=20, ge=0, le=30)
    private_input_public_key: Optional[str] = Field(
        default=None, min_length=44, max_length=44,
    )

    @field_validator("private_input_public_key")
    @classmethod
    def _validate_private_input_public_key(cls, value):
        if value is None:
            return None
        try:
            return validate_sealed_input_public_key(value)
        except SealedInputError as exc:
            raise ValueError(str(exc)) from exc


class BrokerLeaseHeartbeatRequest(BaseModel):
    lease_token: str = Field(min_length=32, max_length=256)
    progress: Optional[int] = Field(default=None, ge=0, le=100)
    phase: Optional[str] = Field(default=None, max_length=160)
    log_lines: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("log_lines")
    @classmethod
    def _bound_broker_log_lines(cls, value):
        return [str(line)[:2000] for line in value]


class BrokerResultRequest(BaseModel):
    lease_token: str = Field(min_length=32, max_length=256)
    result: dict[str, Any]


class BrokerActionAuthorityRequest(BaseModel):
    """Outer job authority plus one immutable action identity."""

    model_config = ConfigDict(extra="forbid")

    job_lease_token: str = Field(min_length=32, max_length=256)
    worker_id: str = Field(min_length=1, max_length=200)
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    action_id: str = Field(min_length=1, max_length=128)
    action_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class BrokerActionLeaseRequest(BrokerActionAuthorityRequest):
    action_lease: dict[str, Any]


class BrokerActionResultRequest(BrokerActionLeaseRequest):
    receipt: dict[str, Any]


class BrokerActionWorkManifestRequest(BrokerActionAuthorityRequest):
    manifest_ref: dict[str, Any]


class BrokerActionCancelStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_lease_token: str = Field(min_length=32, max_length=256)
    worker_id: str = Field(min_length=1, max_length=200)
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class BrokerScanContinuationRequest(BrokerActionCancelStatusRequest):
    allocation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


def _broker_action_work_manifest_references(
    action: Any,
) -> tuple[ScanWorkManifestReference, ...]:
    """Return only canonical manifest references frozen into action arguments."""
    return work_manifest_references_in(getattr(action, "capability_args", {}))


def _fleet_bootstrap_config() -> FleetBootstrapConfig:
    required = {
        "overlay_cidr": os.environ.get("FLEET_OVERLAY_CIDR", ""),
        "control_plane_overlay_url": os.environ.get("FLEET_CONTROL_PLANE_OVERLAY_URL", ""),
        "control_plane_wireguard_public_key": os.environ.get("FLEET_WIREGUARD_PUBLIC_KEY", ""),
        "control_plane_wireguard_endpoint": os.environ.get("FLEET_WIREGUARD_ENDPOINT", ""),
        "worker_image_digest": os.environ.get("FLEET_WORKER_IMAGE_DIGEST", ""),
    }
    missing = [key for key, value in required.items() if not value]
    if missing:
        raise FleetConfigurationError(f"fleet bootstrap is not configured ({', '.join(missing)})")
    return FleetBootstrapConfig(
        **required,
        desired_worker_count=_int_env("FLEET_DESIRED_WORKER_COUNT", 1),
    ).validated()


def _require_fleet_join_rate_limit(request: Request) -> None:
    try:
        configured_limit = int(os.environ.get("FLEET_JOIN_RATE_LIMIT_PER_MINUTE", "30"))
    except (TypeError, ValueError):
        configured_limit = 30
    limit = max(1, min(configured_limit, 1000))
    peer = str(getattr(getattr(request, "client", None), "host", None) or "unknown")
    if _trusted_fleet_gateway_request(request):
        # A reverse proxy appends its direct client to X-Forwarded-For. Earlier
        # entries may be supplied by the caller, so the left-most value is not
        # an authentication or rate-limit identity. Managed Caddy also replaces
        # the header with {remote_host}; the right-most parse is defense in depth
        # for existing/custom trusted gateways that still append it.
        forwarded = request.headers.get("x-forwarded-for", "").rsplit(",", 1)[-1].strip()
        try:
            peer = str(ipaddress.ip_address(forwarded))
        except ValueError:
            # Invalid forwarding metadata collapses to the trusted gateway's
            # socket peer rather than creating attacker-selected buckets.
            pass
    identity = hashlib.sha256(peer.encode("utf-8", "replace")).hexdigest()[:24]
    window = int(time.time()) // 60
    key = f"shakerscan:fleet:join-rate:{window}:{identity}"
    try:
        count = int(get_redis().eval(_FLEET_JOIN_RATE_LIMIT_LUA, 1, key, 120))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="fleet enrollment rate limiter is unavailable") from exc
    if count > limit:
        raise HTTPException(
            status_code=429,
            detail="too many fleet enrollment attempts; retry after the current rate-limit window",
            headers={"Retry-After": "60"},
        )


def _require_fleet_https(request: Request) -> None:
    if not _fleet_request_is_https(request):
        raise HTTPException(status_code=400, detail="fleet enrollment and node secrets require HTTPS")


def _fleet_connection_bundle() -> dict[str, Any]:
    raw = ""
    bundle_path = os.environ.get("FLEET_CONNECTION_BUNDLE_PATH", "").strip()
    if bundle_path:
        path = Path(bundle_path)
        try:
            if not path.is_file() or path.stat().st_mode & 0o077:
                raise FleetConfigurationError("fleet connection bundle file must be owner-only (0600)")
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise FleetConfigurationError("FLEET_CONNECTION_BUNDLE_PATH cannot be read") from exc
        if len(raw.encode("utf-8")) > 256 * 1024:
            raise FleetConfigurationError("fleet connection bundle is too large")
    if not raw:
        raw = os.environ.get("FLEET_CONNECTION_BUNDLE_JSON", "")
    if not raw:
        raise FleetConfigurationError("fleet connection bundle is not configured")
    try:
        bundle = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FleetConfigurationError("fleet connection bundle must be valid JSON") from exc
    if not isinstance(bundle, dict):
        raise FleetConfigurationError("fleet connection bundle must be a JSON object")
    for key in ("redis_url", "database_url"):
        if not isinstance(bundle.get(key), str) or not bundle[key].strip():
            raise FleetConfigurationError(f"connection bundle requires {key}")
    return bundle


def _fleet_ca_certificate_pem() -> str:
    path = Path(os.environ.get("FLEET_CA_CERT_PATH", "/run/shakerscan-fleet/control/ca.crt"))
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FleetConfigurationError("fleet CA certificate is not configured") from exc
    if len(content.encode("utf-8")) > 64 * 1024:
        raise FleetConfigurationError("fleet CA certificate is too large")
    if "-----BEGIN CERTIFICATE-----" not in content or "-----END CERTIFICATE-----" not in content:
        raise FleetConfigurationError("fleet CA certificate is invalid")
    return content.strip() + "\n"


def _fleet_acceptance_lease_probe() -> dict[str, Any]:
    """Exercise an isolated Stream lease loss/reclaim/ack sequence server-side."""
    redis_client = get_redis()
    queue = f"fleet_acceptance:{uuid.uuid4().hex}"
    try:
        message_id = enqueue_job(
            redis_client,
            queue,
            {"kind": "fleet_acceptance", "nonce": uuid.uuid4().hex},
        )
        first = lease_job(
            redis_client,
            [queue],
            consumer_name="acceptance-dead-consumer",
            block_ms=10,
            visibility_timeout_ms=50,
        )
        if not first or first.message_id != message_id:
            raise RuntimeError("lease probe could not acquire its first delivery")
        time.sleep(0.08)
        reclaimed = lease_job(
            redis_client,
            [queue],
            consumer_name="acceptance-recovery-consumer",
            block_ms=10,
            visibility_timeout_ms=50,
        )
        if not reclaimed or reclaimed.message_id != message_id or not reclaimed.reclaimed:
            raise RuntimeError("lease probe did not reclaim the abandoned delivery")
        return {
            "reclaimed": True,
            "delivery_attempts": reclaimed.delivery_attempts,
            "heartbeat_ok": heartbeat_lease(redis_client, reclaimed, "acceptance-recovery-consumer"),
            "first_ack": acknowledge_lease(redis_client, reclaimed),
            "duplicate_ack": acknowledge_lease(redis_client, reclaimed),
        }
    finally:
        try:
            redis_client.delete(queue, stream_key(queue))
        except Exception:
            pass


def _broker_node_labels(node: dict[str, Any]) -> dict[str, Any]:
    labels = node.get("labels") or {}
    if isinstance(labels, str):
        try:
            labels = json.loads(labels)
        except json.JSONDecodeError:
            labels = {}
    labels = dict(labels) if isinstance(labels, dict) else {}
    # Broker workers do not subscribe to Redis routes themselves; the control
    # plane leases on their behalf. Give that broker-side matcher the same
    # canonical identity/capability labels used by overlay workers and
    # placement admission, including the node UUID selected by the user.
    labels["node_id"] = str(node.get("id") or "").strip().lower()
    labels["node_scope"] = "remote"
    if node.get("region"):
        labels["region"] = str(node.get("region"))
    if "tools" not in labels and "capabilities" not in labels:
        labels["tools"] = sorted(DEFAULT_WORKER_TOOL_COMMANDS)
    if "budget_profiles" not in labels:
        labels["budget_profiles"] = sorted(SCAN_BUDGET_PROFILES)
    return labels


def _broker_target_key(value: Any) -> str:
    raw = str(value or "").strip()
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return raw
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return raw
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        return raw
    host = hostname.lower().rstrip(".")
    host_authority = f"[{host}]" if ":" in host else host
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    authority = host_authority if port in {None, default_port} else f"{host_authority}:{port}"
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), authority, parsed.path or "/", parsed.query, "")
    )


def _broker_target_authority(value: Any, *, default_scheme: str = "https") -> tuple[str, int] | None:
    raw = str(value or "").strip()
    parsed = urllib.parse.urlsplit(raw if "://" in raw else f"{default_scheme}://{raw}")
    try:
        host = str(parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError:
        return None
    return (host, int(port)) if host else None


async def _materialize_control_plane_scan_job_v2(
    queue_payload: Mapping[str, Any],
    *,
    revalidate_dns: bool = True,
) -> dict[str, Any]:
    """Project a canonical Redis job for a trusted DB-less broker worker."""
    try:
        scan_id = uuid.UUID(str(queue_payload.get("scan_id") or ""))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="scan-job/v2 has an invalid Scan id") from exc
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT target_id, target_url, job_id, options, scan_generation,
                   policy_json, budget_json, scan_job_payload, scan_job_digest,
                   parent_scan_id, scan_role, shard_index, shard_count
            FROM scans
            WHERE id=$1
            """,
            scan_id,
        )
    if not row:
        raise HTTPException(status_code=409, detail="scan-job/v2 has no durable Scan row")
    try:
        addresses = (
            await _resolve_runtime_target_addresses(
                str(row["target_url"] or ""), subject="broker Scan target",
            )
            if revalidate_dns
            else list(CanonicalScanJob.from_queue_payload(queue_payload).target.allowed_addresses)
        )
        return materialize_canonical_scan_job(
            queue_payload, row, resolved_addresses=addresses,
        )
    except (CanonicalScanJobError, CanonicalScanJobMaterializationError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _broker_execution_projection(materialized: Mapping[str, Any]) -> dict[str, Any]:
    """Remove control-plane-only canonical transport metadata from a broker lease."""
    return {
        str(key): copy.deepcopy(value)
        for key, value in materialized.items()
        if not str(key).startswith("_canonical_")
        and key not in {"placement", "_base_queue_name"}
    }


async def _hydrate_broker_job_options(conn: Any, payload: dict[str, Any]) -> dict[str, Any]:
    """Resolve managed credential references for one authenticated job lease only."""
    options = dict(payload.get("options") or {})
    raw_refs = options.pop("managed_credential_profiles", None)
    if not isinstance(raw_refs, list) or not raw_refs:
        payload["options"] = options
        return payload
    scan_id = _uuid_or_400(str(payload.get("scan_id") or ""), "scan id")
    refs = [dict(item) for item in raw_refs if isinstance(item, dict)][:2]
    profile_ids: list[uuid.UUID] = []
    for ref in refs:
        try:
            profile_ids.append(uuid.UUID(str(ref.get("profile_id") or "")))
        except ValueError as exc:
            raise HTTPException(status_code=409, detail="invalid managed credential reference") from exc
    if len(profile_ids) != len(set(profile_ids)):
        raise HTTPException(status_code=409, detail="managed credential references must be distinct")
    rows = await conn.fetch(
        """
        SELECT cp.id, cp.auth_kind, cp.secret_value
        FROM scans s
        JOIN target_credential_profiles cp ON cp.target_id = s.target_id
        WHERE s.id = $1
          AND cp.id = ANY($2::uuid[])
          AND cp.is_active = true
          AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
        """,
        scan_id,
        profile_ids,
    )
    profiles = {str(row["id"]): row_to_dict(row) for row in rows}
    option_map = {
        "user1": {"authorization_header": "auth_header", "cookie": "auth_cookies"},
        "user2": {"authorization_header": "user2_header", "cookie": "user2_cookies"},
    }
    resolved: list[dict[str, str]] = []
    for ref in refs:
        state = str(ref.get("auth_state") or "")
        profile_id = str(ref.get("profile_id") or "")
        row = profiles.get(profile_id)
        auth_kind = str((row or {}).get("auth_kind") or "")
        option_key = option_map.get(state, {}).get(auth_kind)
        if row is None or not option_key or option_key != str(ref.get("option_key") or ""):
            raise HTTPException(status_code=409, detail=f"managed credential unavailable for {state or 'principal'}")
        secret = str(decrypt_secret(row.get("secret_value")) or "")
        if not secret or secret.startswith("enc:fernet:") or "\r" in secret or "\n" in secret:
            raise HTTPException(status_code=409, detail=f"managed credential cannot be decrypted for {state}")
        options.setdefault(option_key, secret)
        resolved.append({"auth_state": state, "profile_id": profile_id, "option_key": option_key})
    options["resolved_credential_profiles"] = resolved
    payload["options"] = options
    return payload


async def _build_broker_private_scan_payload(
    conn: Any,
    *,
    payload: dict[str, Any],
    plan: Any,
    lease_id: str,
    worker_id: str,
    expires_at: datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the encrypted-only worker patch and scrub its public job copy."""
    scan_id = str(payload.get("scan_id") or "")
    options = await _hydrate_broker_generic_scan_credentials(
        conn,
        options=dict(payload.get("options") or {}),
        scan_id=scan_id,
    )
    encrypted_state_key = options.get(SCAN_PRIVATE_STATE_KEY_OPTION)
    if encrypted_state_key:
        raw_state_key = decrypt_secret(encrypted_state_key)
        if not raw_state_key or raw_state_key == encrypted_state_key:
            raise HTTPException(
                status_code=409,
                detail="broker Scan private-state key could not be decrypted",
            )
        options[SCAN_PRIVATE_STATE_KEY_OPTION] = raw_state_key
    public_options, private_options = _split_broker_private_options(options)
    target = _broker_target_binding_from_options(public_options)
    replay_plans: dict[str, Any] = {}
    for action in plan.actions:
        if action.capability_name in {
            "collections.replay_safe", "collections.replay_authentication",
            "collections.replay_active",
        }:
            replay_plans[action.action_id] = await _broker_private_replay_plan(
                conn,
                action=action,
                options=public_options,
                target=target,
                scan_id=scan_id,
            )
    public_payload = copy.deepcopy(payload)
    public_payload["options"] = public_options
    private_payload = {
        "schema_version": BROKER_PRIVATE_SCAN_INPUT_SCHEMA,
        "lease_id": str(lease_id),
        "worker_id": str(worker_id),
        "plan_digest": plan.plan_digest,
        "target_binding_digest": plan.target_binding_digest,
        "expires_at": expires_at.isoformat(),
        "options": private_options,
        "replay_plans": replay_plans,
    }
    return public_payload, private_payload


async def _broker_reserve_request_budget(
    conn: Any,
    redis_client: Any,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    """Reserve the same root-domain request budget before remote execution."""
    options = dict(payload.get("options") or {})
    immutable_actions = bool(
        str(options.get("scan_action_plan_digest") or "").strip()
        or str(options.get("scan_execution_plan_digest") or "").strip()
    )
    mode = str(options.get("request_budget_mode") or "compatibility").strip().lower()
    if mode == "off":
        return {}
    mode = "enforce"
    options["request_budget_mode"] = mode
    custom_budget = options.get("custom_budget") if isinstance(options.get("custom_budget"), dict) else {}
    resolved = resolve_or_consume_budget(
        str(options.get("scan_type") or "standard"),
        options=options,
        budget_profile=options.get("budget_profile"),
        custom_budget=custom_budget,
    )
    requested = max(0, int(resolved.get("request_max") or 0))
    if requested <= 0:
        payload["options"] = options
        return {}
    try:
        scan_id = uuid.UUID(str(payload.get("scan_id") or ""))
    except ValueError:
        return None
    target = await conn.fetchrow(
        """
        SELECT t.root_domain, t.asm_config, s.parent_scan_id
        FROM scans s JOIN targets t ON t.id=s.target_id
        WHERE s.id=$1
        """,
        scan_id,
    )
    root_domain = str((target or {}).get("root_domain") or "").strip().lower()
    config = asm_inventory.merge_asm_config(parse_json_field((target or {}).get("asm_config")) or {})
    cap = int(config.get("max_requests_per_hour_per_domain") or 0)
    granted = requested
    reservation_request = requested
    pending_sibling_count = 1
    if root_domain and cap > 0:
        used = await asm_inventory.domain_tested_recently_count(conn, root_domain, hours=1)
        remaining = max(0, cap - int(used or 0))
        parent_scan_id = (target or {}).get("parent_scan_id")
        if parent_scan_id and not immutable_actions:
            # A parallel parent owns one logical per-domain allowance. Without
            # fair sharing, the first broker child can reserve the entire cap
            # and leave every sibling parked for the reservation TTL. Include
            # running siblings in the divisor: a child can transition to running
            # between this query and the Redis reservation, and COUNT=0 must not
            # silently become "give this child the full remaining cap".
            try:
                sibling_count_value = await conn.fetchval(
                    """
                    SELECT COUNT(*)
                    FROM scans
                    WHERE parent_scan_id=$1
                      AND status IN ('pending','queued','running')
                    """,
                    parent_scan_id,
                )
                if sibling_count_value is None:
                    return None
                pending_sibling_count = max(1, int(sibling_count_value))
            except Exception:
                return None
            reserved = asm_inventory.reserved_domain_rate_count(redis_client, root_domain)
            unreserved = max(0, remaining - reserved)
            if unreserved <= 0:
                return None
            fair_share = max(1, unreserved // pending_sibling_count)
            reservation_request = min(requested, fair_share)
        try:
            granted = asm_inventory.reserve_domain_rate(
                redis_client,
                root_domain,
                remaining,
                reservation_request,
                all_or_nothing=immutable_actions,
            )
        except Exception:
            return None
        if granted <= 0:
            return None
    adjusted_budget = dict(custom_budget)
    adjusted_budget["request_max"] = granted
    options["custom_budget"] = adjusted_budget
    options["request_budget_reserved"] = granted
    if root_domain:
        options["request_budget_domain"] = root_domain
    payload["options"] = options
    return {
        "requested": requested,
        "reservation_request": reservation_request,
        "granted": granted,
        "root_domain": root_domain,
        "pending_sibling_count": pending_sibling_count,
        "custom_budget": adjusted_budget,
        "request_budget_mode": mode,
    }


async def _mark_broker_budget_wait(conn: Any, payload: Mapping[str, Any]) -> None:
    """Expose a transient broker budget deferral without failing or bypassing it."""
    try:
        scan_id = uuid.UUID(str(payload.get("scan_id") or ""))
    except ValueError:
        return
    await conn.execute(
        """
        UPDATE scans
        SET current_phase='waiting_for_request_budget'
        WHERE id=$1 AND status IN ('pending','queued')
        """,
        scan_id,
    )


async def _broker_authenticated_node(
    node_id: str,
    request: Request,
    *,
    require_schedulable: bool = False,
) -> dict[str, Any]:
    _require_fleet_https(request)
    credential = _fleet_bearer_credential(request)
    try:
        async with _pool().acquire() as conn:
            async with conn.transaction():
                node = await _authenticate_fleet_node(conn, node_id=node_id, credential=credential)
    except FleetAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    labels = _broker_node_labels(node)
    if str(labels.get("transport") or "").strip().lower() != "broker":
        raise HTTPException(status_code=403, detail="node is not enrolled for HTTPS broker transport")
    if require_schedulable:
        stale_after = max(60, _int_env("FLEET_HEARTBEAT_TIMEOUT_SECONDS", HEARTBEAT_TIMEOUT_MINUTES * 60))
        public = _public_fleet_node(node, stale_after_seconds=stale_after)
        schedulable = _fleet_node_is_schedulable(public)
        if not schedulable:
            raise HTTPException(status_code=409, detail="node is not healthy and current for scheduling")
    return node


def _queue_lease_from_broker_row(row: Any) -> QueueLease:
    return QueueLease(
        queue_name=str(row["queue_name"]),
        payload="",
        stream_key=str(row["stream_key"]),
        message_id=str(row["message_id"]),
        delivery_attempts=int(row.get("delivery_attempts") or 1),
    )


def _broker_slot_id(stream_key: str, message_id: str) -> str:
    return f"broker:{hashlib.sha256(f'{stream_key}:{message_id}'.encode()).hexdigest()[:32]}"


async def _broker_active_scan_cap() -> int:
    stale_after = max(60, _int_env("FLEET_HEARTBEAT_TIMEOUT_SECONDS", HEARTBEAT_TIMEOUT_MINUTES * 60))
    async with _pool().acquire() as conn:
        rows = await conn.fetch("SELECT * FROM nodes WHERE status <> 'disabled' ORDER BY created_at ASC")
    nodes = [_public_fleet_node(row, stale_after_seconds=stale_after) for row in rows]
    return _compute_broker_active_scan_cap(
        nodes,
        override=os.environ.get("SHAKERSCAN_BROKER_MAX_ACTIVE_SCANS"),
    )


def _broker_action_plan_requires_local_private_inputs(plan: Any) -> bool:
    """Keep worker-private inputs local until their sealed exchange is available."""
    return any(
        str(getattr(action, "capability_name", ""))
        in _BROKER_PRIVATE_INPUT_CAPABILITIES
        for action in tuple(getattr(plan, "actions", ()) or ())
    )


def _broker_job_has_private_inputs(payload: Mapping[str, Any]) -> bool:
    options = payload.get("options")
    if not isinstance(options, Mapping):
        return False
    if any(
        options.get(key) not in (None, "", [], {})
        for key in _BROKER_PRIVATE_OPTION_KEYS
    ):
        return True
    if options.get("managed_credential_profiles") not in (None, "", [], {}):
        return True
    if options.get("credential_profile_refs") not in (None, "", [], {}):
        return True
    return any(
        isinstance(item, Mapping)
        and str(item.get("replay_policy") or "").strip().lower()
        in EXECUTABLE_REPLAY_POLICIES
        for item in options.get("request_collections") or ()
    )


def _broker_take_or_refresh_slot(redis_client: Any, slot_id: str, *, cap: int | None = None) -> bool:
    try:
        if cap is None:
            try:
                cap = max(1, int(os.environ.get("SHAKERSCAN_BROKER_MAX_ACTIVE_SCANS") or 1))
            except (TypeError, ValueError):
                cap = 1
        return bool(redis_client.eval(
            _BROKER_SLOT_LUA,
            1,
            BROKER_ACTIVE_SLOTS_KEY,
            time.time(),
            BROKER_LEASE_SECONDS,
            cap,
            slot_id,
        ))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="fleet admission control is unavailable") from exc


def _broker_release_slot(redis_client: Any, slot_id: str) -> None:
    try:
        redis_client.zrem(BROKER_ACTIVE_SLOTS_KEY, slot_id)
    except Exception:
        pass


async def _fail_broker_scan_and_reconcile_parent(
    conn: Any,
    *,
    scan_id: uuid.UUID,
    phase: str,
    message: str,
    redis_client: Any,
) -> None:
    failed_row = await conn.fetchrow(
        """
        UPDATE scans
        SET status='failed', progress=100, current_phase=$2,
            error_message=$3, completed_at=NOW()
        WHERE id=$1 AND status NOT IN ('completed','failed','cancelled')
        RETURNING parent_scan_id
        """,
        scan_id,
        phase,
        message[:500],
    )
    parent_id = failed_row.get("parent_scan_id") if failed_row else None
    if parent_id:
        await parallel_scan.reconcile_parallel_parent(
            conn, str(parent_id), redis_client, QUEUE_NAME
        )


async def _broker_lease_row(
    conn: Any,
    *,
    node_id: str,
    lease_id: str,
    lease_token: str,
    for_update: bool = False,
) -> Any:
    suffix = " FOR UPDATE" if for_update else ""
    try:
        row = await conn.fetchrow(
            """
            SELECT * FROM broker_job_leases
            WHERE id=$1 AND node_id=$2 AND lease_token_hash=$3
            """ + suffix,
            uuid.UUID(lease_id),
            uuid.UUID(node_id),
            _hash_fleet_secret(lease_token, "broker-job-lease"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="broker lease not found") from exc
    if not row:
        raise HTTPException(status_code=404, detail="broker lease not found")
    return row


async def _broker_action_context(
    conn: Any,
    *,
    node_id: str,
    lease_id: str,
    job_lease_token: str,
    worker_id: str,
    plan_digest: str,
    action_id: str | None = None,
    action_digest: str | None = None,
) -> tuple[Any, Any, Any, Any | None, Any]:
    """Bind one broker action call to its live outer job and persisted plan."""
    row = await _broker_lease_row(
        conn,
        node_id=node_id,
        lease_id=lease_id,
        lease_token=job_lease_token,
    )
    if str(row.get("status") or "") != "leased":
        raise HTTPException(status_code=409, detail=f"broker lease is {row['status']}")
    if row.get("lease_expires_at") is None or row["lease_expires_at"] <= utc_now():
        raise HTTPException(status_code=410, detail="broker job lease expired")
    expected_worker = f"broker:{str(row.get('worker_id') or '')}"
    if worker_id != expected_worker:
        raise HTTPException(status_code=409, detail="broker action worker differs from job lease")
    if not row.get("scan_id"):
        raise HTTPException(status_code=409, detail="broker job has no Scan owner")
    action_store = PostgresScanActionStore()
    try:
        plan = await action_store.load_plan(conn, scan_id=str(row["scan_id"]))
    except Exception as exc:
        raise HTTPException(
            status_code=409, detail="broker Scan action plan is unavailable",
        ) from exc
    if plan is None or str(plan.plan_digest) != str(plan_digest):
        raise HTTPException(status_code=409, detail="broker Scan action plan changed")
    scan_row = await conn.fetchrow(
        "SELECT status, target_id, scan_job_payload FROM scans WHERE id=$1",
        row["scan_id"],
    )
    if not scan_row:
        raise HTTPException(status_code=409, detail="broker Scan owner disappeared")
    raw_job = parse_json_field(scan_row.get("scan_job_payload")) or {}
    try:
        canonical_job = CanonicalScanJob.from_payload(raw_job)
    except CanonicalScanJobError as exc:
        raise HTTPException(
            status_code=409, detail="broker Scan job authority is invalid",
        ) from exc
    if (
        canonical_job.scan_id != plan.scan_id
        or canonical_job.execution_plan.digest != plan.execution_plan_digest
        or canonical_job.target.digest != plan.target_binding_digest
    ):
        raise HTTPException(
            status_code=409, detail="broker Scan job and action plan differ",
        )
    action = None
    if action_id is not None:
        action = next(
            (item for item in plan.actions if item.action_id == action_id), None,
        )
        if action is None or action.action_digest != str(action_digest or ""):
            raise HTTPException(status_code=409, detail="broker action authority changed")
        if "broker" not in tuple(action.placement.get("eligible_backends") or ()):
            raise HTTPException(status_code=409, detail="broker action placement is unavailable")
    backend = PostgresScanExecutionBackend(
        pool=_pool(),
        plan=plan,
        worker_id=worker_id,
        backend_name="broker",
        lease_seconds=min(BROKER_LEASE_SECONDS, 3600),
        aggregate_owner_id=(
            canonical_job.shard.parent_scan_id
            if canonical_job.shard is not None else None
        ),
    )
    return row, plan, canonical_job, action, backend


async def _revalidate_broker_action_authority(
    conn: Any,
    *,
    action: Any,
    canonical_job: Any,
) -> None:
    target_active = await conn.fetchval(
        "SELECT is_active FROM targets WHERE id=$1",
        uuid.UUID(str(canonical_job.target.target_id)),
    )
    if target_active is not True:
        raise HTTPException(status_code=409, detail="broker Scan target is inactive")
    policy = canonical_job.execution_plan.policy
    decision = await revalidate_scan_action_authority(
        conn,
        action=action,
        target_binding=canonical_job.target,
        scope_receipt_id=(
            canonical_job.target.scope_receipt_id or policy.scope_receipt_id
        ),
        approval_receipt_id=policy.approval_receipt_id,
    )
    if decision is not ActionAuthorityDecision.ALLOWED:
        raise HTTPException(
            status_code=409,
            detail=f"broker action authorization rejected: {decision.value}",
        )


async def _materialize_broker_scan_continuation(
    conn: Any,
    *,
    parent_plan: ScanActionPlan,
    canonical_job: CanonicalScanJob,
    options: Mapping[str, Any],
    allocation: ScanContinuationAllocation,
    worker_id: str,
) -> tuple[ScanActionPlan, ScanPlanRevision, dict[str, Any]]:
    """Compile the broker continuation only from control-plane receipts."""
    backend = PostgresScanExecutionBackend(
        pool=_pool(),
        plan=parent_plan,
        worker_id=worker_id,
        backend_name="broker",
        lease_seconds=min(BROKER_LEASE_SECONDS, 3600),
        aggregate_owner_id=(
            canonical_job.shard.parent_scan_id
            if canonical_job.shard is not None else None
        ),
    )
    results = {}
    observations = {}
    for action in parent_plan.actions:
        result = await backend.load_result_with_connection(conn, action.action_id)
        if result is None:
            raise HTTPException(
                status_code=409,
                detail="broker continuation requires every discovery action receipt",
            )
        results[action.action_id] = result
        if result.observation_manifest_ref is None:
            observations[action.action_id] = ()
            continue
        rows = await PostgresObservationManifestStore().load(
            conn,
            reference=result.observation_manifest_ref,
            scan_id=parent_plan.scan_id,
            action_id=action.action_id,
        )
        if rows is None:
            raise HTTPException(
                status_code=409,
                detail="broker continuation observation manifest is unavailable",
            )
        observations[action.action_id] = rows

    request_manifests: list[ScanWorkManifest] = []
    raw_request_refs = options.get("request_manifest_refs")
    if isinstance(raw_request_refs, Mapping):
        for raw in raw_request_refs.values():
            if not isinstance(raw, Mapping):
                continue
            try:
                reference = ScanWorkManifestReference.from_dict(raw)
            except (ScanWorkManifestError, TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=409,
                    detail="broker continuation request manifest is invalid",
                ) from exc
            if reference.kind.value != "request":
                raise HTTPException(
                    status_code=409,
                    detail="broker continuation request manifest kind is invalid",
                )
            try:
                manifest = await PostgresScanManifestStore().load(
                    conn,
                    manifest_id=reference.manifest_id,
                    scan_id=parent_plan.scan_id,
                    expected_kind=reference.kind,
                    expected_digest=reference.manifest_digest,
                    expected_target_binding_digest=parent_plan.target_binding_digest,
                )
            except ScanManifestStoreError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            if manifest is None or manifest.reference() != reference:
                raise HTTPException(
                    status_code=409,
                    detail="broker continuation request manifest is unavailable",
                )
            request_manifests.append(manifest)

    try:
        endpoints, candidates = build_discovery_continuation_manifests(
            allocation=allocation,
            target_url=str(options.get("_continuation_target_url") or "")
            or canonical_job.target.allowed_origins[0],
            target=canonical_job.target,
            options=options,
            action_results=results,
            observations=observations,
            request_manifests=tuple(request_manifests),
        )
        request_candidates = (
            build_request_candidate_manifest(
                tuple(request_manifests),
                source_action_ids=tuple(dict.fromkeys(
                    action_id
                    for manifest in request_manifests
                    for action_id in manifest.source_action_ids
                )),
                maximum=max(
                    1,
                    min(2_000, allocation.budget_ceiling.get(
                        "state_changing_requests", 0,
                    )),
                ),
            )
            if request_manifests else None
        )
        credential_refs = [
            dict(item)
            for item in options.get("credential_profile_refs") or ()
            if isinstance(item, Mapping)
        ]
        collection_refs = [
            dict(item)
            for item in options.get("request_collections") or ()
            if isinstance(item, Mapping)
        ]
        # Derived from the compiler's own rule: only an interactive credential
        # gets an inputs.auth_* action, so allocating one per credential named
        # actions that were never created and the plan was rejected outright.
        zero_cost_existing_inputs = {
            action_id: {}
            for action_id in interactive_auth_input_action_ids(credential_refs)
        }
        zero_cost_existing_inputs.update({
            f"inputs.collection_{index:02d}": {}
            for index, _item in enumerate(collection_refs)
        })
        continuation_raw = ScanActionPlanCompiler().compile(
            scan_id=parent_plan.scan_id,
            execution_plan=canonical_job.execution_plan,
            target_binding=canonical_job.target,
            credential_profile_refs=credential_profile_action_refs(
                credential_refs
            ),
            request_collection_refs=request_collection_action_refs(
                collection_refs
            ),
            request_manifest_refs=(
                {
                    str(key): dict(value)
                    for key, value in raw_request_refs.items()
                    if isinstance(value, Mapping)
                }
                if isinstance(raw_request_refs, Mapping) else None
            ),
            endpoint_manifest_ref=endpoints.reference().canonical_dict(),
            candidate_manifest_ref=candidates.reference().canonical_dict(),
            request_candidate_manifest_ref=(
                request_candidates.reference().canonical_dict()
                if request_candidates is not None and request_candidates.entries
                else None
            ),
            template_manifest_ref=(
                dict(options["template_manifest_ref"])
                if isinstance(options.get("template_manifest_ref"), Mapping)
                else None
            ),
            action_scope="endpoint",
            action_budgets=zero_cost_existing_inputs,
        )
        continuation_plan = allocate_scan_action_plan(
            continuation_raw,
            # Admit against what the settled root actions actually left, not the
            # worst-case residual frozen at submission (see reconciled_continuation_ceiling).
            ContinuationBudgetCeiling(
                reconciled_continuation_ceiling(allocation, results),
            ),
        ).plan
        amended = merge_scan_action_continuation(
            parent_plan=parent_plan,
            continuation_plan=continuation_plan,
            allocation=allocation,
            parent_results=results,
        )
        revision = amended_scan_plan_revision(
            parent_plan=parent_plan,
            continuation_plan=continuation_plan,
            amended_plan=amended,
            allocation=allocation,
            discovery_results=results,
            work_manifest_references=unique_work_manifest_reference_dicts(
                action.capability_args for action in continuation_plan.actions
            ),
        )
    except (
        ScanActionPlanError,
        ScanBudgetAllocationError,
        ScanContinuationError,
        ScanWorkManifestError,
    ) as exc:
        record_operational_event(get_redis(), "continuation_rejected")
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    manifest_store = PostgresScanManifestStore()
    await manifest_store.persist(conn, manifest=endpoints)
    await manifest_store.persist(conn, manifest=candidates)
    if request_candidates is not None:
        await manifest_store.persist(conn, manifest=request_candidates)
    await PostgresScanActionStore().amend_plan(
        conn,
        parent_plan=parent_plan,
        amended_plan=amended,
        allocation=allocation,
        revision=revision,
    )
    continuation_options = {
        "endpoint_manifest_id": str(endpoints.manifest_id),
        "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
        "candidate_manifest_ref": candidates.reference().canonical_dict(),
        "request_candidate_manifest_ref": (
            request_candidates.reference().canonical_dict()
            if request_candidates is not None and request_candidates.entries
            else None
        ),
        "scan_continuation_plan_digest": amended.plan_digest,
        "scan_plan_revision": revision.canonical_dict(),
    }
    await conn.execute(
        """
        UPDATE scans SET options=options || $2::jsonb
        WHERE id=$1 AND status NOT IN ('cancelled','cancelling')
        """,
        uuid.UUID(parent_plan.scan_id),
        json.dumps(continuation_options),
    )
    record_operational_event(get_redis(), "continuation_compiled")
    return amended, revision, continuation_options


def _broker_submitted_action_lease(
    raw: Mapping[str, Any],
    *,
    plan: Any,
    action: Any,
    worker_id: str,
) -> ActionLease:
    try:
        lease = ActionLease.from_remote_payload(raw)
    except ScanExecutionBackendError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if (
        lease.scan_id != plan.scan_id
        or lease.plan_digest != plan.plan_digest
        or lease.execution_plan_digest != plan.execution_plan_digest
        or lease.target_binding_digest != plan.target_binding_digest
        or lease.action.action_digest != action.action_digest
        or lease.action.action_id != action.action_id
        or lease.backend != "broker"
        or lease.worker_id != worker_id
    ):
        raise HTTPException(status_code=409, detail="submitted broker action lease changed")
    return lease


def _control_plane_broker_ingest_payload(job_payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a broker result job that is intentionally local to the control plane.

    The original execution placement selects the remote scanner. Result ingestion
    is a separate trusted control-plane operation; carrying that placement into
    the ingest queue creates a route no local worker can satisfy.
    """
    ingest_payload = copy.deepcopy(dict(job_payload))
    ingest_payload.pop("placement", None)
    # Preserve trusted-ingest routing across every worker-side requeue path.
    # Falling back to scan_jobs would make a remote broker execute the shard a
    # second time instead of ingesting its already-produced result.
    ingest_payload["_base_queue_name"] = BROKER_INGEST_QUEUE_NAME
    options = ingest_payload.get("options")
    if isinstance(options, dict):
        options.pop("placement", None)
    return ingest_payload
SCAN_BUDGET_PROFILES = {"fast", "balanced", "thorough"}


BROKER_LEASE_SECONDS = max(60, int(os.environ.get("SHAKERSCAN_BROKER_LEASE_SECONDS", "300")))


BROKER_ACTIVE_SLOTS_KEY = "shakerscan:broker:active_scan_slots"


_BROKER_SLOT_LUA = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, tonumber(ARGV[1]))
if redis.call('ZSCORE', KEYS[1], ARGV[4]) then
  redis.call('ZADD', KEYS[1], tonumber(ARGV[1]) + tonumber(ARGV[2]), ARGV[4])
  return 1
end
if redis.call('ZCARD', KEYS[1]) < tonumber(ARGV[3]) then
  redis.call('ZADD', KEYS[1], tonumber(ARGV[1]) + tonumber(ARGV[2]), ARGV[4])
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]) + 600)
  return 1
end
return 0
"""


def _fleet_request_is_https(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    if _trusted_fleet_gateway_request(request):
        forwarded_proto = (
            request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
        )
        if forwarded_proto == "https":
            return True
    allow_lab_http = os.environ.get("FLEET_ALLOW_INSECURE_ENROLLMENT", "").strip().lower() in {
        "1", "true", "yes", "on",
    }
    peer = getattr(getattr(request, "client", None), "host", None)
    try:
        peer_is_loopback = bool(peer) and ipaddress.ip_address(peer).is_loopback
    except ValueError:
        peer_is_loopback = False
    configured_bind = os.environ.get("SHAKERSCAN_BIND_HOST", "").strip()
    if configured_bind:
        try:
            local_transport = ipaddress.ip_address(configured_bind).is_loopback
        except ValueError:
            local_transport = False
    else:
        local_transport = peer_is_loopback
    return allow_lab_http and local_transport


def _trusted_fleet_gateway_request(request: Request) -> bool:
    configured = os.environ.get("FLEET_GATEWAY_PROXY_SECRET", "").strip()
    presented = request.headers.get("x-shakerscan-gateway-secret", "").strip()
    return bool(
        configured
        and presented
        and secrets.compare_digest(configured.encode("utf-8"), presented.encode("utf-8"))
    )


_FLEET_JOIN_RATE_LIMIT_LUA = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""


_BROKER_PRIVATE_OPTION_KEYS = frozenset({
    *SCAN_AUTHENTICATION_KEYS,
    "authentication",
    "ai_api_key",
    SCAN_PRIVATE_STATE_KEY_OPTION,
})


def _broker_target_binding_from_options(options: Mapping[str, Any]) -> TargetBinding:
    raw = options.get("_canonical_target_binding")
    if not isinstance(raw, Mapping):
        raise HTTPException(
            status_code=409,
            detail="broker private inputs have no canonical target binding",
        )
    try:
        return TargetBinding(
            target_id=str(raw.get("target_id") or ""),
            target_kind=str(raw.get("target_kind") or ""),
            canonical_host=raw.get("canonical_host"),
            allowed_origins=tuple(raw.get("allowed_origins") or ()),
            allowed_addresses=tuple(raw.get("allowed_addresses") or ()),
            allowed_root_domains=tuple(raw.get("allowed_root_domains") or ()),
            environment=str(raw.get("environment") or "unknown"),
            scope_receipt_id=str(raw.get("scope_receipt_id") or "") or None,
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=409,
            detail="broker private input target binding is invalid",
        ) from exc


async def _hydrate_broker_generic_scan_credentials(
    conn: Any,
    *,
    options: Mapping[str, Any],
    scan_id: str,
) -> dict[str, Any]:
    """Resolve generic credential references only inside the lease transaction."""
    hydrated = dict(options)
    raw_refs = hydrated.get("credential_profile_refs")
    if not isinstance(raw_refs, list) or not raw_refs:
        return hydrated
    if (
        hydrated.get("managed_credential_profiles") not in (None, "", [], {})
        or hydrated.get("authentication") not in (None, "", [], {})
        or any(
            hydrated.get(key) not in (None, "", [], {})
            for key in SCAN_AUTHENTICATION_KEYS
        )
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "generic Scan credential references cannot be combined with "
                "another authentication path"
            ),
        )
    refs = [dict(item) for item in raw_refs if isinstance(item, Mapping)]
    if len(refs) != len(raw_refs) or not 1 <= len(refs) <= 2:
        raise HTTPException(
            status_code=409, detail="broker Scan credential references are invalid",
        )
    profile_ids = [str(item.get("profile_id") or "") for item in refs]
    lanes = [str(item.get("scan_lane") or "") for item in refs]
    try:
        uuid.UUID(str(scan_id))
        for profile_id in profile_ids:
            uuid.UUID(profile_id)
    except (TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=409,
            detail="broker Scan credential reference UUID is invalid",
        ) from exc
    if (
        len(profile_ids) != len(set(profile_ids))
        or len(lanes) != len(set(lanes))
        or any(lane not in {"primary", "secondary"} for lane in lanes)
    ):
        raise HTTPException(
            status_code=409,
            detail="broker Scan credential references are ambiguous",
        )
    target = _broker_target_binding_from_options(hydrated)
    target_kind = str(hydrated.get("credential_target_kind") or "").lower()
    action_name = str(hydrated.get("credential_action_name") or "").strip()
    if target_kind != target.target_kind or target_kind not in {"web", "api"} or not action_name:
        raise HTTPException(
            status_code=409,
            detail="broker Scan credential authority is incomplete",
        )
    try:
        authority = await validate_worker_credential_authority(
            conn,
            owner_kind="scan",
            owner_id=str(scan_id),
            target=target,
            approval_receipt_id=hydrated.get("approval_receipt_id"),
            scope_receipt_id=hydrated.get("scope_receipt_id"),
            action_name=action_name,
        )
        resolver = WorkerCredentialResolver()
        resolved_refs: list[dict[str, Any]] = []
        for ref in refs:
            expected_version = int(ref.get("profile_version") or 0)
            if expected_version < 1:
                raise ScanCredentialError(
                    "generic Scan credential profile version is invalid"
                )
            expected_allowed = tuple(
                str(item) for item in ref.get("allowed_capabilities") or ()
                if str(item)
            )
            resolution_capability = str(
                ref.get("credential_resolution_capability")
                or scan_credential_resolution_capability(
                    expected_allowed, auth_kind=str(ref.get("auth_kind") or ""),
                )
                or ""
            )
            if not resolution_capability:
                raise ScanCredentialError(
                    "generic Scan credential has no semantic execution authority"
                )
            async with resolver.resolve(
                conn,
                profile_id=ref["profile_id"],
                target=target,
                capability=resolution_capability,
                authority=authority,
            ) as resolved:
                profile = resolved.profile
                if (
                    profile.current_version != expected_version
                    or profile.auth_kind != str(ref.get("auth_kind") or "")
                    or profile.principal_slot
                    != str(ref.get("principal_slot") or "")
                    or profile.target_kind != target_kind
                    or tuple(profile.allowed_capabilities) != expected_allowed
                ):
                    raise ScanCredentialError(
                        "generic Scan credential changed after admission"
                    )
                hydrated = bind_resolved_scan_credential(
                    hydrated,
                    resolved,
                    scan_lane=str(ref["scan_lane"]),
                )
                resolved_refs.append({
                    **resolved.receipt_metadata(),
                    "scan_lane": str(ref["scan_lane"]),
                    "allowed_capabilities": list(expected_allowed),
                    "credential_resolution_capability": resolution_capability,
                })
        hydrated["resolved_credential_profiles"] = resolved_refs
        return hydrated
    except (
        CredentialResolutionError, ScanCredentialError, ValueError, TypeError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _split_broker_private_options(
    options: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return secret-free public options plus the minimal encrypted patch."""
    public = copy.deepcopy(dict(options))
    private: dict[str, Any] = {}
    for key in _BROKER_PRIVATE_OPTION_KEYS:
        if key in public and public[key] not in (None, "", [], {}):
            private[key] = public.pop(key)
        else:
            public.pop(key, None)
    resolved = public.pop("resolved_credential_profiles", None)
    if resolved not in (None, "", [], {}):
        private["resolved_credential_profiles"] = resolved
    return public, private


async def _broker_private_replay_plan(
    conn: Any,
    *,
    action: Any,
    options: Mapping[str, Any],
    target: TargetBinding,
    scan_id: str,
) -> dict[str, Any]:
    """Materialize one exact replay plan and prove it against public authority."""
    bound_ref = action.capability_args.get("request_collection_ref")
    raw_manifest_ref = action.capability_args.get("request_manifest_ref")
    if not isinstance(bound_ref, Mapping) or not isinstance(
        raw_manifest_ref, Mapping,
    ):
        raise HTTPException(
            status_code=409,
            detail="broker collection action has incomplete immutable input authority",
        )
    matches = [
        dict(item)
        for item in options.get("request_collections") or ()
        if isinstance(item, Mapping)
        and str(item.get("selection_id") or "")
        == str(bound_ref.get("selection_id") or "")
        and str(item.get("selection_digest") or "").lower()
        == str(bound_ref.get("selection_digest") or "").lower()
    ]
    if len(matches) != 1:
        raise HTTPException(
            status_code=409,
            detail="broker collection selection changed after action admission",
        )
    ref = matches[0]
    replay_policy = str(ref.get("replay_policy") or "").strip().lower()
    capability_name = (
        "collections.replay_active"
        if replay_policy == "confirmed_active"
        else "collections.replay_authentication"
        if replay_policy == "safe_authentication"
        else "collections.replay_safe"
    )
    if capability_name != action.capability_name:
        raise HTTPException(
            status_code=409,
            detail="broker collection replay policy differs from action authority",
        )
    try:
        collection_id = uuid.UUID(str(ref.get("collection_id") or ""))
        binding_id = uuid.UUID(str(ref.get("binding_id") or ""))
        selection_id = uuid.UUID(str(ref.get("selection_id") or ""))
        target_id = uuid.UUID(target.target_id)
        manifest_ref = ScanWorkManifestReference.from_dict(raw_manifest_ref)
    except (TypeError, ValueError, AttributeError, ScanWorkManifestError) as exc:
        raise HTTPException(
            status_code=409,
            detail="broker collection immutable references are invalid",
        ) from exc
    try:
        manifest = await PostgresScanManifestStore().load(
            conn,
            manifest_id=manifest_ref.manifest_id,
            scan_id=scan_id,
            expected_kind=manifest_ref.kind,
            expected_digest=manifest_ref.manifest_digest,
            expected_target_binding_digest=target.digest,
        )
    except ScanManifestStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if (
        manifest is None
        or manifest.reference() != manifest_ref
        or manifest_ref.kind.value != "request"
        or action.action_id not in manifest.source_action_ids
    ):
        raise HTTPException(
            status_code=409,
            detail="broker exact request manifest is unavailable",
        )
    row = await conn.fetchrow(
        """SELECT c.encrypted_payload, c.payload_sha256,
                  b.allowed_origins, b.environment_id,
                  e.encrypted_payload AS encrypted_environment,
                  e.payload_sha256 AS environment_sha256,
                  s.replay_policy, s.selector_json, s.selection_digest
           FROM request_collections c
           JOIN request_collection_bindings b
             ON b.id=$2 AND b.collection_id=c.id AND b.is_active=true
           JOIN request_collection_selections s
             ON s.id=$3 AND s.collection_id=c.id
            AND s.binding_id=b.id AND s.revoked_at IS NULL
           LEFT JOIN request_collection_environments e
             ON e.id=b.environment_id AND e.collection_id=c.id
            AND e.is_active=true
           WHERE c.id=$1 AND c.target_id=$4 AND c.is_active=true
             AND b.target_id=$4 AND b.target_kind=$5
           FOR UPDATE OF c, b, s""",
        collection_id, binding_id, selection_id, target_id, target.target_kind,
    )
    if not row:
        raise HTTPException(
            status_code=409,
            detail="broker request collection selection is unavailable",
        )
    stored_origins = tuple(str(item) for item in _broker_json_array(
        row["allowed_origins"], subject="broker collection origins",
    ) if str(item))
    expected_origins = tuple(str(item) for item in ref.get("allowed_origins") or ())
    expected_payload_digest = str(ref.get("payload_sha256") or "").lower()
    expected_selection_digest = str(ref.get("selection_digest") or "").lower()
    expected_environment_id = str(ref.get("environment_id") or "") or None
    expected_environment_digest = str(
        ref.get("environment_sha256") or ""
    ).lower() or None
    stored_environment_id = str(row["environment_id"]) if row["environment_id"] else None
    stored_environment_digest = str(row["environment_sha256"] or "").lower() or None
    if (
        str(ref.get("target_id") or "") != target.target_id
        or str(ref.get("target_kind") or "") != target.target_kind
        or stored_origins != expected_origins
        or any(origin not in target.allowed_origins for origin in stored_origins)
        or str(row["payload_sha256"] or "").lower() != expected_payload_digest
        or stored_environment_id != expected_environment_id
        or stored_environment_digest != expected_environment_digest
        or str(row["replay_policy"] or "") != replay_policy
    ):
        raise HTTPException(
            status_code=409,
            detail="broker request collection changed after admission",
        )
    try:
        selection = RequestCollectionSelection.from_mapping(
            _broker_json_object(
                row["selector_json"], subject="broker collection selector",
            )
        )
    except RequestCollectionContractError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if (
        str(row["selection_digest"] or "").lower() != expected_selection_digest
        or request_collection_selection_digest(
            collection_id=str(collection_id),
            payload_sha256=expected_payload_digest,
            binding_id=str(binding_id),
            allowed_origins=stored_origins,
            selector=selection,
            replay_policy=replay_policy,
            environment_sha256=stored_environment_digest,
        ) != expected_selection_digest
    ):
        raise HTTPException(
            status_code=409,
            detail="broker request collection selection digest changed",
        )
    raw_payload = str(decrypt_secret(row["encrypted_payload"]) or "")
    if not raw_payload or raw_payload.startswith("enc:fernet:"):
        raise HTTPException(
            status_code=409,
            detail="broker request collection could not be decrypted",
        )
    try:
        collection_payload = json.loads(raw_payload)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=409, detail="broker request collection payload is invalid",
        ) from exc
    if not isinstance(collection_payload, Mapping) or hashlib.sha256(json.dumps(
        collection_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")).hexdigest() != expected_payload_digest:
        raise HTTPException(
            status_code=409,
            detail="broker request collection failed its content digest",
        )
    collection_payload = dict(collection_payload)
    if expected_environment_id:
        raw_environment = str(decrypt_secret(row["encrypted_environment"]) or "")
        if not raw_environment or raw_environment.startswith("enc:fernet:"):
            raise HTTPException(
                status_code=409,
                detail="broker request collection environment could not be decrypted",
            )
        try:
            environment = json.loads(raw_environment)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=409,
                detail="broker request collection environment is invalid",
            ) from exc
        if not isinstance(environment, Mapping) or hashlib.sha256(json.dumps(
            environment,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")).hexdigest() != expected_environment_digest:
            raise HTTPException(
                status_code=409,
                detail="broker request collection environment failed its digest",
            )
        collection_payload["environment"] = dict(environment)
    try:
        replay_plan = build_selected_replay_plan(
            collection_payload,
            scan_replay_selector(
                selection,
                replay_policy,
                runtime_limit=selection.max_requests,
            ),
            allowed_origins=stored_origins,
            default_origin=stored_origins[0] if stored_origins else None,
            authorization=scan_replay_authorization(
                replay_policy,
                options.get("scan_policy")
                if isinstance(options.get("scan_policy"), Mapping) else {},
                approval_receipt_id=options.get("approval_receipt_id"),
            ),
        )
        replay_plan = narrow_replay_plan_to_request_manifest(
            replay_plan, manifest,
        )
        return private_replay_plan_payload(replay_plan)
    except (ValueError, ScanCollectionReplayContractError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _fleet_node_is_schedulable(node: Mapping[str, Any]) -> bool:
    """Return whether a remote node may accept work right now.

    A verified local-build tag is an explicit development mode. It is allowed to
    execute scans, but ``image_current`` remains false so image-drift telemetry
    and benchmark safeguards continue to expose that it is not the pinned image.
    """
    return (
        node.get("status") == "healthy"
        and not bool(node.get("drain"))
        and not bool(node.get("rollout_in_progress"))
        and bool(node.get("state_current"))
        and (bool(node.get("image_current")) or bool(node.get("local_build_active")))
    )


def _compute_broker_active_scan_cap(
    nodes: list[Mapping[str, Any]],
    *,
    override: Any = None,
) -> int:
    """Bound broker concurrency by currently schedulable broker workers.

    The optional environment override is a ceiling, never a capacity increase.
    """
    available = sum(
        max(0, int(node.get("active_worker_count") or 0))
        for node in nodes
        if _fleet_node_is_schedulable(node)
        and str(_broker_node_labels(node).get("transport") or "").strip().lower() == "broker"
    )
    cap = max(1, available)
    if override not in (None, ""):
        try:
            cap = min(cap, max(1, int(override)))
        except (TypeError, ValueError):
            pass
    return max(1, min(16_384, cap))


_BROKER_PRIVATE_INPUT_CAPABILITIES = frozenset({
    "auth.session.establish",
    "collections.replay_safe",
    "collections.replay_authentication",
    "collections.replay_active",
    "xss.request_verify",
    "sqli.request_verify",
    "xss.request_verify_batch",
    "sqli.request_verify_batch",
})


async def _resolve_runtime_target_addresses(
    url: str, *, subject: str = "runtime target",
) -> list[str]:
    """Resolve once at admission time; execution connects only to this address set."""
    parsed = urllib.parse.urlsplit(str(url or ""))
    hostname = str(parsed.hostname or "").strip().rstrip(".")
    if not hostname:
        raise HTTPException(
            status_code=400, detail=f"{subject} has no resolvable hostname"
        )
    try:
        return [str(ipaddress.ip_address(hostname))]
    except ValueError:
        pass
    port = int(parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
    try:
        records = await asyncio.get_running_loop().getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
        )
    except OSError as exc:
        raise HTTPException(
            status_code=422, detail=f"{subject} DNS resolution failed"
        ) from exc
    addresses: list[str] = []
    for record in records:
        try:
            address = str(ipaddress.ip_address(str(record[4][0]).split("%", 1)[0]))
        except (IndexError, ValueError):
            continue
        if address not in addresses:
            addresses.append(address)
        if len(addresses) >= 16:
            break
    if not addresses:
        raise HTTPException(
            status_code=422, detail=f"{subject} DNS returned no usable address"
        )
    return addresses
def _broker_json_object(value: Any, *, subject: str) -> dict[str, Any]:
    parsed = parse_json_field(value)
    if not isinstance(parsed, Mapping):
        raise HTTPException(status_code=409, detail=f"{subject} is invalid")
    return dict(parsed)


def _broker_json_array(value: Any, *, subject: str) -> list[Any]:
    parsed = parse_json_field(value)
    if not isinstance(parsed, list):
        raise HTTPException(status_code=409, detail=f"{subject} is invalid")
    return parsed
