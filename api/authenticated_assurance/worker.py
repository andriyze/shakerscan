"""One owner-reviewed GET using the canonical HTTP adapter and credential resolver.

Queue messages contain only request IDs. No response content, resolved headers, or
application-supplied text is persisted, logged, or returned by this worker.
"""

import asyncio
from datetime import datetime, timezone
import json
import math
from uuid import UUID, uuid4

from runtime.capability_settlement import terminalize_capability_reservation
from runtime.credential_resolver import WorkerCredentialResolver, validate_worker_credential_authority
from runtime.credentials import IMMEDIATE_HTTP_HEADER_KINDS

from .health_probe import observe_identity
from .job_lifecycle import claim_request, lock_request, unknown_observation
from .jobs import ACTION_NAME, CAPABILITY, CAPABILITY_REGISTRY, ValidationJobs, target_binding
from .models import ProfileConfiguration, ValidationRecord, exact_origin
from .store import ProfileConflict, decode


async def _profile_for_execution(conn, row):
    profile = await ValidationJobs().profiles.get(conn, row["profile_id"], revision=row["revision"])
    if not profile or profile["current_profile_revision"] != row["revision"]:
        raise ProfileConflict("profile_changed")
    if profile["current_lifecycle_state"] in {"disabled", "archived"}:
        raise ProfileConflict("profile_disabled")
    if not profile["credential_active"]:
        raise ProfileConflict("credential_revoked")
    if (profile["current_version"] != profile["credential_version"] or
            profile["current_record_version"] != profile["credential_record_version"]):
        raise ProfileConflict("credential_changed")
    if profile["credential_expires_at"] and profile["credential_expires_at"] <= datetime.now(timezone.utc):
        raise ProfileConflict("credential_expired")
    config = ProfileConfiguration.model_validate(profile["configuration"])
    binding = target_binding(decode(row["target_binding_json"]))
    target = await conn.fetchrow("SELECT url FROM targets WHERE id=$1 AND is_active=true", config.target_id)
    if (not target or exact_origin(target["url"]) != config.credential_destinations[0]
            or list(binding.allowed_origins) != config.credential_destinations
            or str(binding.target_id) != str(config.target_id)):
        raise ProfileConflict("destination_rejected")
    if config.credential_destinations[0].startswith("http://") and not row["allow_insecure_transport"]:
        raise ProfileConflict("insecure_transport_not_approved")
    return profile, config, binding


async def _observe(conn, row, attempt):
    profile, config, binding = await _profile_for_execution(conn, row)
    authority = await validate_worker_credential_authority(conn, owner_kind="validation", owner_id=str(row["id"]),
        target=binding, approval_receipt_id=row["approval_receipt_id"], scope_receipt_id=binding.scope_receipt_id,
        action_name=ACTION_NAME)
    # Also require an action-bound receipt, rather than a legacy unbound receipt.
    action = await conn.fetchval("SELECT action_name FROM approval_receipts WHERE id=$1", row["approval_receipt_id"])
    if action != ACTION_NAME:
        raise ProfileConflict("approval_unavailable")
    async with WorkerCredentialResolver().resolve(conn, profile_id=row["profile_id"], target=binding,
            capability=CAPABILITY, authority=authority, expected_version=profile["credential_version"],
            expected_record_version=profile["credential_record_version"]) as credential:
        if credential.profile.auth_kind not in IMMEDIATE_HTTP_HEADER_KINDS:
            raise ProfileConflict("validation_not_supported")
        return await observe_identity(config, target=binding, headers=credential.http_headers().as_dict(),
            principal_slot=credential.profile.principal_slot, revision=profile["revision"],
            credential_version=profile["credential_version"], credential_record_version=profile["credential_record_version"],
            generation=row["process_generation"], attempt=attempt)


async def _watch_stop(pool, row):
    while True:
        async with pool.acquire() as conn:
            current = await conn.fetchrow("SELECT status, reason_code FROM authentication_validation_requests WHERE id=$1", row["id"])
        if not current or current["status"] != "running":
            return current["reason_code"] if current and current["reason_code"] else "validation_cancelled"
        if datetime.now(timezone.utc) >= row["deadline_at"]:
            return "validation_timeout"
        await asyncio.sleep(0.2)


async def _run_bounded(pool, row, attempt):
    async def observe():
        async with pool.acquire() as conn:
            return await _observe(conn, row, attempt)
    observation_task = asyncio.create_task(observe())
    stop_task = asyncio.create_task(_watch_stop(pool, row))
    try:
        done, _ = await asyncio.wait((observation_task, stop_task), return_when=asyncio.FIRST_COMPLETED)
        if stop_task in done:
            raise ProfileConflict(stop_task.result())
        return observation_task.result()
    finally:
        for task in (observation_task, stop_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(observation_task, stop_task, return_exceptions=True)


async def _settle(conn, row, observation, *, attempt, execution_status):
    jobs = ValidationJobs()
    current, stored = await lock_request(conn, row["id"])
    if stored.record.status != "running" or stored.record.worker_id != row["worker_id"]:
        return  # Recovery already made this uncertain. Never resurrect it.
    if current["status"] != "running":
        profile = await jobs.profiles.get(conn, row["profile_id"], revision=row["revision"])
        reason = current["reason_code"] or "validation_cancelled"
        observation = unknown_observation(profile, row["process_generation"], reason)
        execution_status = "cancelled" if current["status"] == "cancelled" else "failed"
    # Revalidate receipt authority after the response, just as record() rechecks
    # credential and profile revocation. These checks never cause another GET.
    if observation.state == "valid":
        try:
            _, _, binding = await _profile_for_execution(conn, row)
            await validate_worker_credential_authority(conn, owner_kind="validation", owner_id=str(row["id"]),
                target=binding, approval_receipt_id=row["approval_receipt_id"], scope_receipt_id=binding.scope_receipt_id,
                action_name=ACTION_NAME)
        except Exception:
            observation = ValidationRecord.model_validate({**observation.model_dump(), "state": "unknown",
                "reason_code": "approval_unavailable", "identity_matched": False, "role_matched": None, "valid_until": None})
    receipt_id = uuid4()
    observation = ValidationRecord.model_validate({**observation.model_dump(), "evidence_reference": receipt_id, "request_id": row["id"]})
    observation = await jobs.profiles.record(conn, observation)
    spec = CAPABILITY_REGISTRY.require(CAPABILITY)
    actual = {"http_requests": int(attempt["started"]), "hosts_attempted": int(attempt["started"]),
              "tool_wall_seconds": min(math.ceil(attempt.get("elapsed", 0)), stored.record.requested["tool_wall_seconds"])}
    terminal, receipt = terminalize_capability_reservation(stored.record,
        action_digest=observation.configuration_digest, capability_name=CAPABILITY,
        adapter_name=spec.adapter, adapter_version=spec.adapter_version,
        target_id=decode(row["target_binding_json"])["target_id"],
        target_kind=decode(row["target_binding_json"])["target_kind"],
        capability_input={"method": "GET", "profile_revision": row["revision"]},
        action_status=execution_status, actual_budget=actual, worker_id=row["worker_id"],
        started_at=row["started_at"].isoformat(), finished_at=datetime.now(timezone.utc).isoformat(),
        receipt_id=str(receipt_id), parser_version=spec.output_schema,
        scope_receipt_id=decode(row["target_binding_json"])["scope_receipt_id"],
        approval_receipt_id=row["approval_receipt_id"],
        result={"execution_started": attempt["started"], "receipt_observations": [{"kind": "http_observation",
            "authentication_state": observation.state, "reason_code": observation.reason_code,
            "identity_matched": observation.identity_matched, "response_content_retained": False,
            "measured_http_elapsed_ms": round(attempt.get("elapsed", 0) * 1000),
            "wall_time_charge_capped": math.ceil(attempt.get("elapsed", 0)) > stored.record.requested["tool_wall_seconds"]}]})
    ledger = terminal.reconcile_consumed(decode(current["budget_used_json"]))
    await jobs.reservations.persist_terminal(conn, previous=stored, terminal=terminal,
        ledger_after_settlement=ledger, receipt=receipt)
    status = "completed" if execution_status == "completed" else "cancelled" if execution_status == "cancelled" else "failed"
    await conn.execute("""UPDATE authentication_validation_requests SET status=$2, reason_code=$3,
        finished_at=NOW(), budget_used_json=$4::jsonb, validation_record_id=$5 WHERE id=$1""",
        row["id"], status, observation.reason_code, json.dumps(ledger), observation.validation_id)


async def process_validation_job(payload, *, pool, worker_id, build_fingerprint):
    job_id = UUID(str(payload.get("validation_id")))
    if str(payload.get("job_id")) != str(job_id):
        raise ValueError("validation job identity mismatch")
    async with pool.acquire() as conn, conn.transaction():
        row = await claim_request(conn, job_id, worker_id, build_fingerprint)
    if not row:
        return
    attempt, execution_status = {"started": False}, "completed"
    try:
        observation = await _run_bounded(pool, row, attempt)
    except Exception as exc:
        # Never expose exception text: resolvers and HTTP clients can hold secrets.
        reason = str(exc) if isinstance(exc, ProfileConflict) else "validation_timeout" if isinstance(exc, TimeoutError) else "validation_unavailable"
        execution_status = "cancelled" if reason == "validation_cancelled" else "failed"
        async with pool.acquire() as conn:
            profile = await ValidationJobs().profiles.get(conn, row["profile_id"], revision=row["revision"])
        observation = unknown_observation(profile, row["process_generation"], reason)
    async with pool.acquire() as conn, conn.transaction():
        await _settle(conn, row, observation, attempt=attempt, execution_status=execution_status)
