"""Transactional lifecycle helpers; reservations always lock before their owner."""

from datetime import datetime, timezone
import json
from uuid import UUID

from .evaluation import evaluate_health_response
from .jobs import ValidationJobs
from .models import ProfileConfiguration, ValidationRecord


def unknown_observation(profile, generation, reason, *, request_id=None):
    config = ProfileConfiguration.model_validate(profile["configuration"])
    value = evaluate_health_response(config, revision=profile["revision"],
        credential_version=profile["credential_version"],
        credential_record_version=profile["credential_record_version"],
        checked_at=datetime.now(timezone.utc), process_generation=generation)
    return ValidationRecord.model_validate({**value.model_dump(), "reason_code": reason, "request_id": request_id})


async def lock_request(conn, job_id):
    jobs = ValidationJobs()
    reservation_id = await conn.fetchval(
        "SELECT reservation_id FROM authentication_validation_requests WHERE id=$1", job_id)
    if not reservation_id:
        return None, None
    reservation = await jobs.reservations.load(conn, reservation_id, for_update=True)
    row = await conn.fetchrow(
        "SELECT * FROM authentication_validation_requests WHERE id=$1 FOR UPDATE", job_id)
    return row, reservation


async def stop_request(conn, job_id: UUID, *, reason="validation_cancelled"):
    """Stop queued work immediately; a running worker closes its bounded request."""
    jobs = ValidationJobs()
    row, stored = await lock_request(conn, job_id)
    if not row or row["status"] not in {"queued", "running"}:
        return
    status = "cancelled" if reason == "validation_cancelled" else "failed"
    if stored.record.status == "reserved":
        terminal = stored.record.release(proof_not_started=True, reason=reason, now=datetime.now(timezone.utc))
        ledger = terminal.reconcile_consumed(dict(stored.ledger_after_hold))
        await jobs.reservations.persist_terminal(conn, previous=stored, terminal=terminal,
            ledger_after_settlement=ledger, receipt=None)
        profile = await jobs.profiles.get(conn, row["profile_id"], revision=row["revision"])
        observation = await jobs.profiles.record(conn, unknown_observation(profile, row["process_generation"], reason, request_id=job_id))
        await conn.execute("""UPDATE authentication_validation_requests SET status=$2, reason_code=$3,
            finished_at=NOW(), budget_used_json=$4::jsonb, validation_record_id=$5 WHERE id=$1""",
            job_id, status, reason, json.dumps(ledger), observation.validation_id)
    elif stored.record.status == "running":
        await conn.execute("""UPDATE authentication_validation_requests SET status=$2, reason_code=$3
            WHERE id=$1""", job_id, status, reason)


async def claim_request(conn, job_id: UUID, worker_id: str, build_fingerprint: str):
    row, stored = await lock_request(conn, job_id)
    if not row or row["status"] != "queued" or stored.record.status != "reserved":
        return None
    now = datetime.now(timezone.utc)
    if not build_fingerprint or row["expected_build_fingerprint"] != build_fingerprint:
        await stop_request(conn, job_id, reason="worker_unavailable")
        return None
    if row["deadline_at"] <= now:
        await stop_request(conn, job_id, reason="validation_timeout")
        return None
    running = stored.record.start(worker_id=worker_id, now=now, lease_seconds=30)
    await ValidationJobs().reservations.persist_transition(conn, previous=stored, current=running)
    await conn.execute("""UPDATE authentication_validation_requests SET status='running',
        started_at=$2, worker_id=$3 WHERE id=$1""", job_id, now, worker_id)
    return {**dict(row), "started_at": now, "worker_id": worker_id}
