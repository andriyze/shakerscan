"""Durable lifecycle helpers for signed Model Intake admission packages."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LEGACY_ADMISSION_SCHEMA_VERSION = "model-intake-admission/v1"
REASSESSMENT_TRIGGERS = {
    "model_revision",
    "artifact_digest",
    "runtime_change",
    "loader_change",
    "cve_update",
    "malware_rules_update",
    "secret_rules_update",
    "unsafe_model_rules_update",
    "scanner_update",
    "scanner_data_stale",
    "policy_change",
    "data_classification_change",
    "exception_expiry",
    "upstream_compromise",
    "upstream_ownership_change",
    "retrieval_drift",
    "resource_regression",
    "poisoning_indicator",
    "authorization_incident",
    "scheduled_review",
}
IMMEDIATE_REVOCATION_TRIGGERS = {"upstream_compromise", "poisoning_indicator", "authorization_incident"}


def _parse_time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def record_from_result(
    *, scan_id: str, target_id: str | None, result: Any, reassessment_days: int = 30
) -> dict[str, Any] | None:
    model_intake = result.get("model_intake") if isinstance(result, dict) else None
    package = model_intake.get("admission") if isinstance(model_intake, dict) else None
    if not isinstance(package, dict) or package.get("status") != "SIGNED":
        return None
    statement = package.get("statement") if isinstance(package.get("statement"), dict) else {}
    subject = statement.get("subject") if isinstance(statement.get("subject"), dict) else {}
    decision_data = statement.get("decision") if isinstance(statement.get("decision"), dict) else {}
    policy = statement.get("policy") if isinstance(statement.get("policy"), dict) else {}
    artifact_sha256 = str(subject.get("artifact_sha256") or "").lower()
    statement_sha256 = str(package.get("statement_sha256") or "").lower()
    issued_at = _parse_time(statement.get("issued_at"))
    expires_at = _parse_time(statement.get("expires_at"))
    if not SHA256_RE.fullmatch(artifact_sha256) or not SHA256_RE.fullmatch(statement_sha256) or not issued_at or not expires_at:
        return None
    decision = str(decision_data.get("outcome") or "block").lower()
    schema_version = str(statement.get("_type") or LEGACY_ADMISSION_SCHEMA_VERSION)
    if schema_version != LEGACY_ADMISSION_SCHEMA_VERSION:
        # Admission v2 is not released yet. New schemas require a dedicated
        # verifier/signer and exact-bundle regression suite before persistence.
        return None
    status = "active" if decision == "allow" and expires_at > datetime.now(timezone.utc) else "denied"
    if status == "active":
        status = "reassessment_required"
    reassessment_due = min(expires_at, issued_at + timedelta(days=max(1, min(int(reassessment_days), 365))))
    return {
        "scan_id": str(uuid.UUID(str(scan_id))),
        "target_id": str(uuid.UUID(str(target_id))) if target_id else None,
        "artifact_sha256": artifact_sha256,
        "repository_snapshot_sha256": str(subject.get("repository_snapshot_sha256") or "").lower() or None,
        "statement_sha256": statement_sha256,
        "admission_package": package,
        "decision": decision,
        "status": status,
        "schema_version": schema_version,
        "policy_profile": policy.get("profile"),
        "policy_version": policy.get("version"),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "reassessment_due_at": reassessment_due,
    }


async def persist_from_result(
    conn: Any, *, scan_id: str, target_id: str | None, result: Any, reassessment_days: int = 30
) -> dict[str, Any] | None:
    record = record_from_result(
        scan_id=scan_id,
        target_id=target_id,
        result=result,
        reassessment_days=reassessment_days,
    )
    if record is None:
        return None
    if record["status"] == "active" and record["target_id"]:
        await conn.execute(
            """UPDATE model_intake_admissions
               SET status='superseded', updated_at=NOW()
               WHERE target_id=$1 AND status='active' AND scan_id<>$2""",
            uuid.UUID(record["target_id"]),
            uuid.UUID(record["scan_id"]),
        )
    row = await conn.fetchrow(
        """INSERT INTO model_intake_admissions (
               scan_id, target_id, artifact_sha256, repository_snapshot_sha256,
               statement_sha256, admission_package, decision, status, schema_version,
               policy_profile, policy_version, issued_at, expires_at, reassessment_due_at
           ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,$11,$12,$13,$14)
           ON CONFLICT (scan_id) DO UPDATE SET
               admission_package=EXCLUDED.admission_package,
               statement_sha256=EXCLUDED.statement_sha256,
               updated_at=NOW()
           RETURNING id, status""",
        uuid.UUID(record["scan_id"]),
        uuid.UUID(record["target_id"]) if record["target_id"] else None,
        record["artifact_sha256"],
        record["repository_snapshot_sha256"],
        record["statement_sha256"],
        json.dumps(record["admission_package"]),
        record["decision"],
        record["status"],
        record["schema_version"],
        record["policy_profile"],
        record["policy_version"],
        record["issued_at"],
        record["expires_at"],
        record["reassessment_due_at"],
    )
    if row:
        await conn.execute(
            """INSERT INTO model_intake_admission_events
               (admission_id, event_type, actor, reason, new_status, evidence_digest)
               VALUES ($1,'registered','worker','Signed scan decision registered',$2,$3)""",
            row["id"], row["status"], record["statement_sha256"],
        )
    return {**record, "id": str(row["id"]) if row else None}


def triggered_status(trigger_type: str, requested_action: str = "reassess") -> str:
    trigger = str(trigger_type or "").strip().lower()
    if trigger not in REASSESSMENT_TRIGGERS:
        raise ValueError("unsupported reassessment trigger")
    action = str(requested_action or "reassess").strip().lower()
    if action not in {"reassess", "revoke"}:
        raise ValueError("requested action must be reassess or revoke")
    return "revoked" if action == "revoke" or trigger in IMMEDIATE_REVOCATION_TRIGGERS else "reassessment_required"


__all__ = ["REASSESSMENT_TRIGGERS", "persist_from_result", "record_from_result", "triggered_status"]
