"""Dedicated narrow Model Intake admission signer service.

The API accepts only a stored policy-decision ID plus idempotency key. It does
not accept bytes to sign, trust roots, approvals, policy input, or model data.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

import asyncpg
from fastapi import FastAPI, HTTPException
try:
    from fastapi import Header
except ImportError:  # pragma: no cover - minimal API-module test shims
    def Header(default=None):
        return default
from pydantic import BaseModel, ConfigDict, Field

try:
    from model_intake_control_plane import (
        AdmissionContractError,
        AwsKmsSigner,
        LocalPemSigner,
        issue_admission_v2,
    )
except ModuleNotFoundError:  # pragma: no cover - package import in tests
    from api.model_intake_control_plane import (
        AdmissionContractError,
        AwsKmsSigner,
        LocalPemSigner,
        issue_admission_v2,
    )


class IssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_decision_id: str
    idempotency_key: str = Field(min_length=16, max_length=200)
    requested_by_subject: str = Field(
        pattern=r"^(?:operator-token:[0-9a-f]{24}|operator:[A-Za-z0-9][A-Za-z0-9_.:@/-]{1,199})$"
    )


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _signer_provider(target_environment: str):
    backend = os.getenv("MODEL_INTAKE_SIGNER_BACKEND", "").strip().lower()
    if backend == "aws-kms":
        return AwsKmsSigner(
            os.getenv("MODEL_INTAKE_SIGNER_AWS_KMS_KEY_ID", ""),
            region=os.getenv("MODEL_INTAKE_SIGNER_AWS_REGION") or None,
        )
    if backend == "local-pem":
        if target_environment == "production":
            raise AdmissionContractError("local PEM signing is prohibited for production admissions")
        if os.getenv("MODEL_INTAKE_SIGNER_ALLOW_LOCAL_PEM", "").strip().lower() not in {"1", "true", "yes"}:
            raise AdmissionContractError("local PEM signer requires explicit development opt-in")
        pem = os.getenv("MODEL_INTAKE_CONTROL_PLANE_SIGNING_KEY_PEM", "")
        if not pem:
            raise AdmissionContractError("local signer key is unavailable")
        return LocalPemSigner(pem)
    raise AdmissionContractError("no supported admission signer backend is configured")


def _authorize_internal(presented: str | None) -> None:
    expected = os.getenv("MODEL_INTAKE_SIGNER_INTERNAL_TOKEN", "")
    if len(expected) < 32 or not presented or not secrets.compare_digest(presented, expected):
        raise HTTPException(status_code=403, detail="signer service authentication failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    database_url = os.getenv("DATABASE_URL", "")
    app.state.pool = await asyncpg.create_pool(database_url, min_size=1, max_size=4) if database_url else None
    try:
        yield
    finally:
        if app.state.pool:
            await app.state.pool.close()


app = FastAPI(title="ShakerScan Model Intake Signer", lifespan=lifespan)


@app.get("/health")
async def health():
    backend = os.getenv("MODEL_INTAKE_SIGNER_BACKEND", "").strip().lower()
    configured = bool(
        backend == "aws-kms" and os.getenv("MODEL_INTAKE_SIGNER_AWS_KMS_KEY_ID")
        or backend == "local-pem" and os.getenv("MODEL_INTAKE_CONTROL_PLANE_SIGNING_KEY_PEM")
    )
    dependency_available = backend != "aws-kms" or importlib.util.find_spec("boto3") is not None
    database_ready = False
    if app.state.pool is not None:
        try:
            database_ready = bool(await app.state.pool.fetchval("SELECT 1"))
        except (asyncpg.PostgresError, OSError):
            database_ready = False
    ready = configured and dependency_available and database_ready
    return {
        "status": "healthy" if ready else "not_ready",
        "service": "model-intake-signer",
        "backend": backend or None,
        "configured": configured,
        "dependency_available": dependency_available,
        "database_ready": database_ready,
        "generic_signing_api": False,
    }


@app.post("/internal/model-intake/admissions/issue")
async def issue(
    request: IssueRequest,
    x_shakerscan_signer_token: str | None = Header(default=None),
):
    _authorize_internal(x_shakerscan_signer_token)
    try:
        decision_uuid = uuid.UUID(request.policy_decision_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid policy decision id") from exc
    pool = app.state.pool
    if pool is None:
        raise HTTPException(status_code=503, detail="signer database is unavailable")
    idempotency_digest = hashlib.sha256(request.idempotency_key.encode()).hexdigest()
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Serialize one digest without granting the signer UPDATE on the
            # admission registry. The unique index remains the final guard.
            await conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                idempotency_digest,
            )
            existing = await conn.fetchrow(
                "SELECT * FROM model_intake_admissions WHERE idempotency_key_sha256=$1",
                idempotency_digest,
            )
            if existing:
                return {
                    "admission_id": str(existing["id"]),
                    "status": existing["status"],
                    "admission_package": _json_object(existing["admission_package"]),
                    "idempotent_replay": True,
                }
            row = await conn.fetchrow(
                """
                SELECT decision.*,submission.scan_id,submission.id AS submission_id,submission.state AS submission_state,
                       manifest.manifest_json,manifest.deployment_bundle_json,
                       manifest.manifest_sha256,scan.target_id,
                       manifest.id=(
                           SELECT latest.id FROM model_intake_evidence_manifests AS latest
                           WHERE latest.submission_id=submission.id
                           ORDER BY latest.version DESC LIMIT 1
                       ) AS is_latest_manifest
                FROM model_intake_policy_decisions AS decision
                JOIN model_intake_submissions AS submission ON submission.id=decision.submission_id
                JOIN model_intake_evidence_manifests AS manifest ON manifest.id=decision.evidence_manifest_id
                LEFT JOIN scans AS scan ON scan.id=submission.scan_id
                WHERE decision.id=$1
                FOR UPDATE OF submission
                """,
                decision_uuid,
            )
            if not row:
                raise HTTPException(status_code=404, detail="Stored policy decision not found")
            if row["decision"] != "allow" or not row["scan_id"]:
                raise HTTPException(status_code=409, detail="Only an allow decision with bound scan evidence can be signed")
            if row["submission_state"] != "policy_decided" or not row["is_latest_manifest"]:
                raise HTTPException(status_code=409, detail="Submission evidence changed after the policy decision")
            approvals = [
                _json_object(item["receipt_json"])
                for item in await conn.fetch(
                    """
                    SELECT receipt_json FROM model_intake_approval_receipts
                    WHERE evidence_manifest_id=$1 AND revoked_at IS NULL AND expires_at>NOW()
                    ORDER BY receipt_sha256
                    """,
                    row["evidence_manifest_id"],
                )
            ]
            bundle = _json_object(row["deployment_bundle_json"])
            manifest = _json_object(row["manifest_json"])
            decision = _json_object(row["decision_json"])
            try:
                package = issue_admission_v2(
                    deployment_bundle=bundle,
                    evidence_manifest=manifest,
                    policy_decision=decision,
                    approvals=approvals,
                    signer=_signer_provider(str(bundle.get("target_environment") or "")),
                    admission_builder_id=os.getenv(
                        "MODEL_INTAKE_ADMISSION_BUILDER_ID",
                        "https://shakerscan.dev/builders/model-admission/v2",
                    ),
                    idempotency_key=request.idempotency_key,
                )
            except AdmissionContractError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            predicate = package["statement"]["predicate"]
            admission_id = uuid.uuid4()
            await conn.execute(
                """
                INSERT INTO model_intake_admissions
                    (id,scan_id,target_id,submission_id,artifact_sha256,repository_snapshot_sha256,
                     statement_sha256,admission_package,decision,status,schema_version,
                     deployment_bundle_sha256,evidence_manifest_sha256,policy_decision_sha256,
                     target_environment,idempotency_key_sha256,policy_profile,policy_version,
                     issued_at,expires_at,reassessment_due_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,'allow','active',$9,$10,$11,$12,$13,$14,
                        'corporate-v2','model-intake-policy/v2',$15,$16,$16)
                """,
                admission_id,
                row["scan_id"],
                row["target_id"],
                row["submission_id"],
                bundle["model_artifact_sha256"],
                bundle["repository_snapshot_sha256"],
                package["statement_sha256"],
                json.dumps(package),
                package["schema_version"],
                bundle["bundle_sha256"],
                manifest["manifest_sha256"],
                decision["decision_sha256"],
                bundle["target_environment"],
                idempotency_digest,
                datetime.fromisoformat(predicate["issued_at"]),
                datetime.fromisoformat(predicate["expires_at"]),
            )
            await conn.execute(
                """
                INSERT INTO model_intake_admission_events
                    (admission_id,event_type,actor,reason,new_status,evidence_digest,metadata_json)
                VALUES ($1,'admission_v2_issued',$3,
                        'Exact frozen bundle admitted by narrow signer','active',$2,$4::jsonb)
                """,
                admission_id,
                package["statement_sha256"],
                request.requested_by_subject,
                json.dumps({
                    "issued_by_service": "model-intake-signer",
                    "signer_provider": package["envelope"]["signatures"][0]["provider"],
                }),
            )
            transitioned = await conn.fetchrow(
                """
                UPDATE model_intake_submissions
                SET state='admitted',updated_at=NOW()
                WHERE id=$1 AND state='policy_decided'
                RETURNING id
                """,
                row["submission_id"],
            )
            if not transitioned:
                raise HTTPException(status_code=409, detail="Submission is no longer eligible for admission")
            await conn.execute(
                """
                INSERT INTO model_intake_submission_events
                    (submission_id,event_type,actor,reason,previous_state,new_state,metadata_json)
                VALUES ($1,'admission_issued',$3,
                        'Narrow signer issued an exact-bundle admission','policy_decided','admitted',$2::jsonb)
                """,
                row["submission_id"],
                json.dumps({
                    "issued_by_service": "model-intake-signer",
                    "admission_id": str(admission_id),
                    "policy_decision_id": str(decision_uuid),
                    "statement_sha256": package["statement_sha256"],
                }),
                request.requested_by_subject,
            )
            await conn.execute(
                """
                INSERT INTO model_intake_deployment_bindings
                    (submission_id,admission_id,deployment_bundle_sha256,environment,verifier_status)
                VALUES ($1,$2,$3,$4,'not_observed')
                """,
                row["submission_id"],
                admission_id,
                bundle["bundle_sha256"],
                bundle["target_environment"],
            )
    return {
        "admission_id": str(admission_id),
        "status": "active",
        "admission_package": package,
        "idempotent_replay": False,
    }
