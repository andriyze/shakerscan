"""One-shot validation requests on the existing queue/reservation infrastructure."""

from datetime import datetime, timedelta, timezone
import json
from uuid import UUID, uuid4

try:
    from runtime.budget_reservations import DurableBudgetReservation
    from runtime.reservation_store import PostgresBudgetReservationStore
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from runtime.credentials import IMMEDIATE_HTTP_HEADER_KINDS
    from runtime.credential_store import PostgresCredentialProfileStore
    from runtime.models import TargetBinding
except ModuleNotFoundError:
    from api.runtime.budget_reservations import DurableBudgetReservation
    from api.runtime.reservation_store import PostgresBudgetReservationStore
    from api.runtime.capability_registry import CAPABILITY_REGISTRY
    from api.runtime.credentials import IMMEDIATE_HTTP_HEADER_KINDS
    from api.runtime.credential_store import PostgresCredentialProfileStore
    from api.runtime.models import TargetBinding

from .models import ProfileConfiguration, ValidationRequest
from .evaluation import evaluate_health_response
from .store import AssuranceStore, ProfileConflict, decode

JOB_TYPE = "authentication_validation"
ACTION_NAME = "authentication.validate"
CAPABILITY = "http.request"
QUEUE_DEADLINE_SECONDS = 60
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS authentication_validation_requests (
    id UUID PRIMARY KEY,
    profile_id UUID NOT NULL,
    revision INTEGER NOT NULL,
    approval_receipt_id UUID NOT NULL,
    target_binding_json JSONB NOT NULL,
    process_generation UUID NOT NULL,
    expected_build_fingerprint TEXT NOT NULL,
    allow_insecure_transport BOOLEAN NOT NULL DEFAULT false,
    status TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed','cancelled')),
    reason_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deadline_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_by TEXT NOT NULL,
    worker_id TEXT,
    budget_used_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    reservation_id TEXT NOT NULL REFERENCES budget_reservations(id),
    validation_record_id UUID REFERENCES authentication_validations(id),
    FOREIGN KEY (profile_id, revision) REFERENCES authenticated_profile_revisions(profile_id, revision)
);
ALTER TABLE authentication_validation_requests ADD COLUMN IF NOT EXISTS expected_build_fingerprint TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS authentication_validation_requests_profile_time
    ON authentication_validation_requests(profile_id, created_at DESC);
INSERT INTO app_schema_migrations(name) VALUES ('authentication_validation_requests_v1')
ON CONFLICT (name) DO NOTHING;
"""


def validation_supported() -> bool:
    spec = CAPABILITY_REGISTRY.require(CAPABILITY)
    return spec.credential_transport == "exact_origin" and spec.credential_interruption == "cooperative"


def validation_identity_contract() -> dict:
    return CAPABILITY_REGISTRY.require(CAPABILITY).identity_contract()


def validation_budget(config: ProfileConfiguration) -> dict[str, int]:
    spec = CAPABILITY_REGISTRY.require(CAPABILITY)
    return {"http_requests": 1, "hosts_attempted": 1,
            "tool_wall_seconds": min(spec.budget_cost["tool_wall_seconds"], config.validation_policy.timeout_seconds + 1)}


def target_binding(value: dict) -> TargetBinding:
    return TargetBinding(**{key: value[key] for key in (
        "target_id", "target_kind", "canonical_host", "allowed_origins", "allowed_addresses",
        "allowed_root_domains", "environment", "scope_receipt_id",
    ) if key in value})


class ValidationJobs:
    def __init__(self):
        self.profiles = AssuranceStore()
        self.reservations = PostgresBudgetReservationStore()

    async def prepare(self, conn, *, profile_id: UUID, request: ValidationRequest,
                      actor: str, generation: UUID, expected_build_fingerprint: str, approve, freeze) -> dict:
        """Caller holds a transaction. Reserve capacity before enqueueing any work."""
        if not expected_build_fingerprint:
            raise ProfileConflict("worker_unavailable")
        if not validation_supported():
            raise ProfileConflict("validation_not_supported")
        credential = await conn.fetchrow("SELECT * FROM credential_profiles WHERE id=$1 FOR UPDATE", profile_id)
        profile = await self.profiles.get(conn, profile_id)
        if not credential or not profile:
            raise ProfileConflict("authenticated_profile_not_found")
        if profile["revision"] != request.expected_revision:
            raise ProfileConflict("profile_changed")
        config = ProfileConfiguration.model_validate(profile["configuration"])
        if config.lifecycle_state in {"disabled", "archived"}:
            raise ProfileConflict("profile_disabled")
        if not credential["is_active"]:
            raise ProfileConflict("credential_revoked")
        if credential["expires_at"] and credential["expires_at"] <= datetime.now(timezone.utc):
            raise ProfileConflict("credential_expired")
        if credential["auth_kind"] not in IMMEDIATE_HTTP_HEADER_KINDS:
            raise ProfileConflict("validation_not_supported")
        metadata = await PostgresCredentialProfileStore().get_profile(conn, profile_id=profile_id)
        if CAPABILITY not in metadata.allowed_capabilities:
            raise ProfileConflict("credential_capability_not_allowed")
        if (credential["current_version"] != profile["credential_version"] or
                credential["record_version"] != profile["credential_record_version"]):
            raise ProfileConflict("credential_changed")
        origin = config.credential_destinations[0]
        if origin.startswith("http://") and not request.allow_insecure_transport:
            raise ProfileConflict("insecure_transport_not_approved")
        recent = await conn.fetchval(
            """SELECT EXISTS(SELECT 1 FROM authentication_validation_requests
               WHERE profile_id=$1 AND (created_at > NOW() - INTERVAL '30 seconds'
                  OR (status IN ('queued','running') AND deadline_at > NOW())))""", profile_id,
        )
        if recent:
            raise ProfileConflict("validation_rate_limited")
        target = await conn.fetchrow("SELECT url FROM targets WHERE id=$1 AND is_active=true", config.target_id)
        from .models import exact_origin
        if not target or exact_origin(target["url"]) != origin:
            raise ProfileConflict("destination_rejected")
        authority = await approve(
            conn, str(request.approval_receipt_id), target_url=origin, target_id=config.target_id,
            action_name=ACTION_NAME, required_action_name=ACTION_NAME, risk_tier="credential",
            always_require_receipt=True, require_target_binding=True, require_expiry=True,
        )
        guard = await freeze(target_id=config.target_id, target_kind=credential["target_kind"],
                             target_url=origin, scope_receipt_id=authority["scope_receipt_id"], scheme_inferred=False,
                             existing_guard=authority.get("runtime_scope_guard"), subject="Authentication health target")
        # A host-level receipt never widens the credential disclosure destination.
        guard["allowed_origins"] = [origin]
        binding = target_binding(guard)
        now = datetime.now(timezone.utc)
        job_id = uuid4()
        budget = validation_budget(config)
        requested = DurableBudgetReservation.request(owner_kind="validation", owner_id=str(job_id),
            capability_name=CAPABILITY, amounts=budget, now=now)
        stored = await self.reservations.create_requested(conn, action_id="identity.health",
            action_digest=profile["configuration_digest"], record=requested)
        reserved, ledger = requested.reserve_against(limits=budget, consumed={}, now=now, lease_seconds=90)
        await self.reservations.persist_transition(conn, previous=stored, current=reserved, ledger_after_hold=ledger)
        await conn.execute(
            """INSERT INTO authentication_validation_requests
               (id,profile_id,revision,approval_receipt_id,target_binding_json,process_generation,
                allow_insecure_transport,status,deadline_at,created_by,budget_used_json,reservation_id,expected_build_fingerprint)
               VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,'queued',$8,$9,$10::jsonb,$11,$12)""",
            job_id, profile_id, profile["revision"], request.approval_receipt_id,
            json.dumps(binding.canonical_dict()), generation, request.allow_insecure_transport,
            now + timedelta(seconds=QUEUE_DEADLINE_SECONDS), actor, json.dumps(ledger), reserved.reservation_id, expected_build_fingerprint,
        )
        # A new attempt starts an uncertainty interval immediately. An unavailable
        # worker must not leave an earlier fresh success green while it times out.
        # Preserve ordering even if a prior worker clock was ahead of the API.
        # Equal-time uncertainty wins over validity in the canonical projection.
        pending_at = max(now, datetime.fromisoformat(profile["validation"]["checked_at"])) if profile["validation"] else now
        pending = evaluate_health_response(config, revision=profile["revision"],
            credential_version=profile["credential_version"], credential_record_version=profile["credential_record_version"],
            checked_at=pending_at, process_generation=generation)
        await self.profiles.record(conn, pending.model_copy(update={"reason_code": "validation_pending", "request_id": job_id}))
        return {"type": JOB_TYPE, "job_id": str(job_id), "validation_id": str(job_id)}

    async def read(self, conn, job_id: UUID) -> dict | None:
        row = await conn.fetchrow("SELECT * FROM authentication_validation_requests WHERE id=$1", job_id)
        if not row:
            return None
        expired = row["status"] in {"queued", "running"} and row["deadline_at"] <= datetime.now(timezone.utc)
        observation = None
        if row["validation_record_id"]:
            record = await conn.fetchval("SELECT record_json FROM authentication_validations WHERE id=$1", row["validation_record_id"])
            observation = decode(record) if record else None
        reservation = await self.reservations.load(conn, row["reservation_id"])
        return {"request_id": str(row["id"]), "profile_id": str(row["profile_id"]), "revision": row["revision"],
                "status": "failed" if expired else row["status"],
                "reason_code": "validation_timeout" if expired else row["reason_code"],
                "created_at": row["created_at"], "deadline_at": row["deadline_at"],
                "validation": observation,
                "budget_reserved": dict(reservation.record.requested) if reservation else {},
                "budget_consumed": dict(reservation.record.actual) if reservation and reservation.record.terminal else None,
                "receipt": dict(reservation.receipt) if reservation and reservation.receipt else None,
                "secret_values_visible": False}
