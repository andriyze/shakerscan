"""Additive, immutable assurance revisions referencing the existing secret store."""

from datetime import datetime, timezone
import json
from typing import Any
from uuid import UUID

from .models import ProfileConfiguration, ProfileWrite, ValidationRecord, exact_origin

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS authenticated_profile_revisions (
    profile_id UUID NOT NULL REFERENCES credential_profiles(id),
    revision INTEGER NOT NULL CHECK (revision > 0),
    credential_version INTEGER NOT NULL CHECK (credential_version > 0),
    credential_record_version INTEGER NOT NULL CHECK (credential_record_version >= 0),
    configuration_json JSONB NOT NULL CHECK (jsonb_typeof(configuration_json)='object'),
    configuration_digest TEXT NOT NULL CHECK (configuration_digest ~ '^[a-f0-9]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT NOT NULL,
    PRIMARY KEY (profile_id, revision),
    FOREIGN KEY (profile_id, credential_version)
        REFERENCES credential_profile_versions(profile_id, version)
);
ALTER TABLE authenticated_profile_revisions ADD COLUMN IF NOT EXISTS
    credential_record_version INTEGER NOT NULL DEFAULT 0 CHECK (credential_record_version >= 0);
CREATE TABLE IF NOT EXISTS authentication_validations (
    id UUID PRIMARY KEY,
    profile_id UUID NOT NULL,
    revision INTEGER NOT NULL,
    record_json JSONB NOT NULL CHECK (jsonb_typeof(record_json)='object'),
    checked_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (profile_id, revision)
        REFERENCES authenticated_profile_revisions(profile_id, revision)
);
CREATE INDEX IF NOT EXISTS authentication_validations_profile_time
    ON authentication_validations(profile_id, revision, checked_at DESC, id);
INSERT INTO app_schema_migrations(name) VALUES ('authenticated_scan_assurance_v1')
ON CONFLICT (name) DO NOTHING;
"""


class ProfileConflict(ValueError):
    pass


def decode(value: Any) -> dict:
    return json.loads(value) if isinstance(value, str) else dict(value)


class AssuranceStore:
    async def ensure_schema(self, conn):
        await conn.execute(SCHEMA_SQL)

    async def write(self, conn, request: ProfileWrite, *, actor: str) -> dict:
        config = request.configuration
        # The canonical credential row serializes revisions AND secret revocation/rotation.
        # The caller must hold a transaction; all public entry points do so.
        credential = await conn.fetchrow(
            "SELECT * FROM credential_profiles WHERE id=$1 FOR UPDATE", config.credential_reference,
        )
        if not credential or str(credential["target_id"]) != str(config.target_id) or credential["target_kind"] not in {"web", "api"}:
            raise ProfileConflict("credential_target_mismatch")
        if not credential["is_active"]:
            raise ProfileConflict("credential_revoked")
        if credential["expires_at"] and credential["expires_at"] <= datetime.now(timezone.utc):
            raise ProfileConflict("credential_expired")
        target = await conn.fetchrow("SELECT id, url FROM targets WHERE id=$1 AND is_active=true", config.target_id)
        if not target:
            raise ProfileConflict("target_unavailable")
        if config.credential_destinations != [exact_origin(target["url"])]:
            raise ProfileConflict("credential_destination_mismatch")
        previous = await conn.fetchrow(
            """SELECT revision, configuration_json FROM authenticated_profile_revisions
               WHERE profile_id=$1 ORDER BY revision DESC LIMIT 1""", config.credential_reference,
        )
        current = previous["revision"] if previous else 0
        if current != request.expected_revision:
            raise ProfileConflict("profile_changed")
        if previous and decode(previous["configuration_json"])["lifecycle_state"] == "archived":
            raise ProfileConflict("profile_archived")
        version = credential["current_version"]
        revision = current + 1
        await conn.execute(
            """INSERT INTO authenticated_profile_revisions
               (profile_id, revision, credential_version, configuration_json, configuration_digest, created_by, credential_record_version)
               VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7)""",
            config.credential_reference, revision, version,
            config.model_dump_json(), config.digest(version, credential["record_version"]), actor, credential["record_version"],
        )
        return await self.get(conn, config.credential_reference, revision=revision)

    async def get(self, conn, profile_id: UUID, *, revision: int | None = None) -> dict | None:
        row = await conn.fetchrow(
            """SELECT r.*, c.is_active AS credential_active, c.current_version,
                      c.expires_at AS credential_expires_at, c.record_version AS current_record_version,
                      t.is_active AS target_active, t.url AS current_target_url,
                      head.revision AS current_profile_revision,
                      head.configuration_json->>'lifecycle_state' AS current_lifecycle_state
               FROM authenticated_profile_revisions r
               JOIN credential_profiles c ON c.id=r.profile_id
               JOIN targets t ON t.id=c.target_id
               JOIN LATERAL (SELECT revision, configuration_json FROM authenticated_profile_revisions
                             WHERE profile_id=r.profile_id ORDER BY revision DESC LIMIT 1) head ON true
               WHERE r.profile_id=$1 AND ($2::integer IS NULL OR r.revision=$2)
               ORDER BY r.revision DESC LIMIT 1""", profile_id, revision,
        )
        if not row:
            return None
        result = dict(row)
        result["configuration"] = ProfileConfiguration.model_validate(decode(result.pop("configuration_json"))).model_dump(mode="json")
        latest = await conn.fetchrow(
            """SELECT record_json FROM authentication_validations
               WHERE profile_id=$1 AND revision=$2
               ORDER BY checked_at DESC, (record_json->>'state' = 'valid') ASC, id DESC LIMIT 1""",
            profile_id, row["revision"],
        )
        result["validation"] = ValidationRecord.model_validate(decode(latest["record_json"])).model_dump(mode="json") if latest else None
        result["last_successful_validation_at"] = await conn.fetchval(
            """SELECT MAX(checked_at) FROM authentication_validations
               WHERE profile_id=$1 AND revision=$2 AND record_json->>'state'='valid'""", profile_id, row["revision"])
        return result

    async def list(self, conn, target_id: UUID) -> list[dict]:
        rows = await conn.fetch(
            """SELECT DISTINCT r.profile_id FROM authenticated_profile_revisions r
               JOIN credential_profiles c ON c.id=r.profile_id WHERE c.target_id=$1
               ORDER BY r.profile_id LIMIT 100""", target_id,
        )
        return [await self.get(conn, row["profile_id"]) for row in rows]

    async def record(self, conn, observation: ValidationRecord) -> ValidationRecord:
        """Lock/recheck on completion; an in-flight response cannot defeat revocation."""
        credential = await conn.fetchrow(
            "SELECT * FROM credential_profiles WHERE id=$1 FOR UPDATE", observation.profile_id,
        )
        current = await self.get(conn, observation.profile_id)
        if not credential or not current:
            raise ProfileConflict("credential_unavailable")
        reason, state = None, "unknown"
        if not credential["is_active"]:
            reason, state = "credential_revoked", "revoked"
        elif credential["expires_at"] and credential["expires_at"] <= datetime.now(timezone.utc):
            reason, state = "credential_expired", "expired"
        elif (credential["current_version"] != observation.credential_version or
              credential["record_version"] != observation.credential_record_version):
            reason = "credential_changed"
        elif current["revision"] != observation.revision or current["configuration_digest"] != observation.configuration_digest:
            reason = "profile_changed"
        elif current["configuration"]["lifecycle_state"] in {"disabled", "archived"}:
            reason, state = "profile_disabled", "revoked"
        if reason:
            observation = ValidationRecord.model_validate({
                **observation.model_dump(), "state": state, "reason_code": reason,
                "identity_matched": False, "role_matched": None, "valid_until": None,
            })
        inserted = await conn.fetchrow(
            """INSERT INTO authentication_validations(id, profile_id, revision, record_json, checked_at)
               VALUES ($1,$2,$3,$4::jsonb,$5) ON CONFLICT (id) DO NOTHING RETURNING id""",
            observation.validation_id, observation.profile_id, observation.revision,
            observation.model_dump_json(), observation.checked_at,
        )
        if not inserted:
            existing = await conn.fetchrow("SELECT record_json FROM authentication_validations WHERE id=$1", observation.validation_id)
            if ValidationRecord.model_validate(decode(existing["record_json"])) != observation:
                raise ProfileConflict("validation_id_conflict")
        return observation

    async def history(self, conn, profile_id: UUID, *, limit: int = 20, before: UUID | None = None):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ProfileConflict("invalid_history_limit")
        before_time = None
        if before:
            before_time = await conn.fetchval("SELECT checked_at FROM authentication_validations WHERE id=$1 AND profile_id=$2", before, profile_id)
            if before_time is None:
                raise ProfileConflict("invalid_history_cursor")
        rows = await conn.fetch("""SELECT record_json FROM authentication_validations
            WHERE profile_id=$1 AND ($2::timestamptz IS NULL OR (checked_at,id)<($2,$3::uuid))
            ORDER BY checked_at DESC, id DESC LIMIT $4""", profile_id, before_time, before, limit + 1)
        records = [ValidationRecord.model_validate(decode(row["record_json"])).model_dump(mode="json") for row in rows[:limit]]
        return {"records": records, "next_cursor": records[-1]["validation_id"] if len(rows) > limit else None,
                "secret_values_visible": False}
