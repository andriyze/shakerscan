"""Durable private observation objects behind content-free capability references."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Protocol, Sequence
import uuid

from .json_fields import strip_null_bytes
from .observation_manifests import (
    ObservationManifest,
    ObservationManifestError,
    ObservationManifestReference,
    validate_observation_manifest_reference,
)


MIGRATION_NAME = "v2_scan_observation_manifests_v1"
SCAN_OBSERVATION_MANIFEST_SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS scan_observation_manifests (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    action_id TEXT NOT NULL,
    capability_name TEXT NOT NULL,
    output_schema TEXT NOT NULL,
    manifest_digest CHAR(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    content_sha256 CHAR(64) NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    observation_count INTEGER NOT NULL CHECK (
        observation_count >= 0 AND observation_count <= 100000
    ),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= 67108864),
    object_key TEXT NOT NULL,
    manifest_json JSONB NOT NULL CHECK (jsonb_typeof(manifest_json)='object'),
    observations_json JSONB NOT NULL CHECK (jsonb_typeof(observations_json)='array'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT scan_observation_identity_unique UNIQUE (
        scan_id, action_id, content_sha256
    )
);
CREATE INDEX IF NOT EXISTS idx_scan_observation_manifests_scan_action
    ON scan_observation_manifests(scan_id, action_id, created_at DESC);
CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_observation_manifests_v1')
ON CONFLICT (name) DO NOTHING;
"""


class ObservationStoreError(RuntimeError):
    """Observation content conflicts with its immutable manifest reference."""


class ObservationDatabase(Protocol):
    async def execute(self, query: str, *args: Any) -> Any: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...


def _json_value(value: Any, *, name: str) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise ObservationStoreError(f"{name} is invalid JSON") from exc
    return value


def _canonical_observations(
    observations: Sequence[Mapping[str, Any]],
) -> tuple[tuple[dict[str, Any], ...], bytes]:
    if len(observations) > 100_000:
        raise ObservationStoreError("observation count exceeds its durable ceiling")
    normalized: list[dict[str, Any]] = []
    for item in observations:
        if not isinstance(item, Mapping):
            raise ObservationStoreError("capability observation must be an object")
        try:
            # Round-trip through strict JSON to detach mutable adapter objects,
            # reject non-finite values, and preserve only portable evidence.
            # NUL is stripped here because PostgreSQL accepts neither text nor
            # jsonb containing it: a capability that captured binary content --
            # a probe reading a .pyc or .bak from an exposed directory -- failed
            # its whole action on the write and discarded every observation it
            # had already gathered, not just the one carrying the byte.
            encoded = json.dumps(
                strip_null_bytes(dict(item)), sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            )
            decoded = json.loads(encoded)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ObservationStoreError("capability observation is not canonical JSON") from exc
        if not isinstance(decoded, dict):
            raise ObservationStoreError("capability observation must remain an object")
        normalized.append(decoded)
    content = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    if len(content) > 64 * 1024 * 1024:
        raise ObservationStoreError("observation content exceeds its durable byte ceiling")
    return tuple(normalized), content


class PostgresObservationManifestStore:
    async def ensure_schema(self, conn: ObservationDatabase) -> None:
        await conn.execute(SCAN_OBSERVATION_MANIFEST_SCHEMA_SQL)

    async def persist(
        self,
        conn: ObservationDatabase,
        *,
        scan_id: str,
        action_id: str,
        capability_name: str,
        output_schema: str,
        observations: Sequence[Mapping[str, Any]],
    ) -> ObservationManifestReference:
        try:
            normalized_scan_id = str(uuid.UUID(str(scan_id)))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ObservationStoreError("Scan ID is invalid") from exc
        normalized, content = _canonical_observations(observations)
        content_sha256 = hashlib.sha256(content).hexdigest()
        manifest_id = str(uuid.uuid5(
            uuid.UUID(normalized_scan_id),
            f"observation:{action_id}:{content_sha256}",
        ))
        manifest = ObservationManifest(
            manifest_id=manifest_id,
            owner_id=normalized_scan_id,
            action_id=action_id,
            capability_name=capability_name,
            output_schema=output_schema,
            observation_count=len(normalized),
            content_sha256=content_sha256,
            size_bytes=len(content),
            object_key=f"scan-observations/{manifest_id}.json",
        )
        manifest_json = json.dumps(
            manifest.canonical_dict(), sort_keys=True, separators=(",", ":"),
        )
        observations_json = content.decode("utf-8")
        row = await conn.fetchrow(
            """INSERT INTO scan_observation_manifests (
                   id, scan_id, action_id, capability_name, output_schema,
                   manifest_digest, content_sha256, observation_count,
                   size_bytes, object_key, manifest_json, observations_json
               ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb)
               ON CONFLICT (id) DO UPDATE SET
                   manifest_digest=scan_observation_manifests.manifest_digest
               WHERE scan_observation_manifests.scan_id=EXCLUDED.scan_id
                 AND scan_observation_manifests.action_id=EXCLUDED.action_id
                 AND scan_observation_manifests.manifest_digest=EXCLUDED.manifest_digest
                 AND scan_observation_manifests.content_sha256=EXCLUDED.content_sha256
                 AND scan_observation_manifests.observations_json=EXCLUDED.observations_json
               RETURNING manifest_json""",
            uuid.UUID(manifest_id),
            uuid.UUID(normalized_scan_id),
            action_id,
            capability_name,
            output_schema,
            manifest.manifest_digest,
            content_sha256,
            len(normalized),
            len(content),
            manifest.object_key,
            manifest_json,
            observations_json,
        )
        if row is None:
            raise ObservationStoreError("observation manifest conflicts with durable content")
        try:
            stored = ObservationManifest.from_dict(
                _json_value(row["manifest_json"], name="stored observation manifest")
            )
        except (ObservationManifestError, TypeError) as exc:
            raise ObservationStoreError("stored observation manifest is invalid") from exc
        reference = stored.reference()
        validate_observation_manifest_reference(reference, manifest)
        return reference

    async def load(
        self,
        conn: ObservationDatabase,
        *,
        reference: ObservationManifestReference,
        scan_id: str,
        action_id: str,
    ) -> tuple[dict[str, Any], ...] | None:
        try:
            parsed_scan_id = uuid.UUID(str(scan_id))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ObservationStoreError("Scan ID is invalid") from exc
        row = await conn.fetchrow(
            """SELECT manifest_json, observations_json
                 FROM scan_observation_manifests
                WHERE id=$1 AND scan_id=$2 AND action_id=$3""",
            uuid.UUID(reference.manifest_id),
            parsed_scan_id,
            action_id,
        )
        if row is None:
            return None
        try:
            manifest = ObservationManifest.from_dict(
                _json_value(row["manifest_json"], name="stored observation manifest")
            )
            validate_observation_manifest_reference(reference, manifest)
        except (ObservationManifestError, TypeError) as exc:
            raise ObservationStoreError("stored observation manifest is invalid") from exc
        raw = _json_value(row["observations_json"], name="stored observations")
        if not isinstance(raw, list) or any(not isinstance(item, Mapping) for item in raw):
            raise ObservationStoreError("stored observations are invalid")
        normalized, content = _canonical_observations(tuple(dict(item) for item in raw))
        if (
            hashlib.sha256(content).hexdigest() != manifest.content_sha256
            or len(content) != manifest.size_bytes
            or len(normalized) != manifest.observation_count
        ):
            raise ObservationStoreError("stored observations differ from their manifest")
        return normalized
