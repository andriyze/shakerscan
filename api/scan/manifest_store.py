"""Durable private storage for canonical endpoint/candidate/request/template manifests."""

from __future__ import annotations

import json
from typing import Any, Mapping, Protocol
import uuid

from .work_manifests import (
    ScanWorkManifest,
    ScanWorkManifestError,
    ScanWorkManifestKind,
    ScanWorkManifestReference,
)


MIGRATION_NAME = "v2_scan_work_manifests_v1"
SCAN_WORK_MANIFEST_SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS scan_work_manifests (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('endpoint','candidate','request','template')),
    schema_version TEXT NOT NULL,
    content_schema TEXT NOT NULL,
    target_binding_digest CHAR(64) NOT NULL CHECK (
        target_binding_digest ~ '^[0-9a-f]{64}$'
    ),
    source_action_ids JSONB NOT NULL CHECK (jsonb_typeof(source_action_ids)='array'),
    status TEXT NOT NULL CHECK (status IN ('complete','partial','cancelled')),
    reason_code TEXT,
    entry_count INTEGER NOT NULL CHECK (entry_count >= 0 AND entry_count <= 100000),
    manifest_digest CHAR(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    content_json JSONB NOT NULL CHECK (jsonb_typeof(content_json)='object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT scan_work_manifest_identity_unique UNIQUE (scan_id, kind, manifest_digest),
    CONSTRAINT scan_work_manifest_reason_check CHECK (
        (status='complete' AND reason_code IS NULL)
        OR (status<>'complete' AND reason_code IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_scan_work_manifests_scan_kind
    ON scan_work_manifests(scan_id, kind, created_at DESC);
CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_work_manifests_v1')
ON CONFLICT (name) DO NOTHING;
"""


class ScanManifestStoreError(RuntimeError):
    """Durable manifest content conflicts with immutable Scan authority."""


class ScanManifestDatabase(Protocol):
    async def execute(self, query: str, *args: Any) -> Any: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetch(self, query: str, *args: Any) -> Any: ...


def _json_object(value: Any, *, name: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ScanManifestStoreError(f"{name} is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise ScanManifestStoreError(f"{name} must be an object")
    return dict(value)


class PostgresScanManifestStore:
    async def ensure_schema(self, conn: ScanManifestDatabase) -> None:
        await conn.execute(SCAN_WORK_MANIFEST_SCHEMA_SQL)

    async def persist(
        self,
        conn: ScanManifestDatabase,
        *,
        manifest: ScanWorkManifest,
    ) -> ScanWorkManifestReference:
        content = json.dumps(
            manifest.canonical_dict(), sort_keys=True, separators=(",", ":"),
        )
        row = await conn.fetchrow(
            """INSERT INTO scan_work_manifests (
                   id, scan_id, kind, schema_version, content_schema,
                   target_binding_digest, source_action_ids, status, reason_code,
                   entry_count, manifest_digest, content_json
               ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12::jsonb)
               ON CONFLICT (id) DO UPDATE SET
                   manifest_digest=scan_work_manifests.manifest_digest
               WHERE scan_work_manifests.scan_id=EXCLUDED.scan_id
                 AND scan_work_manifests.kind=EXCLUDED.kind
                 AND scan_work_manifests.target_binding_digest=EXCLUDED.target_binding_digest
                 AND scan_work_manifests.manifest_digest=EXCLUDED.manifest_digest
                 AND scan_work_manifests.content_json=EXCLUDED.content_json
               RETURNING content_json""",
            uuid.UUID(str(manifest.manifest_id)),
            uuid.UUID(manifest.scan_id),
            manifest.kind.value,
            manifest.schema_version,
            manifest.content_schema,
            manifest.target_binding_digest,
            json.dumps(list(manifest.source_action_ids), separators=(",", ":")),
            manifest.status,
            manifest.reason_code,
            len(manifest.entries),
            manifest.manifest_digest,
            content,
        )
        if row is None:
            raise ScanManifestStoreError("work manifest conflicts with durable content")
        try:
            stored = ScanWorkManifest.from_dict(_json_object(
                row["content_json"], name="stored work manifest",
            ))
        except ScanWorkManifestError as exc:
            raise ScanManifestStoreError("stored work manifest is invalid") from exc
        if stored != manifest:
            raise ScanManifestStoreError("stored work manifest differs from submitted content")
        return stored.reference()

    async def load(
        self,
        conn: ScanManifestDatabase,
        *,
        manifest_id: str,
        scan_id: str,
        expected_kind: ScanWorkManifestKind | str | None = None,
        expected_digest: str | None = None,
        expected_target_binding_digest: str | None = None,
    ) -> ScanWorkManifest | None:
        try:
            parsed_manifest_id = uuid.UUID(str(manifest_id))
            parsed_scan_id = uuid.UUID(str(scan_id))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ScanManifestStoreError("manifest or Scan ID is invalid") from exc
        row = await conn.fetchrow(
            """SELECT content_json FROM scan_work_manifests
                WHERE id=$1 AND scan_id=$2""",
            parsed_manifest_id,
            parsed_scan_id,
        )
        if row is None:
            return None
        try:
            manifest = ScanWorkManifest.from_dict(_json_object(
                row["content_json"], name="stored work manifest",
            ))
        except ScanWorkManifestError as exc:
            raise ScanManifestStoreError("stored work manifest is invalid") from exc
        kind = (
            expected_kind
            if isinstance(expected_kind, ScanWorkManifestKind)
            else ScanWorkManifestKind(str(expected_kind))
            if expected_kind is not None else None
        )
        if kind is not None and manifest.kind is not kind:
            raise ScanManifestStoreError("stored work manifest kind differs from authority")
        if expected_digest is not None and manifest.manifest_digest != expected_digest:
            raise ScanManifestStoreError("stored work manifest digest differs from authority")
        if (
            expected_target_binding_digest is not None
            and manifest.target_binding_digest != expected_target_binding_digest
        ):
            raise ScanManifestStoreError(
                "stored work manifest target binding differs from authority"
            )
        return manifest

    async def list_references(
        self,
        conn: ScanManifestDatabase,
        *,
        scan_id: str,
        kind: ScanWorkManifestKind | str | None = None,
    ) -> tuple[ScanWorkManifestReference, ...]:
        try:
            parsed_scan_id = uuid.UUID(str(scan_id))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ScanManifestStoreError("Scan ID is invalid") from exc
        parsed_kind = (
            kind if isinstance(kind, ScanWorkManifestKind)
            else ScanWorkManifestKind(str(kind)) if kind is not None else None
        )
        rows = await conn.fetch(
            """SELECT content_json FROM scan_work_manifests
                WHERE scan_id=$1 AND ($2::text IS NULL OR kind=$2)
                ORDER BY created_at, id""",
            parsed_scan_id,
            parsed_kind.value if parsed_kind is not None else None,
        )
        references: list[ScanWorkManifestReference] = []
        for row in rows:
            try:
                manifest = ScanWorkManifest.from_dict(_json_object(
                    row["content_json"], name="stored work manifest",
                ))
            except ScanWorkManifestError as exc:
                raise ScanManifestStoreError("stored work manifest is invalid") from exc
            references.append(manifest.reference())
        return tuple(references)
