"""Content-free durable checkpoints for the canonical Scan stage graph."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Protocol
import uuid

from .executor import NATIVE_SCAN_STAGES


MIGRATION_NAME = "v2_scan_stage_checkpoints_v1"
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_IDENTIFIER_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,255}$")
_STATUSES = frozenset({
    "completed", "partial", "skipped", "failed", "cancelled",
})
_ROW_KEYS = frozenset({
    "index", "name", "enabled", "status", "reason", "adapter",
    "capability_names", "output_keys", "elapsed_ms",
})


SCAN_STAGE_CHECKPOINT_SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS scan_stage_checkpoints (
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    job_id TEXT NOT NULL,
    stage_index SMALLINT NOT NULL CHECK (stage_index >= 0 AND stage_index < 32),
    stage_name TEXT NOT NULL CHECK (stage_name ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$'),
    status TEXT NOT NULL CHECK (
        status IN ('completed','partial','skipped','failed','cancelled')
    ),
    execution_plan_digest TEXT NOT NULL CHECK (
        execution_plan_digest ~ '^[0-9a-f]{64}$'
    ),
    target_binding_digest TEXT NOT NULL CHECK (
        target_binding_digest ~ '^[0-9a-f]{64}$'
    ),
    history_digest TEXT NOT NULL CHECK (history_digest ~ '^[0-9a-f]{64}$'),
    stage_row_digest TEXT NOT NULL CHECK (stage_row_digest ~ '^[0-9a-f]{64}$'),
    stage_row_json JSONB NOT NULL CHECK (
        jsonb_typeof(stage_row_json) = 'object'
        AND stage_row_json - ARRAY[
            'index','name','enabled','status','reason','adapter',
            'capability_names','output_keys','elapsed_ms'
        ]::text[] = '{}'::jsonb
    ),
    worker_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scan_id, job_id, stage_index),
    CONSTRAINT scan_stage_checkpoints_stage_unique
        UNIQUE (scan_id, job_id, stage_name)
);
CREATE INDEX IF NOT EXISTS idx_scan_stage_checkpoints_scan
    ON scan_stage_checkpoints(scan_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_stage_checkpoints_v1')
ON CONFLICT (name) DO NOTHING;
"""


_UPSERT_SQL = r"""
INSERT INTO scan_stage_checkpoints (
    scan_id, job_id, stage_index, stage_name, status,
    execution_plan_digest, target_binding_digest, history_digest,
    stage_row_digest, stage_row_json, worker_id
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)
ON CONFLICT (scan_id, job_id, stage_index) DO UPDATE SET
    status=EXCLUDED.status,
    history_digest=EXCLUDED.history_digest,
    stage_row_digest=EXCLUDED.stage_row_digest,
    stage_row_json=EXCLUDED.stage_row_json,
    worker_id=EXCLUDED.worker_id,
    updated_at=NOW()
WHERE scan_stage_checkpoints.stage_name=EXCLUDED.stage_name
  AND scan_stage_checkpoints.execution_plan_digest=EXCLUDED.execution_plan_digest
  AND scan_stage_checkpoints.target_binding_digest=EXCLUDED.target_binding_digest
RETURNING *
"""


class ScanStageCheckpointError(RuntimeError):
    """A stage checkpoint was malformed or conflicted with durable authority."""


class ScanStageCheckpointDatabase(Protocol):
    async def execute(self, query: str, *args: Any) -> Any: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetch(self, query: str, *args: Any) -> Any: ...


def _digest(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _DIGEST_RE.fullmatch(normalized):
        raise ScanStageCheckpointError(
            f"{name} must be 64 lowercase hex characters"
        )
    return normalized


def _token(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip()
    if not _TOKEN_RE.fullmatch(normalized):
        raise ScanStageCheckpointError(f"{name} is invalid")
    return normalized


def _identifier(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip()
    if not _IDENTIFIER_RE.fullmatch(normalized):
        raise ScanStageCheckpointError(f"{name} is invalid")
    return normalized


def public_stage_row(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the scheduler's public row and reject any private output value."""
    if not isinstance(value, Mapping) or set(value) != _ROW_KEYS:
        raise ScanStageCheckpointError("stage row fields are invalid")
    index = value.get("index")
    elapsed = value.get("elapsed_ms")
    if (
        isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < 32
        or isinstance(elapsed, bool) or not isinstance(elapsed, int) or elapsed < 0
    ):
        raise ScanStageCheckpointError("stage row counters are invalid")
    if not isinstance(value.get("enabled"), bool):
        raise ScanStageCheckpointError("stage row enabled flag is invalid")
    status = str(value.get("status") or "")
    if status not in _STATUSES:
        raise ScanStageCheckpointError("stage row status is invalid")
    reason = value.get("reason")
    adapter = value.get("adapter")
    if reason is not None:
        _token(reason, name="stage reason")
    if adapter is not None:
        _token(adapter, name="stage adapter")

    def tokens(field: str) -> list[str]:
        raw = value.get(field)
        if not isinstance(raw, list) or len(raw) > 64:
            raise ScanStageCheckpointError(f"stage {field} is invalid")
        result = [_token(item, name=f"stage {field} item") for item in raw]
        if len(set(result)) != len(result):
            raise ScanStageCheckpointError(f"stage {field} contains duplicates")
        return result

    return {
        "index": index,
        "name": _token(value.get("name"), name="stage name"),
        "enabled": value["enabled"],
        "status": status,
        "reason": str(reason) if reason is not None else None,
        "adapter": str(adapter) if adapter is not None else None,
        "capability_names": tokens("capability_names"),
        # Only output field names are durable. Values remain worker-private.
        "output_keys": tokens("output_keys"),
        "elapsed_ms": elapsed,
    }


def stage_row_digest(row: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        public_stage_row(row), sort_keys=True, separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _history_digest(rows: list[dict[str, Any]]) -> str:
    encoded = json.dumps(
        rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_object(value: Any, *, name: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ScanStageCheckpointError(f"{name} is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise ScanStageCheckpointError(f"{name} must be an object")
    return dict(value)


class PostgresScanStageCheckpointStore:
    async def ensure_schema(self, conn: ScanStageCheckpointDatabase) -> None:
        await conn.execute(SCAN_STAGE_CHECKPOINT_SCHEMA_SQL)

    async def persist(
        self,
        conn: ScanStageCheckpointDatabase,
        *,
        scan_id: str,
        job_id: str,
        execution_plan_digest: str,
        target_binding_digest: str,
        history_digest: str,
        stage_row: Mapping[str, Any],
        worker_id: str,
    ) -> Mapping[str, Any]:
        try:
            normalized_scan_id = uuid.UUID(str(scan_id))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ScanStageCheckpointError("scan_id is invalid") from exc
        normalized_job_id = _identifier(job_id, name="job_id")
        normalized_worker_id = _identifier(worker_id, name="worker_id")
        row = public_stage_row(stage_row)
        stored = await conn.fetchrow(
            _UPSERT_SQL,
            normalized_scan_id,
            normalized_job_id,
            row["index"],
            row["name"],
            row["status"],
            _digest(execution_plan_digest, name="execution_plan_digest"),
            _digest(target_binding_digest, name="target_binding_digest"),
            _digest(history_digest, name="history_digest"),
            stage_row_digest(row),
            json.dumps(row, sort_keys=True, separators=(",", ":")),
            normalized_worker_id,
        )
        if stored is None:
            raise ScanStageCheckpointError(
                "stage checkpoint conflicts with immutable Scan authority"
            )
        return stored

    async def load_prefix(
        self,
        conn: ScanStageCheckpointDatabase,
        *,
        scan_id: str,
        job_id: str,
    ) -> Mapping[str, Any] | None:
        """Load and verify one contiguous, digest-linked public stage prefix."""
        try:
            normalized_scan_id = uuid.UUID(str(scan_id))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ScanStageCheckpointError("scan_id is invalid") from exc
        normalized_job_id = _identifier(job_id, name="job_id")
        rows = await conn.fetch(
            """SELECT stage_index, stage_name, status,
                      execution_plan_digest, target_binding_digest,
                      history_digest, stage_row_digest, stage_row_json
               FROM scan_stage_checkpoints
               WHERE scan_id=$1 AND job_id=$2
               ORDER BY stage_index""",
            normalized_scan_id,
            normalized_job_id,
        )
        if not rows:
            return None

        public_rows: list[dict[str, Any]] = []
        plan_digest: str | None = None
        target_digest: str | None = None
        for expected_index, stored in enumerate(rows):
            stage_row = public_stage_row(
                _json_object(stored["stage_row_json"], name="stage_row_json")
            )
            stored_index = int(stored["stage_index"])
            if stored_index != expected_index or stage_row["index"] != expected_index:
                raise ScanStageCheckpointError(
                    "stage checkpoint prefix is not contiguous"
                )
            if (
                expected_index >= len(NATIVE_SCAN_STAGES)
                or stage_row["name"] != NATIVE_SCAN_STAGES[expected_index]
            ):
                raise ScanStageCheckpointError(
                    "stage checkpoint does not match the fixed Scan graph"
                )
            if str(stored["stage_name"]) != stage_row["name"]:
                raise ScanStageCheckpointError("stage checkpoint name mismatch")
            if str(stored["status"]) != stage_row["status"]:
                raise ScanStageCheckpointError("stage checkpoint status mismatch")
            if _digest(
                stored["stage_row_digest"], name="stage_row_digest"
            ) != stage_row_digest(stage_row):
                raise ScanStageCheckpointError("stage checkpoint row digest mismatch")
            row_plan = _digest(
                stored["execution_plan_digest"], name="execution_plan_digest"
            )
            row_target = _digest(
                stored["target_binding_digest"], name="target_binding_digest"
            )
            if plan_digest is None:
                plan_digest, target_digest = row_plan, row_target
            elif row_plan != plan_digest or row_target != target_digest:
                raise ScanStageCheckpointError(
                    "stage checkpoint authority changed within one prefix"
                )
            public_rows.append(stage_row)
            if _digest(
                stored["history_digest"], name="history_digest"
            ) != _history_digest(public_rows):
                raise ScanStageCheckpointError(
                    "stage checkpoint history digest mismatch"
                )

        return {
            "schema_version": "canonical-scan-stage-checkpoint/v1",
            "execution_plan_digest": plan_digest,
            "target_binding_digest": target_digest,
            "status": public_rows[-1]["status"],
            "last_stage": public_rows[-1]["name"],
            "stages": public_rows,
            "history_digest": _history_digest(public_rows),
            "content_free": True,
        }
