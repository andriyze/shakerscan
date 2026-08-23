"""Durable scheduler index for immutable canonical Scan action plans."""

from __future__ import annotations

import json
from typing import Any, Mapping, Protocol
import uuid

try:
    from runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityRegistry
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityRegistry

from .action_plan import ScanActionPlan, ScanActionPlanError
from .continuation import (
    ScanContinuationAllocation,
    ScanContinuationError,
)


MIGRATION_NAME = "v2_scan_capability_actions_v1"
ACTION_LEASE_MIGRATION_NAME = "v2_scan_action_leases_v1"
ACTION_CONTINUATION_MIGRATION_NAME = "v2_scan_action_continuations_v1"
SCAN_ACTION_SCHEMA_SQL = r"""
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_action_plan_json JSONB;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_action_plan_digest TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_action_plan_schema TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_continuation_allocation_json JSONB;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_continuation_allocation_digest TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_continuation_applied_at TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS scan_capability_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    action_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 512),
    capability_name TEXT NOT NULL,
    adapter_name TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    output_schema TEXT NOT NULL,
    action_digest CHAR(64) NOT NULL CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    execution_plan_digest CHAR(64) NOT NULL CHECK (execution_plan_digest ~ '^[0-9a-f]{64}$'),
    target_binding_digest CHAR(64) NOT NULL CHECK (target_binding_digest ~ '^[0-9a-f]{64}$'),
    input_binding_digest CHAR(64) NOT NULL CHECK (input_binding_digest ~ '^[0-9a-f]{64}$'),
    requested_budget JSONB NOT NULL CHECK (jsonb_typeof(requested_budget) = 'object'),
    placement_json JSONB NOT NULL CHECK (jsonb_typeof(placement_json) = 'object'),
    dependencies_json JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(dependencies_json) = 'array'
    ),
    required BOOLEAN NOT NULL,
    supporting BOOLEAN NOT NULL,
    status TEXT NOT NULL DEFAULT 'planned' CHECK (status IN (
        'planned','leased','running','success','partial','skipped','blocked',
        'failed','cancelled','timed_out'
    )),
    reason_code TEXT,
    reservation_id TEXT,
    receipt_id TEXT,
    receipt_hash CHAR(64),
    observation_manifest_id UUID,
    result_digest CHAR(64),
    result_json JSONB,
    receipt_json JSONB,
    backend_name TEXT,
    worker_id TEXT,
    lease_id UUID,
    lease_token_hash CHAR(64),
    lease_expires_at TIMESTAMPTZ,
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT scan_capability_actions_action_unique UNIQUE (scan_id, action_id),
    CONSTRAINT scan_capability_actions_ordinal_unique UNIQUE (scan_id, ordinal),
    CONSTRAINT scan_capability_actions_terminal_result_check CHECK (
        status NOT IN ('success','partial','failed','timed_out')
        OR (receipt_hash ~ '^[0-9a-f]{64}$' AND result_digest ~ '^[0-9a-f]{64}$')
    )
);
CREATE INDEX IF NOT EXISTS idx_scan_capability_actions_scan_status
    ON scan_capability_actions(scan_id, status, ordinal);
ALTER TABLE scan_capability_actions ADD COLUMN IF NOT EXISTS result_json JSONB;
ALTER TABLE scan_capability_actions ADD COLUMN IF NOT EXISTS receipt_json JSONB;
ALTER TABLE scan_capability_actions ADD COLUMN IF NOT EXISTS backend_name TEXT;
ALTER TABLE scan_capability_actions ADD COLUMN IF NOT EXISTS worker_id TEXT;
ALTER TABLE scan_capability_actions ADD COLUMN IF NOT EXISTS lease_id UUID;
ALTER TABLE scan_capability_actions ADD COLUMN IF NOT EXISTS lease_token_hash CHAR(64);
ALTER TABLE scan_capability_actions ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_scan_capability_actions_lease_expiry
    ON scan_capability_actions(lease_expires_at)
    WHERE status IN ('leased','running');
CREATE TABLE IF NOT EXISTS scan_action_plan_revisions (
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    plan_digest CHAR(64) NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
    parent_plan_digest CHAR(64),
    continuation_allocation_digest CHAR(64),
    plan_json JSONB NOT NULL CHECK (jsonb_typeof(plan_json) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scan_id, revision),
    UNIQUE (scan_id, plan_digest)
);
CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_capability_actions_v1')
ON CONFLICT (name) DO NOTHING;
INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_action_leases_v1')
ON CONFLICT (name) DO NOTHING;
INSERT INTO app_schema_migrations(name)
VALUES ('v2_scan_action_continuations_v1')
ON CONFLICT (name) DO NOTHING;
"""


_PERSIST_PLAN_SQL = r"""
UPDATE scans
SET scan_action_plan_json=$4::jsonb,
    scan_action_plan_digest=$2,
    scan_action_plan_schema=$3
WHERE id=$1
  AND (scan_action_plan_digest IS NULL OR scan_action_plan_digest=$2)
RETURNING id, scan_action_plan_digest
"""


_PERSIST_ACTION_SQL = r"""
INSERT INTO scan_capability_actions (
    scan_id, action_id, stage, ordinal, capability_name,
    adapter_name, adapter_version, output_schema,
    action_digest, execution_plan_digest, target_binding_digest,
    input_binding_digest, requested_budget, placement_json,
    dependencies_json, required, supporting, status, reason_code
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
    $13::jsonb,$14::jsonb,$15::jsonb,$16,$17,$18,$19
)
ON CONFLICT (scan_id, action_id) DO UPDATE SET
    updated_at=scan_capability_actions.updated_at
WHERE scan_capability_actions.action_digest=EXCLUDED.action_digest
  AND scan_capability_actions.ordinal=EXCLUDED.ordinal
  AND scan_capability_actions.execution_plan_digest=EXCLUDED.execution_plan_digest
  AND scan_capability_actions.target_binding_digest=EXCLUDED.target_binding_digest
RETURNING id, action_id, action_digest, ordinal, status
"""


_PERSIST_CONTINUATION_SQL = r"""
UPDATE scans
SET scan_continuation_allocation_json=$3::jsonb,
    scan_continuation_allocation_digest=$2
WHERE id=$1
  AND scan_action_plan_digest=$4
  AND (
      scan_continuation_allocation_digest IS NULL
      OR scan_continuation_allocation_digest=$2
  )
RETURNING id, scan_continuation_allocation_digest
"""


_AMEND_PLAN_SQL = r"""
UPDATE scans
SET scan_action_plan_json=$5::jsonb,
    scan_action_plan_digest=$4,
    scan_action_plan_schema=$6,
    scan_continuation_applied_at=NOW()
WHERE id=$1
  AND scan_action_plan_digest=$2
  AND scan_continuation_allocation_digest=$3
  AND scan_continuation_applied_at IS NULL
  AND status NOT IN ('cancelled','cancelling')
RETURNING id, scan_action_plan_digest
"""


class ScanActionStoreError(RuntimeError):
    """Persisted scheduler state conflicts with immutable Scan authority."""


class ScanActionDatabase(Protocol):
    async def execute(self, query: str, *args: Any) -> Any: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetch(self, query: str, *args: Any) -> Any: ...
    def transaction(self) -> Any: ...


def _json_object(value: Any, *, name: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ScanActionStoreError(f"{name} is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise ScanActionStoreError(f"{name} must be an object")
    return dict(value)


class PostgresScanActionStore:
    def __init__(self, registry: CapabilityRegistry = CAPABILITY_REGISTRY) -> None:
        self._registry = registry

    async def ensure_schema(self, conn: ScanActionDatabase) -> None:
        await conn.execute(SCAN_ACTION_SCHEMA_SQL)

    async def persist_plan(
        self,
        conn: ScanActionDatabase,
        *,
        plan: ScanActionPlan,
    ) -> tuple[Mapping[str, Any], ...]:
        """Persist the plan header and complete action index atomically.

        asyncpg turns this into a savepoint when the caller already owns the
        wider Scan-admission transaction.
        """
        async with conn.transaction():
            return await self._persist_plan_rows(conn, plan=plan)

    async def _persist_plan_rows(
        self,
        conn: ScanActionDatabase,
        *,
        plan: ScanActionPlan,
    ) -> tuple[Mapping[str, Any], ...]:
        plan_json = json.dumps(
            plan.canonical_dict(), sort_keys=True, separators=(",", ":"),
        )
        plan_row = await conn.fetchrow(
            _PERSIST_PLAN_SQL,
            uuid.UUID(plan.scan_id),
            plan.plan_digest,
            plan.schema_version,
            plan_json,
        )
        if plan_row is None:
            raise ScanActionStoreError(
                "Scan action plan conflicts with existing immutable authority"
            )
        stored: list[Mapping[str, Any]] = []
        for action in plan.actions:
            specification = self._registry.require(action.capability_name)
            row = await conn.fetchrow(
                _PERSIST_ACTION_SQL,
                uuid.UUID(plan.scan_id),
                action.action_id,
                action.stage,
                action.ordinal,
                action.capability_name,
                specification.adapter,
                specification.adapter_version,
                action.output_schema,
                action.action_digest,
                plan.execution_plan_digest,
                plan.target_binding_digest,
                action.input_binding_digest,
                json.dumps(dict(action.requested_budget), sort_keys=True, separators=(",", ":")),
                json.dumps(action.canonical_dict()["placement"], sort_keys=True, separators=(",", ":")),
                json.dumps(list(action.dependencies), separators=(",", ":")),
                action.required,
                action.supporting,
                action.admission_status,
                action.reason_code,
            )
            if row is None:
                raise ScanActionStoreError(
                    f"Scan action {action.action_id} conflicts with immutable authority"
                )
            stored.append(row)
        return tuple(stored)

    async def persist_continuation_allocation(
        self,
        conn: ScanActionDatabase,
        *,
        allocation: ScanContinuationAllocation,
        parent_plan: ScanActionPlan,
    ) -> Mapping[str, Any]:
        """Freeze the only residual budget authority before discovery runs."""
        if (
            allocation.scan_id != parent_plan.scan_id
            or allocation.parent_plan_digest != parent_plan.plan_digest
            or allocation.execution_plan_digest != parent_plan.execution_plan_digest
            or allocation.target_binding_digest != parent_plan.target_binding_digest
        ):
            raise ScanActionStoreError(
                "continuation allocation differs from its parent plan"
            )
        allocation_json = json.dumps(
            allocation.canonical_dict(), sort_keys=True, separators=(",", ":"),
        )
        row = await conn.fetchrow(
            _PERSIST_CONTINUATION_SQL,
            uuid.UUID(allocation.scan_id),
            allocation.allocation_digest,
            allocation_json,
            parent_plan.plan_digest,
        )
        if row is None:
            raise ScanActionStoreError(
                "Scan continuation allocation conflicts with persisted authority"
            )
        await conn.execute(
            """
            INSERT INTO scan_action_plan_revisions (
                scan_id, revision, plan_digest, parent_plan_digest,
                continuation_allocation_digest, plan_json
            ) VALUES ($1,0,$2,NULL,$3,$4::jsonb)
            ON CONFLICT (scan_id, plan_digest) DO NOTHING
            """,
            uuid.UUID(allocation.scan_id),
            parent_plan.plan_digest,
            allocation.allocation_digest,
            json.dumps(
                parent_plan.canonical_dict(),
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
        return row

    async def load_continuation_allocation(
        self,
        conn: ScanActionDatabase,
        *,
        scan_id: str,
    ) -> ScanContinuationAllocation | None:
        try:
            normalized_scan_id = uuid.UUID(str(scan_id))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ScanActionStoreError("scan_id is invalid") from exc
        row = await conn.fetchrow(
            """
            SELECT scan_continuation_allocation_json,
                   scan_continuation_allocation_digest
            FROM scans WHERE id=$1
            """,
            normalized_scan_id,
        )
        if row is None or row.get("scan_continuation_allocation_json") is None:
            return None
        try:
            allocation = ScanContinuationAllocation.from_dict(_json_object(
                row["scan_continuation_allocation_json"],
                name="scan_continuation_allocation_json",
            ))
        except ScanContinuationError as exc:
            raise ScanActionStoreError(
                f"stored Scan continuation allocation is invalid: {exc}"
            ) from exc
        if str(row.get("scan_continuation_allocation_digest") or "") != (
            allocation.allocation_digest
        ):
            raise ScanActionStoreError(
                "stored Scan continuation metadata is inconsistent"
            )
        return allocation

    async def amend_plan(
        self,
        conn: ScanActionDatabase,
        *,
        parent_plan: ScanActionPlan,
        amended_plan: ScanActionPlan,
        allocation: ScanContinuationAllocation,
    ) -> tuple[Mapping[str, Any], ...]:
        """Apply one append-only continuation under compare-and-swap authority."""
        if (
            parent_plan.scan_id != amended_plan.scan_id
            or allocation.scan_id != amended_plan.scan_id
            or allocation.parent_plan_digest != parent_plan.plan_digest
            or amended_plan.execution_plan_digest != allocation.execution_plan_digest
            or amended_plan.target_binding_digest != allocation.target_binding_digest
            or tuple(amended_plan.actions[:len(parent_plan.actions)])
            != parent_plan.actions
        ):
            raise ScanActionStoreError(
                "amended Scan plan does not preserve its immutable parent prefix"
            )
        plan_json = json.dumps(
            amended_plan.canonical_dict(), sort_keys=True, separators=(",", ":"),
        )
        row = await conn.fetchrow(
            _AMEND_PLAN_SQL,
            uuid.UUID(amended_plan.scan_id),
            parent_plan.plan_digest,
            allocation.allocation_digest,
            amended_plan.plan_digest,
            plan_json,
            amended_plan.schema_version,
        )
        if row is None:
            current = await conn.fetchrow(
                """
                SELECT scan_action_plan_digest,
                       scan_continuation_allocation_digest,
                       scan_continuation_applied_at
                FROM scans WHERE id=$1
                """,
                uuid.UUID(amended_plan.scan_id),
            )
            if (
                current is None
                or str(current.get("scan_action_plan_digest") or "")
                != amended_plan.plan_digest
                or str(current.get("scan_continuation_allocation_digest") or "")
                != allocation.allocation_digest
                or current.get("scan_continuation_applied_at") is None
            ):
                raise ScanActionStoreError(
                    "Scan continuation conflicts with persisted plan authority"
                )

        stored: list[Mapping[str, Any]] = []
        for action in amended_plan.actions:
            specification = self._registry.require(action.capability_name)
            action_row = await conn.fetchrow(
                _PERSIST_ACTION_SQL,
                uuid.UUID(amended_plan.scan_id),
                action.action_id,
                action.stage,
                action.ordinal,
                action.capability_name,
                specification.adapter,
                specification.adapter_version,
                action.output_schema,
                action.action_digest,
                amended_plan.execution_plan_digest,
                amended_plan.target_binding_digest,
                action.input_binding_digest,
                json.dumps(dict(action.requested_budget), sort_keys=True, separators=(",", ":")),
                json.dumps(action.canonical_dict()["placement"], sort_keys=True, separators=(",", ":")),
                json.dumps(list(action.dependencies), separators=(",", ":")),
                action.required,
                action.supporting,
                action.admission_status,
                action.reason_code,
            )
            if action_row is None:
                raise ScanActionStoreError(
                    f"continued action {action.action_id} conflicts with immutable authority"
                )
            stored.append(action_row)
        await conn.execute(
            """
            INSERT INTO scan_action_plan_revisions (
                scan_id, revision, plan_digest, parent_plan_digest,
                continuation_allocation_digest, plan_json
            ) VALUES ($1,1,$2,$3,$4,$5::jsonb)
            ON CONFLICT (scan_id, plan_digest) DO NOTHING
            """,
            uuid.UUID(amended_plan.scan_id),
            amended_plan.plan_digest,
            parent_plan.plan_digest,
            allocation.allocation_digest,
            plan_json,
        )
        return tuple(stored)

    async def load_plan(
        self,
        conn: ScanActionDatabase,
        *,
        scan_id: str,
    ) -> ScanActionPlan | None:
        try:
            normalized_scan_id = uuid.UUID(str(scan_id))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ScanActionStoreError("scan_id is invalid") from exc
        row = await conn.fetchrow(
            """SELECT scan_action_plan_json, scan_action_plan_digest,
                      scan_action_plan_schema
                 FROM scans WHERE id=$1""",
            normalized_scan_id,
        )
        if row is None or row.get("scan_action_plan_json") is None:
            return None
        try:
            plan = ScanActionPlan.from_dict(_json_object(
                row["scan_action_plan_json"], name="scan_action_plan_json",
            ))
        except ScanActionPlanError as exc:
            raise ScanActionStoreError(f"stored Scan action plan is invalid: {exc}") from exc
        if (
            str(row.get("scan_action_plan_digest") or "") != plan.plan_digest
            or str(row.get("scan_action_plan_schema") or "") != plan.schema_version
        ):
            raise ScanActionStoreError("stored Scan action-plan metadata is inconsistent")
        action_rows = await conn.fetch(
            """SELECT action_id, ordinal, action_digest, execution_plan_digest,
                      target_binding_digest, status
                 FROM scan_capability_actions
                WHERE scan_id=$1 ORDER BY ordinal""",
            normalized_scan_id,
        )
        if len(action_rows) != len(plan.actions):
            raise ScanActionStoreError("stored Scan action index is incomplete")
        for action, action_row in zip(plan.actions, action_rows, strict=True):
            if (
                str(action_row.get("action_id") or "") != action.action_id
                or int(action_row.get("ordinal", -1)) != action.ordinal
                or str(action_row.get("action_digest") or "") != action.action_digest
                or str(action_row.get("execution_plan_digest") or "")
                != plan.execution_plan_digest
                or str(action_row.get("target_binding_digest") or "")
                != plan.target_binding_digest
            ):
                raise ScanActionStoreError("stored Scan action index conflicts with its plan")
        return plan
