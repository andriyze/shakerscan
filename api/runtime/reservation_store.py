"""PostgreSQL persistence for durable Scan/Hunt budget reservations.

The state machine lives in :mod:`runtime.budget_reservations`; this module makes it
transactionally durable.  Callers are expected to hold the owning Scan/Hunt ledger row
lock while calling these methods and to persist the returned ledger snapshot in the same
transaction.  Optimistic version and state-digest checks prevent stale workers from
settling a newer lease.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from typing import Any, Mapping, Protocol

from .budget_reservations import DurableBudgetReservation
from .receipts import CapabilityReceipt


MIGRATION_NAME = "v2_budget_reservations_v2"
_ACTION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")

BUDGET_RESERVATION_SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS budget_reservations (
    id TEXT PRIMARY KEY,
    owner_kind TEXT NOT NULL CHECK (owner_kind IN ('scan','hunt')),
    owner_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    action_digest TEXT NOT NULL CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    capability_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('requested','reserved','running','committed','released','failed')
    ),
    requested_json JSONB NOT NULL CHECK (jsonb_typeof(requested_json) = 'object'),
    actual_json JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(actual_json) = 'object'),
    hold_applied BOOLEAN NOT NULL DEFAULT false,
    worker_id TEXT,
    lease_expires_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    execution_receipt_hash TEXT,
    failure_reason TEXT,
    execution_uncertain BOOLEAN NOT NULL DEFAULT false,
    version INTEGER NOT NULL CHECK (version > 0),
    state_digest TEXT NOT NULL CHECK (state_digest ~ '^[0-9a-f]{64}$'),
    state_json JSONB NOT NULL CHECK (jsonb_typeof(state_json) = 'object'),
    ledger_after_hold_json JSONB CHECK (
        ledger_after_hold_json IS NULL OR jsonb_typeof(ledger_after_hold_json) = 'object'
    ),
    ledger_after_settlement_json JSONB CHECK (
        ledger_after_settlement_json IS NULL OR jsonb_typeof(ledger_after_settlement_json) = 'object'
    ),
    receipt_json JSONB CHECK (receipt_json IS NULL OR jsonb_typeof(receipt_json) = 'object'),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT budget_reservations_action_unique UNIQUE (owner_kind, owner_id, action_id),
    CONSTRAINT budget_reservations_runtime_state_check CHECK (
        (status = 'requested' AND hold_applied = false AND worker_id IS NULL
            AND lease_expires_at IS NULL AND started_at IS NULL AND finished_at IS NULL)
        OR
        (status = 'reserved' AND hold_applied = true AND worker_id IS NULL
            AND lease_expires_at IS NOT NULL AND started_at IS NULL AND finished_at IS NULL)
        OR
        (status = 'running' AND hold_applied = true AND worker_id IS NOT NULL
            AND lease_expires_at IS NOT NULL AND started_at IS NOT NULL AND finished_at IS NULL)
        OR
        (status IN ('committed','released','failed')
            AND lease_expires_at IS NULL AND finished_at IS NOT NULL)
    ),
    CONSTRAINT budget_reservations_committed_receipt_check CHECK (
        status <> 'committed' OR execution_receipt_hash ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT budget_reservations_uncertain_check CHECK (
        execution_uncertain = false OR (status = 'failed' AND hold_applied = true)
    )
);
ALTER TABLE budget_reservations ADD COLUMN IF NOT EXISTS action_digest TEXT;
UPDATE budget_reservations
SET action_digest = repeat('0', 64)
WHERE action_digest IS NULL;
ALTER TABLE budget_reservations ALTER COLUMN action_digest SET NOT NULL;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'budget_reservations_action_digest_check'
          AND conrelid = 'budget_reservations'::regclass
    ) THEN
        ALTER TABLE budget_reservations
        ADD CONSTRAINT budget_reservations_action_digest_check
        CHECK (action_digest ~ '^[0-9a-f]{64}$');
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_budget_reservations_owner
    ON budget_reservations(owner_kind, owner_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_budget_reservations_stale
    ON budget_reservations(lease_expires_at)
    WHERE status IN ('reserved','running');
CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_budget_reservations_v1'), ('v2_budget_reservations_v2')
ON CONFLICT (name) DO NOTHING;
"""


class ReservationStoreError(RuntimeError):
    """Base class for reservation persistence failures."""


class ReservationConflict(ReservationStoreError):
    """A stale or conflicting action attempted to change a durable reservation."""


class ReservationDatabase(Protocol):
    async def execute(self, query: str, *args: Any) -> Any: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetch(self, query: str, *args: Any) -> Any: ...


def _utc(value: Any, *, name: str) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ReservationStoreError(f"{name} is not an ISO-8601 timestamp") from exc
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ReservationStoreError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _json_object(value: Any, *, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ReservationStoreError(f"{name} is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise ReservationStoreError(f"{name} must be a JSON object")
    return dict(value)


def _action_id(value: Any) -> str:
    normalized = str(value or "").strip()
    if not _ACTION_ID_RE.fullmatch(normalized):
        raise ReservationStoreError("action_id is invalid")
    return normalized


def _digest(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _DIGEST_RE.fullmatch(normalized):
        raise ReservationStoreError(f"{name} must be 64 lowercase hex characters")
    return normalized


def _record_from_state(value: Any) -> DurableBudgetReservation:
    state = _json_object(value, name="state_json")
    for key in (
        "created_at", "updated_at", "lease_expires_at", "started_at", "finished_at"
    ):
        if state.get(key) is not None:
            state[key] = _utc(state[key], name=key)
    try:
        return DurableBudgetReservation(**state)
    except (TypeError, ValueError) as exc:
        raise ReservationStoreError(f"stored reservation state is invalid: {exc}") from exc


@dataclass(frozen=True)
class StoredBudgetReservation:
    action_id: str
    action_digest: str
    record: DurableBudgetReservation
    ledger_after_hold: Mapping[str, int] | None = None
    ledger_after_settlement: Mapping[str, int] | None = None
    receipt: Mapping[str, Any] | None = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "StoredBudgetReservation":
        record = _record_from_state(row["state_json"])
        if str(row.get("id") or "") != record.reservation_id:
            raise ReservationStoreError("reservation row ID does not match state_json")
        if str(row.get("state_digest") or "") != record.state_digest:
            raise ReservationStoreError("reservation row state digest mismatch")
        return cls(
            action_id=_action_id(row["action_id"]),
            action_digest=_digest(row["action_digest"], name="action_digest"),
            record=record,
            ledger_after_hold=(
                _json_object(row.get("ledger_after_hold_json"), name="ledger_after_hold_json")
                if row.get("ledger_after_hold_json") is not None else None
            ),
            ledger_after_settlement=(
                _json_object(
                    row.get("ledger_after_settlement_json"),
                    name="ledger_after_settlement_json",
                )
                if row.get("ledger_after_settlement_json") is not None else None
            ),
            receipt=(
                _json_object(row.get("receipt_json"), name="receipt_json")
                if row.get("receipt_json") is not None else None
            ),
        )


def _state_args(
    record: DurableBudgetReservation,
    *,
    action_id: str,
    ledger_after_hold: Mapping[str, int] | None,
    ledger_after_settlement: Mapping[str, int] | None,
    receipt: Mapping[str, Any] | None,
) -> tuple[Any, ...]:
    state = record.canonical_dict()
    return (
        record.reservation_id,
        record.owner_kind,
        record.owner_id,
        _action_id(action_id),
        record.capability_name,
        record.status,
        json.dumps(dict(record.requested), sort_keys=True, separators=(",", ":")),
        json.dumps(dict(record.actual), sort_keys=True, separators=(",", ":")),
        record.hold_applied,
        record.worker_id,
        record.lease_expires_at,
        record.started_at,
        record.finished_at,
        record.execution_receipt_hash,
        record.failure_reason,
        record.execution_uncertain,
        record.version,
        record.state_digest,
        json.dumps(state, sort_keys=True, separators=(",", ":")),
        (
            json.dumps(dict(ledger_after_hold), sort_keys=True, separators=(",", ":"))
            if ledger_after_hold is not None else None
        ),
        (
            json.dumps(
                dict(ledger_after_settlement), sort_keys=True, separators=(",", ":")
            )
            if ledger_after_settlement is not None else None
        ),
        (
            json.dumps(dict(receipt), sort_keys=True, separators=(",", ":"))
            if receipt is not None else None
        ),
        record.created_at,
        record.updated_at,
    )


_INSERT_SQL = """
INSERT INTO budget_reservations (
    id, owner_kind, owner_id, action_id, capability_name, status,
    requested_json, actual_json, hold_applied, worker_id, lease_expires_at,
    started_at, finished_at, execution_receipt_hash, failure_reason,
    execution_uncertain, version, state_digest, state_json,
    ledger_after_hold_json, ledger_after_settlement_json, receipt_json,
    created_at, updated_at, action_digest
) VALUES (
    $1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10,$11,$12,$13,$14,$15,$16,
    $17,$18,$19::jsonb,$20::jsonb,$21::jsonb,$22::jsonb,$23,$24,$25
)
ON CONFLICT (owner_kind, owner_id, action_id) DO NOTHING
RETURNING *
"""

_UPDATE_SQL = """
UPDATE budget_reservations SET
    status=$6, requested_json=$7::jsonb, actual_json=$8::jsonb,
    hold_applied=$9, worker_id=$10, lease_expires_at=$11,
    started_at=$12, finished_at=$13, execution_receipt_hash=$14,
    failure_reason=$15, execution_uncertain=$16, version=$17,
    state_digest=$18, state_json=$19::jsonb,
    ledger_after_hold_json=$20::jsonb,
    ledger_after_settlement_json=$21::jsonb,
    receipt_json=$22::jsonb, updated_at=$24
WHERE id=$1 AND version=$26 AND state_digest=$27
  AND owner_kind=$2 AND owner_id=$3 AND action_id=$4
  AND capability_name=$5 AND created_at=$23 AND action_digest=$25
RETURNING *
"""


class PostgresBudgetReservationStore:
    """Versioned persistence used inside the caller's existing DB transaction."""

    async def ensure_schema(self, conn: ReservationDatabase) -> None:
        await conn.execute(BUDGET_RESERVATION_SCHEMA_SQL)

    async def load(
        self,
        conn: ReservationDatabase,
        reservation_id: str,
        *,
        for_update: bool = False,
    ) -> StoredBudgetReservation | None:
        suffix = " FOR UPDATE" if for_update else ""
        row = await conn.fetchrow(
            "SELECT * FROM budget_reservations WHERE id=$1" + suffix,
            str(reservation_id),
        )
        return StoredBudgetReservation.from_row(row) if row else None

    async def load_by_action(
        self,
        conn: ReservationDatabase,
        *,
        owner_kind: str,
        owner_id: str,
        action_id: str,
        for_update: bool = False,
    ) -> StoredBudgetReservation | None:
        suffix = " FOR UPDATE" if for_update else ""
        row = await conn.fetchrow(
            """SELECT * FROM budget_reservations
               WHERE owner_kind=$1 AND owner_id=$2 AND action_id=$3""" + suffix,
            str(owner_kind),
            str(owner_id),
            _action_id(action_id),
        )
        return StoredBudgetReservation.from_row(row) if row else None

    async def create_requested(
        self,
        conn: ReservationDatabase,
        *,
        action_id: str,
        action_digest: str,
        record: DurableBudgetReservation,
    ) -> StoredBudgetReservation:
        if record.status != "requested" or record.version != 1:
            raise ReservationStoreError("create_requested requires a version-1 requested record")
        args = _state_args(
            record,
            action_id=action_id,
            ledger_after_hold=None,
            ledger_after_settlement=None,
            receipt=None,
        )
        digest = _digest(action_digest, name="action_digest")
        row = await conn.fetchrow(_INSERT_SQL, *args, digest)
        if row:
            return StoredBudgetReservation.from_row(row)
        existing = await self.load_by_action(
            conn,
            owner_kind=record.owner_kind,
            owner_id=record.owner_id,
            action_id=action_id,
            for_update=True,
        )
        if existing is None:
            raise ReservationConflict("reservation insert conflicted but no row is visible")
        if (
            existing.record.capability_name != record.capability_name
            or dict(existing.record.requested) != dict(record.requested)
            or existing.action_digest != digest
        ):
            raise ReservationConflict(
                "action_id already belongs to a different capability, input, or budget request"
            )
        return existing

    async def persist_transition(
        self,
        conn: ReservationDatabase,
        *,
        previous: StoredBudgetReservation,
        current: DurableBudgetReservation,
        ledger_after_hold: Mapping[str, int] | None = None,
    ) -> StoredBudgetReservation:
        self._validate_transition(previous.record, current)
        held = (
            dict(ledger_after_hold)
            if ledger_after_hold is not None
            else previous.ledger_after_hold
        )
        args = _state_args(
            current,
            action_id=previous.action_id,
            ledger_after_hold=held,
            ledger_after_settlement=previous.ledger_after_settlement,
            receipt=previous.receipt,
        )
        row = await conn.fetchrow(
            _UPDATE_SQL,
            *args,
            previous.action_digest,
            previous.record.version,
            previous.record.state_digest,
        )
        if not row:
            raise ReservationConflict("reservation changed concurrently or lease version is stale")
        return StoredBudgetReservation.from_row(row)

    async def persist_terminal(
        self,
        conn: ReservationDatabase,
        *,
        previous: StoredBudgetReservation,
        terminal: DurableBudgetReservation,
        ledger_after_settlement: Mapping[str, int],
        receipt: CapabilityReceipt | None,
    ) -> StoredBudgetReservation:
        self._validate_transition(previous.record, terminal)
        if not terminal.terminal:
            raise ReservationStoreError("persist_terminal requires a terminal reservation")
        receipt_json: Mapping[str, Any] | None = None
        if receipt is not None:
            if receipt.budget_reservation_id != terminal.reservation_id:
                raise ReservationStoreError("receipt references another budget reservation")
            if receipt.budget_reservation_state != terminal.status:
                raise ReservationStoreError("receipt reservation state does not match terminal state")
            if receipt.receipt_hash != terminal.execution_receipt_hash:
                raise ReservationStoreError("receipt hash does not match terminal reservation")
            if receipt.input_digest != previous.action_digest:
                raise ReservationStoreError("receipt input digest does not match durable action")
            receipt_json = receipt.public_dict()
        elif terminal.execution_receipt_hash is not None:
            raise ReservationStoreError("terminal reservation has a receipt hash but no receipt")
        elif not terminal.execution_uncertain and terminal.status != "released":
            raise ReservationStoreError(
                "terminal execution without a receipt must be released or explicitly uncertain"
            )
        args = _state_args(
            terminal,
            action_id=previous.action_id,
            ledger_after_hold=previous.ledger_after_hold,
            ledger_after_settlement=ledger_after_settlement,
            receipt=receipt_json,
        )
        row = await conn.fetchrow(
            _UPDATE_SQL,
            *args,
            previous.action_digest,
            previous.record.version,
            previous.record.state_digest,
        )
        if not row:
            raise ReservationConflict("terminal reservation settlement lost an optimistic lock")
        return StoredBudgetReservation.from_row(row)

    async def stale(
        self,
        conn: ReservationDatabase,
        *,
        now: datetime,
        limit: int = 100,
        for_update_skip_locked: bool = True,
    ) -> tuple[StoredBudgetReservation, ...]:
        timestamp = _utc(now, name="now")
        if isinstance(limit, bool) or not 1 <= int(limit) <= 1000:
            raise ReservationStoreError("stale reservation limit must be between 1 and 1000")
        suffix = " FOR UPDATE SKIP LOCKED" if for_update_skip_locked else ""
        rows = await conn.fetch(
            """SELECT * FROM budget_reservations
               WHERE status IN ('reserved','running') AND lease_expires_at < $1
               ORDER BY lease_expires_at ASC, id ASC LIMIT $2""" + suffix,
            timestamp,
            int(limit),
        )
        return tuple(StoredBudgetReservation.from_row(row) for row in rows)

    @staticmethod
    def _validate_transition(
        previous: DurableBudgetReservation,
        current: DurableBudgetReservation,
    ) -> None:
        if previous.terminal:
            raise ReservationStoreError("terminal reservations are immutable")
        allowed = {
            "requested": {"reserved", "released", "failed"},
            "reserved": {"running", "released", "failed"},
            "running": {"running", "committed", "failed"},
        }
        if current.status not in allowed.get(previous.status, set()):
            raise ReservationStoreError(
                f"invalid reservation transition: {previous.status} -> {current.status}"
            )
        for name in (
            "reservation_id", "owner_kind", "owner_id", "capability_name", "requested"
        ):
            if getattr(previous, name) != getattr(current, name):
                raise ReservationStoreError(f"reservation transition changed immutable {name}")
        if current.version != previous.version + 1:
            raise ReservationStoreError("reservation transition must increment version exactly once")
        if current.updated_at < previous.updated_at:
            raise ReservationStoreError("reservation transition moved updated_at backwards")
