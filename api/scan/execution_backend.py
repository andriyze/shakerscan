"""Backend-neutral leases for the canonical Scan action scheduler.

The control plane owns immutable plans and durable settlement.  Local workers and
outbound-only broker workers receive the same action authority; the backend is
allowed to vary only the placement and short-lived lease metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import secrets
from typing import Any, Awaitable, Callable, Mapping, Protocol
import uuid

from .action_plan import SCAN_ACTION_PLAN_SCHEMA, ScanAction, ScanActionPlan
from .action_reservations import (
    ScanActionReservationError,
    admit_and_start_scan_action_reservation,
    cancel_scan_action_reservation,
    heartbeat_scan_action_reservation,
    settle_scan_action_reservation,
)
from .capability_result import (
    CapabilityReceiptReference,
    CapabilityResultReason,
    CapabilityResultError,
    CapabilityResultReference,
    CapabilityResultStatus,
    placement_from_stored_result,
)
from .manifest_store import PostgresScanManifestStore, ScanManifestStoreError
from .work_manifests import (
    ScanWorkManifest,
    ScanWorkManifestReference,
    work_manifest_references_in,
)
try:  # Preserve one class identity under api.scan.* host imports.
    from ..runtime.observation_store import (
        ObservationStoreError,
        PostgresObservationManifestStore,
    )
    from ..runtime.json_fields import strip_null_bytes
    from ..runtime.receipts import CapabilityReceipt
    from ..runtime.reservation_store import PostgresBudgetReservationStore
except (ImportError, ModuleNotFoundError):  # top-level scan.* worker imports
    from runtime.observation_store import (
        ObservationStoreError,
        PostgresObservationManifestStore,
    )
    from runtime.json_fields import strip_null_bytes
    from runtime.receipts import CapabilityReceipt
    from runtime.reservation_store import PostgresBudgetReservationStore


ACTION_LEASE_SCHEMA = "scan-action-lease/v1"
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_LEASE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")


class ScanExecutionBackendError(RuntimeError):
    """A backend could not preserve immutable Scan execution authority."""


class ActionAlreadyTerminal(ScanExecutionBackendError):
    """A competing or redelivered lease already settled this action."""


class ActionLeaseLost(ScanExecutionBackendError):
    """The worker lost exclusive action authority during execution."""


def _uuid(value: Any, *, name: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ScanExecutionBackendError(f"{name} must be a UUID") from exc


def _digest(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _HEX_64_RE.fullmatch(normalized):
        raise ScanExecutionBackendError(f"{name} must be a SHA-256 digest")
    return normalized


def _positive_seconds(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 5 <= value <= 3_600:
        raise ScanExecutionBackendError("lease_seconds must be between 5 and 3600")
    return value


@dataclass(frozen=True)
class ActionLease:
    """Short-lived authority to execute exactly one immutable Scan action."""

    lease_id: str
    lease_token: str
    scan_id: str
    plan_digest: str
    execution_plan_digest: str
    target_binding_digest: str
    action: ScanAction
    backend: str
    worker_id: str
    lease_seconds: int
    attempt: int
    schema_version: str = ACTION_LEASE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != ACTION_LEASE_SCHEMA:
            raise ScanExecutionBackendError("unsupported Scan action lease schema")
        if not isinstance(self.action, ScanAction):
            raise ScanExecutionBackendError("action lease requires canonical ScanAction authority")
        token = str(self.lease_token or "").strip()
        if not _LEASE_TOKEN_RE.fullmatch(token):
            raise ScanExecutionBackendError("lease_token is invalid")
        backend = str(self.backend or "").strip().lower()
        eligible = tuple(self.action.placement.get("eligible_backends") or ())
        if backend not in eligible:
            raise ScanExecutionBackendError(
                f"action placement does not permit backend {backend or '<empty>'}"
            )
        worker_id = str(self.worker_id or "").strip()
        if not worker_id or len(worker_id) > 200:
            raise ScanExecutionBackendError("worker_id is invalid")
        if isinstance(self.attempt, bool) or not isinstance(self.attempt, int) or self.attempt < 1:
            raise ScanExecutionBackendError("action lease attempt must be positive")
        target_digest = _digest(
            self.target_binding_digest, name="target_binding_digest",
        )
        if self.action.target_binding_digest != target_digest:
            raise ScanExecutionBackendError("action lease target binding is inconsistent")
        object.__setattr__(self, "lease_id", _uuid(self.lease_id, name="lease_id"))
        object.__setattr__(self, "scan_id", _uuid(self.scan_id, name="scan_id"))
        object.__setattr__(self, "plan_digest", _digest(
            self.plan_digest, name="plan_digest",
        ))
        object.__setattr__(self, "execution_plan_digest", _digest(
            self.execution_plan_digest, name="execution_plan_digest",
        ))
        object.__setattr__(self, "target_binding_digest", target_digest)
        object.__setattr__(self, "lease_token", token)
        object.__setattr__(self, "backend", backend)
        object.__setattr__(self, "worker_id", worker_id)
        object.__setattr__(self, "lease_seconds", _positive_seconds(self.lease_seconds))

    def remote_payload(self) -> dict[str, Any]:
        """Return the complete database-free action authority for a worker."""
        return {
            "schema_version": self.schema_version,
            "lease_id": self.lease_id,
            "lease_token": self.lease_token,
            "scan_id": self.scan_id,
            "plan_schema_version": SCAN_ACTION_PLAN_SCHEMA,
            "plan_digest": self.plan_digest,
            "execution_plan_digest": self.execution_plan_digest,
            "target_binding_digest": self.target_binding_digest,
            "action": self.action.canonical_dict(),
            "backend": self.backend,
            "worker_id": self.worker_id,
            "lease_seconds": self.lease_seconds,
            "attempt": self.attempt,
        }

    @classmethod
    def from_remote_payload(cls, value: Mapping[str, Any]) -> "ActionLease":
        """Rehydrate a database-free lease and verify every authority field."""
        expected = {
            "schema_version", "lease_id", "lease_token", "scan_id",
            "plan_schema_version", "plan_digest", "execution_plan_digest",
            "target_binding_digest", "action", "backend", "worker_id",
            "lease_seconds", "attempt",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ScanExecutionBackendError("Scan action lease fields are invalid")
        if value.get("plan_schema_version") != SCAN_ACTION_PLAN_SCHEMA:
            raise ScanExecutionBackendError("Scan action lease plan schema is invalid")
        try:
            action = ScanAction.from_dict(value["action"])
        except (ScanExecutionBackendError, ValueError, TypeError) as exc:
            raise ScanExecutionBackendError("Scan action lease action is invalid") from exc
        return cls(
            schema_version=value["schema_version"],
            lease_id=value["lease_id"],
            lease_token=value["lease_token"],
            scan_id=value["scan_id"],
            plan_digest=value["plan_digest"],
            execution_plan_digest=value["execution_plan_digest"],
            target_binding_digest=value["target_binding_digest"],
            action=action,
            backend=value["backend"],
            worker_id=value["worker_id"],
            lease_seconds=value["lease_seconds"],
            attempt=value["attempt"],
        )


class ScanExecutionBackend(Protocol):
    """Durable scheduler boundary shared by local and broker placements."""

    backend_name: str

    async def acquire_action(self, action: ScanAction) -> ActionLease: ...

    async def heartbeat(self, lease: ActionLease) -> None: ...

    async def settle(
        self,
        lease: ActionLease,
        result: CapabilityResultReference | CapabilityReceipt,
    ) -> CapabilityResultReference: ...

    async def cancel_action(
        self, action: ScanAction,
    ) -> CapabilityResultReference: ...

    async def load_result(self, action_id: str) -> CapabilityResultReference | None: ...

    async def load_observations(
        self, action_id: str,
    ) -> tuple[Mapping[str, Any], ...]: ...

    async def load_work_manifest(
        self, action_id: str, reference: ScanWorkManifestReference,
    ) -> ScanWorkManifest: ...

    async def load_batch_attempts(
        self, action_id: str,
    ) -> tuple[Mapping[str, Any], ...]: ...

    async def checkpoint_batch_attempt(
        self, action_id: str, attempt: Mapping[str, Any],
    ) -> None: ...

    async def cancellation_requested(self) -> bool: ...


ActionHeartbeat = Callable[[], Awaitable[None]]


class ScanActionExecutor(Protocol):
    """Canonical adapter driver used above every execution backend."""

    async def execute(
        self,
        action: ScanAction,
        lease: ActionLease,
        heartbeat: ActionHeartbeat,
    ) -> CapabilityResultReference | CapabilityReceipt: ...

    async def terminal_without_execution(
        self,
        action: ScanAction,
        lease: ActionLease,
        *,
        status: str,
        reason_code: str,
        charge_full_reservation: bool,
    ) -> CapabilityResultReference | CapabilityReceipt: ...


def validate_action_lease(
    lease: ActionLease,
    *,
    plan: ScanActionPlan,
    action: ScanAction,
) -> None:
    """Fail closed when a backend substitutes any immutable authority field."""
    if (
        lease.scan_id != plan.scan_id
        or lease.plan_digest != plan.plan_digest
        or lease.execution_plan_digest != plan.execution_plan_digest
        or lease.target_binding_digest != plan.target_binding_digest
        or lease.action.action_id != action.action_id
        or lease.action.action_digest != action.action_digest
    ):
        raise ScanExecutionBackendError("action lease differs from the persisted Scan plan")


def validate_lease_freshness(
    *,
    expires_at: datetime,
    now: datetime | None = None,
) -> None:
    """Common strict lease-time check for local and broker transports."""
    current = now or datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        raise ScanExecutionBackendError("lease expiry must be timezone-aware")
    if expires_at <= current:
        raise ActionLeaseLost("action lease expired")


def _json_object(value: Any, *, name: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ScanExecutionBackendError(f"{name} is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise ScanExecutionBackendError(f"{name} must be an object")
    return dict(value)


class PostgresScanExecutionBackend:
    """Transactional action leases for the local control-plane scheduler.

    Only the SHA-256 hash of the lease token is persisted.  A raw token exists
    solely in the short-lived :class:`ActionLease` delivered to its selected
    worker.
    """

    backend_name = "local"

    def __init__(
        self,
        *,
        pool: Any,
        plan: ScanActionPlan,
        worker_id: str,
        backend_name: str = "local",
        lease_seconds: int = 120,
        token_factory: Callable[[], str] | None = None,
        aggregate_owner_id: str | None = None,
    ) -> None:
        if not isinstance(plan, ScanActionPlan):
            raise ScanExecutionBackendError("Postgres backend requires a canonical action plan")
        normalized_backend = str(backend_name or "").strip().lower()
        if normalized_backend not in {"local", "broker"}:
            raise ScanExecutionBackendError("Postgres backend placement is invalid")
        normalized_worker = str(worker_id or "").strip()
        if not normalized_worker or len(normalized_worker) > 200:
            raise ScanExecutionBackendError("Postgres backend worker_id is invalid")
        self._pool = pool
        self._plan = plan
        self._worker_id = normalized_worker
        self.backend_name = normalized_backend
        self._lease_seconds = _positive_seconds(lease_seconds)
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._aggregate_owner_id = (
            _uuid(aggregate_owner_id, name="aggregate_owner_id")
            if aggregate_owner_id else None
        )
        if self._aggregate_owner_id == plan.scan_id:
            raise ScanExecutionBackendError(
                "aggregate_owner_id must differ from the child Scan"
            )
        self._actions = {action.action_id: action for action in plan.actions}

    def _require_action(self, action_id: str) -> ScanAction:
        action = self._actions.get(str(action_id or ""))
        if action is None:
            raise ScanExecutionBackendError("action is absent from the persisted Scan plan")
        return action

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def _persist_recovered_terminal_action(
        self,
        conn: Any,
        *,
        action: ScanAction,
        receipt: CapabilityReceipt,
        reservation_id: str,
    ) -> None:
        """Consume one terminal reservation after an expired action lease."""
        result = await self._result_from_receipt(
            conn, action=action, receipt=receipt,
        )
        result_json = json.dumps(
            result.canonical_dict(), sort_keys=True, separators=(",", ":"),
        )
        manifest_id = (
            uuid.UUID(result.observation_manifest_ref.manifest_id)
            if result.observation_manifest_ref is not None else None
        )
        row = await conn.fetchrow(
            """UPDATE scan_capability_actions
                  SET status=$4, reason_code=$5, receipt_id=$6,
                      receipt_hash=$7, observation_manifest_id=$8,
                      result_digest=$9, result_json=$10::jsonb,
                      receipt_json=$11::jsonb, reservation_id=$12,
                      finished_at=now(), updated_at=now(),
                      lease_token_hash=NULL, lease_expires_at=NULL
                WHERE scan_id=$1 AND action_id=$2 AND action_digest=$3
                  AND status IN ('leased','running')
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= now()
                  AND reservation_id=$12
            RETURNING result_json""",
            uuid.UUID(self._plan.scan_id),
            action.action_id,
            action.action_digest,
            result.status.value,
            result.reason_code.value if result.reason_code is not None else None,
            result.receipt_ref.receipt_id,
            result.receipt_ref.receipt_hash,
            manifest_id,
            result.result_digest,
            result_json,
            json.dumps(
                receipt.public_dict(), sort_keys=True, separators=(",", ":"),
            ),
            reservation_id,
        )
        if row is None:
            raise ScanExecutionBackendError(
                "expired action changed during conservative recovery"
            )

    async def _recover_expired_action(
        self,
        conn: Any,
        *,
        action: ScanAction,
        state: Mapping[str, Any],
    ) -> None:
        """Settle once and charge the full hold instead of replaying traffic."""
        worker_id = str(state.get("worker_id") or "").strip()
        reservation_id = str(state.get("reservation_id") or "").strip()
        if not worker_id or not reservation_id:
            raise ScanExecutionBackendError(
                "expired action has no authoritative worker budget lease"
            )
        stored = await PostgresBudgetReservationStore().load(
            conn, reservation_id, for_update=True,
        )
        if stored is None:
            raise ScanExecutionBackendError(
                "expired action budget reservation is missing"
            )
        if stored.record.terminal:
            if not stored.receipt:
                raise ScanExecutionBackendError(
                    "terminal expired-action reservation has no receipt"
                )
            try:
                receipt = CapabilityReceipt.from_dict(stored.receipt)
            except (TypeError, ValueError) as exc:
                raise ScanExecutionBackendError(
                    "terminal expired-action receipt is invalid"
                ) from exc
        else:
            target_id = await conn.fetchval(
                "SELECT target_id::text FROM scans WHERE id=$1",
                uuid.UUID(self._plan.scan_id),
            )
            now = datetime.now(timezone.utc).isoformat()
            raw_receipt = CapabilityReceipt(
                capability_name=action.capability_name,
                adapter_name=str(action.placement.get("adapter_name") or ""),
                adapter_version=str(action.placement.get("adapter_version") or ""),
                target_id=str(target_id or self._plan.scan_id),
                scan_id=self._plan.scan_id,
                worker_id=worker_id,
                status="failed",
                input_digest=action.action_digest,
                parser_version="expired-action-recovery/v1",
                started_at=(
                    stored.record.started_at.isoformat()
                    if stored.record.started_at is not None else now
                ),
                finished_at=now,
                redacted_execution={
                    "action_id": action.action_id,
                    "execution_started": True,
                    "recovery": "expired_lease_full_charge",
                },
                budget_reserved=action.requested_budget,
                budget_consumed=action.requested_budget,
                observations=(),
                errors=("expired_action_lease_execution_uncertain",),
            )
            try:
                stored, receipt = await settle_scan_action_reservation(
                    conn,
                    plan=self._plan,
                    action=action,
                    worker_id=worker_id,
                    receipt=raw_receipt,
                    aggregate_owner_id=self._aggregate_owner_id,
                )
            except ScanActionReservationError as exc:
                raise ScanExecutionBackendError(str(exc)) from exc
        await self._persist_recovered_terminal_action(
            conn,
            action=action,
            receipt=receipt,
            reservation_id=stored.record.reservation_id,
        )

    async def acquire_action(self, action: ScanAction) -> ActionLease:
        async with self._pool.acquire() as conn:
            return await self.acquire_action_with_connection(conn, action)

    async def acquire_action_with_connection(
        self, conn: Any, action: ScanAction,
    ) -> ActionLease:
        """Lease one action on a caller-owned control-plane connection."""
        expected = self._require_action(action.action_id)
        if expected.action_digest != action.action_digest:
            raise ScanExecutionBackendError("action differs from the persisted Scan plan")
        if self.backend_name not in tuple(action.placement.get("eligible_backends") or ()):
            raise ScanExecutionBackendError("action cannot run on this backend")
        lease_id = str(uuid.uuid4())
        token = str(self._token_factory() or "").strip()
        if not _LEASE_TOKEN_RE.fullmatch(token):
            raise ScanExecutionBackendError("generated lease token is invalid")
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=self._lease_seconds,
        )
        recovered_expired = False
        async with conn.transaction():
            state = await conn.fetchrow(
                """SELECT status, result_json, action_digest, lease_expires_at,
                          worker_id, reservation_id
                     FROM scan_capability_actions
                    WHERE scan_id=$1 AND action_id=$2
                      AND action_digest=$3
                      AND execution_plan_digest=$4
                      AND target_binding_digest=$5
                    FOR UPDATE""",
                uuid.UUID(self._plan.scan_id),
                action.action_id,
                action.action_digest,
                self._plan.execution_plan_digest,
                self._plan.target_binding_digest,
            )
            if state is None:
                raise ScanExecutionBackendError(
                    "action immutable authority changed before lease"
                )
            status = str(state.get("status") or "")
            if status in {
                "success", "partial", "skipped", "blocked", "failed",
                "cancelled", "timed_out",
            }:
                raise ActionAlreadyTerminal(action.action_id)
            if status != "planned":
                expires_at = state.get("lease_expires_at")
                if (
                    status in {"leased", "running"}
                    and expires_at is not None
                    and expires_at <= datetime.now(timezone.utc)
                ):
                    await self._recover_expired_action(
                        conn, action=action, state=state,
                    )
                    recovered_expired = True
                else:
                    raise ScanExecutionBackendError(
                        "action already has an active execution lease"
                    )
            if not recovered_expired:
                try:
                    reservation = await admit_and_start_scan_action_reservation(
                        conn,
                        plan=self._plan,
                        action=action,
                        worker_id=self._worker_id,
                        lease_seconds=self._lease_seconds,
                        aggregate_owner_id=self._aggregate_owner_id,
                    )
                except ScanActionReservationError as exc:
                    raise ScanExecutionBackendError(str(exc)) from exc
                if reservation.record.terminal:
                    raise ScanExecutionBackendError(
                        "terminal Scan reservation has no terminal action result"
                    )
                row = await conn.fetchrow(
                """UPDATE scan_capability_actions
                      SET status='leased', backend_name=$6, worker_id=$7,
                          lease_id=$8, lease_token_hash=$9,
                          lease_expires_at=$10, reservation_id=$11,
                          attempt=attempt+1,
                          started_at=COALESCE(started_at, now()), updated_at=now()
                    WHERE scan_id=$1 AND action_id=$2
                      AND action_digest=$3
                      AND execution_plan_digest=$4
                      AND target_binding_digest=$5
                      AND status='planned'
                      AND (reservation_id IS NULL OR reservation_id=$11)
                RETURNING attempt""",
                    uuid.UUID(self._plan.scan_id),
                    action.action_id,
                    action.action_digest,
                    self._plan.execution_plan_digest,
                    self._plan.target_binding_digest,
                    self.backend_name,
                    self._worker_id,
                    uuid.UUID(lease_id),
                    self._token_hash(token),
                    expires_at,
                    reservation.record.reservation_id,
                )
                if row is None:
                    raise ScanExecutionBackendError(
                        "action changed while associating its budget hold"
                    )
                attempt = int(row["attempt"])
        if recovered_expired:
            raise ActionAlreadyTerminal(action.action_id)
        return ActionLease(
            lease_id=lease_id,
            lease_token=token,
            scan_id=self._plan.scan_id,
            plan_digest=str(self._plan.plan_digest),
            execution_plan_digest=self._plan.execution_plan_digest,
            target_binding_digest=self._plan.target_binding_digest,
            action=action,
            backend=self.backend_name,
            worker_id=self._worker_id,
            lease_seconds=self._lease_seconds,
            attempt=attempt,
        )

    async def cancel_action(
        self, action: ScanAction,
    ) -> CapabilityResultReference:
        """Persist a zero-traffic cancellation without an execution lease."""
        async with self._pool.acquire() as conn, conn.transaction():
            return await self.cancel_action_with_connection(conn, action)

    async def cancel_action_with_connection(
        self, conn: Any, action: ScanAction,
    ) -> CapabilityResultReference:
        """Cancel through a caller-owned control-plane transaction."""
        expected = self._require_action(action.action_id)
        if expected.action_digest != action.action_digest:
            raise ScanExecutionBackendError(
                "action differs from the persisted Scan plan"
            )
        state = await conn.fetchrow(
            """SELECT status, action_digest, result_json
                 FROM scan_capability_actions
                WHERE scan_id=$1 AND action_id=$2
                  AND action_digest=$3
                  AND execution_plan_digest=$4
                  AND target_binding_digest=$5
                FOR UPDATE""",
            uuid.UUID(self._plan.scan_id),
            action.action_id,
            action.action_digest,
            self._plan.execution_plan_digest,
            self._plan.target_binding_digest,
        )
        if state is None:
            raise ScanExecutionBackendError(
                "action immutable authority changed before cancellation"
            )
        existing = state.get("result_json")
        if existing is not None:
            try:
                result = CapabilityResultReference.from_dict(_json_object(
                    existing, name="stored cancelled action result",
                ))
                placement_from_stored_result(action=action, stored=result)
                return result
            except (CapabilityResultError, ValueError) as exc:
                raise ScanExecutionBackendError(
                    "stored cancelled action result is invalid"
                ) from exc
        if str(state.get("status") or "") != "planned":
            raise ScanExecutionBackendError(
                "active action cancellation belongs to its owning worker"
            )
        target_id = await conn.fetchval(
            "SELECT target_id::text FROM scans WHERE id=$1",
            uuid.UUID(self._plan.scan_id),
        )
        now = datetime.now(timezone.utc).isoformat()
        raw_receipt = CapabilityReceipt(
            capability_name=action.capability_name,
            adapter_name=str(action.placement.get("adapter_name") or ""),
            adapter_version=str(action.placement.get("adapter_version") or ""),
            target_id=str(target_id or self._plan.scan_id),
            scan_id=self._plan.scan_id,
            worker_id=self._worker_id,
            status="cancelled",
            input_digest=action.action_digest,
            parser_version="scan-cancellation/v1",
            started_at=now,
            finished_at=now,
            redacted_execution={
                "action_id": action.action_id,
                "execution_started": False,
                "terminalization": "owner_cancelled",
            },
            budget_reserved=action.requested_budget,
            budget_consumed={
                name: 0 for name in action.requested_budget
            },
            observations=(),
            errors=("cancelled_before_execution",),
        )
        try:
            reservation, linked_receipt = await cancel_scan_action_reservation(
                conn,
                plan=self._plan,
                action=action,
                receipt=raw_receipt,
                aggregate_owner_id=self._aggregate_owner_id,
            )
        except ScanActionReservationError as exc:
            raise ScanExecutionBackendError(str(exc)) from exc
        result = await self._result_from_receipt(
            conn, action=action, receipt=linked_receipt,
        )
        result_json = json.dumps(
            result.canonical_dict(), sort_keys=True, separators=(",", ":"),
        )
        row = await conn.fetchrow(
            """UPDATE scan_capability_actions
                  SET status='cancelled', reason_code=$4,
                      receipt_id=$5, receipt_hash=$6,
                      result_digest=$7, result_json=$8::jsonb,
                      receipt_json=$9::jsonb, reservation_id=$10,
                      finished_at=now(), updated_at=now(),
                      lease_token_hash=NULL, lease_expires_at=NULL
                WHERE scan_id=$1 AND action_id=$2 AND action_digest=$3
                  AND status='planned'
                  AND (reservation_id IS NULL OR reservation_id=$10)
            RETURNING result_json""",
            uuid.UUID(self._plan.scan_id),
            action.action_id,
            action.action_digest,
            CapabilityResultReason.CANCELLED.value,
            result.receipt_ref.receipt_id,
            result.receipt_ref.receipt_hash,
            result.result_digest,
            result_json,
            json.dumps(
                linked_receipt.public_dict(),
                sort_keys=True,
                separators=(",", ":"),
            ),
            reservation.record.reservation_id,
        )
        if row is None:
            raise ScanExecutionBackendError(
                "action changed during cancellation settlement"
            )
        return CapabilityResultReference.from_dict(_json_object(
            row["result_json"], name="stored cancelled action result",
        ))

    async def heartbeat(self, lease: ActionLease) -> None:
        action = self._require_action(lease.action.action_id)
        validate_action_lease(lease, plan=self._plan, action=action)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._lease_seconds)
        async with self._pool.acquire() as conn, conn.transaction():
            try:
                await heartbeat_scan_action_reservation(
                    conn,
                    plan=self._plan,
                    action=action,
                    worker_id=self._worker_id,
                    lease_seconds=self._lease_seconds,
                    aggregate_owner_id=self._aggregate_owner_id,
                )
            except ScanActionReservationError as exc:
                raise ActionLeaseLost(str(exc)) from exc
            row = await conn.fetchrow(
                """UPDATE scan_capability_actions
                      SET status='running', lease_expires_at=$7, updated_at=now()
                    WHERE scan_id=$1 AND action_id=$2 AND action_digest=$3
                      AND lease_id=$4 AND lease_token_hash=$5
                      AND worker_id=$6 AND status IN ('leased','running')
                      AND lease_expires_at > now()
                RETURNING lease_expires_at""",
                uuid.UUID(self._plan.scan_id),
                action.action_id,
                action.action_digest,
                uuid.UUID(lease.lease_id),
                self._token_hash(lease.lease_token),
                self._worker_id,
                expires_at,
            )
        if row is None:
            raise ActionLeaseLost("action heartbeat lost durable lease authority")

    async def settle(
        self,
        lease: ActionLease,
        result: CapabilityResultReference | CapabilityReceipt,
    ) -> CapabilityResultReference:
        async with self._pool.acquire() as conn:
            return await self.settle_with_connection(conn, lease, result)

    async def settle_with_connection(
        self,
        conn: Any,
        lease: ActionLease,
        result: CapabilityResultReference | CapabilityReceipt,
    ) -> CapabilityResultReference:
        """Settle one action transactionally on a caller-owned connection."""
        action = self._require_action(lease.action.action_id)
        validate_action_lease(lease, plan=self._plan, action=action)
        receipt_json: str | None = None
        reservation_id: str | None = None
        async with conn.transaction():
            existing = await self._load_result_with_conn(conn, action)
            if existing is not None:
                return existing
            if isinstance(result, CapabilityReceipt):
                try:
                    reservation, result = await settle_scan_action_reservation(
                        conn,
                        plan=self._plan,
                        action=action,
                        worker_id=self._worker_id,
                        receipt=result,
                        aggregate_owner_id=self._aggregate_owner_id,
                    )
                    reservation_id = reservation.record.reservation_id
                except ScanActionReservationError as exc:
                    raise ScanExecutionBackendError(str(exc)) from exc
                receipt_json = json.dumps(
                    result.public_dict(), sort_keys=True, separators=(",", ":"),
                )
                result = await self._result_from_receipt(
                    conn, action=action, receipt=result,
                )
            if not isinstance(result, CapabilityResultReference):
                raise ScanExecutionBackendError("action settlement result type is invalid")
            if receipt_json is None:
                raise ScanExecutionBackendError(
                    "Scan action settlement requires a capability receipt"
                )
            try:
                placement_from_stored_result(action=action, stored=result)
            except CapabilityResultError as exc:
                raise ScanExecutionBackendError("action result is detached from its lease") from exc
            if (
                result.adapter_name != str(action.placement.get("adapter_name") or "")
                or result.adapter_version != str(action.placement.get("adapter_version") or "")
                or dict(result.budget_reserved) != dict(action.requested_budget)
            ):
                raise ScanExecutionBackendError("action result conflicts with lease authority")
            result_json = json.dumps(
                result.canonical_dict(), sort_keys=True, separators=(",", ":"),
            )
            manifest_id = (
                uuid.UUID(result.observation_manifest_ref.manifest_id)
                if result.observation_manifest_ref is not None else None
            )
            row = await conn.fetchrow(
                """UPDATE scan_capability_actions
                      SET status=$7, reason_code=$8, receipt_id=$9,
                          receipt_hash=$10, observation_manifest_id=$11,
                          result_digest=$12, result_json=$13::jsonb,
                          receipt_json=COALESCE($14::jsonb, receipt_json),
                          reservation_id=COALESCE(reservation_id, $15),
                          finished_at=now(), updated_at=now(),
                          lease_token_hash=NULL, lease_expires_at=NULL
                    WHERE scan_id=$1 AND action_id=$2 AND action_digest=$3
                      AND lease_id=$4 AND lease_token_hash=$5
                      AND worker_id=$6 AND status IN ('leased','running')
                      AND lease_expires_at > now()
                      AND reservation_id=$15
                RETURNING result_json""",
                uuid.UUID(self._plan.scan_id),
                action.action_id,
                action.action_digest,
                uuid.UUID(lease.lease_id),
                self._token_hash(lease.lease_token),
                self._worker_id,
                result.status.value,
                result.reason_code.value if result.reason_code is not None else None,
                result.receipt_ref.receipt_id,
                result.receipt_ref.receipt_hash,
                manifest_id,
                result.result_digest,
                result_json,
                receipt_json,
                reservation_id,
            )
            if row is None:
                existing = await self._load_result_with_conn(conn, action)
                if existing is not None and existing.result_digest == result.result_digest:
                    return existing
                raise ActionLeaseLost("action settlement lost durable lease authority")
            stored = CapabilityResultReference.from_dict(_json_object(
                row["result_json"], name="stored action result",
            ))
            placement_from_stored_result(action=action, stored=stored)
            return stored

    async def _result_from_receipt(
        self,
        conn: Any,
        *,
        action: ScanAction,
        receipt: CapabilityReceipt,
    ) -> CapabilityResultReference:
        if (
            receipt.scan_id != self._plan.scan_id
            or receipt.input_digest != action.action_digest
            or receipt.capability_name != action.capability_name
            or receipt.adapter_name != str(action.placement.get("adapter_name") or "")
            or receipt.adapter_version != str(action.placement.get("adapter_version") or "")
            or dict(receipt.budget_reserved) != dict(action.requested_budget)
        ):
            raise ScanExecutionBackendError("capability receipt conflicts with action authority")
        raw_status = receipt.status.strip().lower()
        if raw_status in {"success", "succeeded", "completed"}:
            status = CapabilityResultStatus.SUCCESS
            reason = None
        elif receipt.timed_out or raw_status == "timed_out":
            status = CapabilityResultStatus.TIMED_OUT
            reason = CapabilityResultReason.TIMED_OUT
        elif raw_status == "partial" or receipt.partial:
            status = CapabilityResultStatus.PARTIAL
            # A partial result is not automatically a truncated one. A batch that
            # deliberately funds fewer, viable attempts than it planned is
            # partial for budget reasons and nothing was cut off; labelling that
            # "output_truncated" put a false reason on the action and made the
            # whole grade unreliable. Honour whatever reason the adapter stated,
            # exactly as the skipped and blocked branches already do, and keep
            # truncation as the fallback for adapters that state nothing.
            reason = self._receipt_reason(
                receipt, CapabilityResultReason.OUTPUT_TRUNCATED,
            )
        elif raw_status == "skipped":
            status = CapabilityResultStatus.SKIPPED
            reason = self._receipt_reason(receipt, CapabilityResultReason.NOT_APPLICABLE)
        elif raw_status == "blocked":
            status = CapabilityResultStatus.BLOCKED
            reason = self._receipt_reason(receipt, CapabilityResultReason.ADAPTER_FAILED)
        elif raw_status == "cancelled":
            status = CapabilityResultStatus.CANCELLED
            reason = CapabilityResultReason.CANCELLED
        else:
            status = CapabilityResultStatus.FAILED
            reason = self._receipt_reason(receipt, CapabilityResultReason.ADAPTER_FAILED)
        manifest_ref = None
        if status in {
            CapabilityResultStatus.SUCCESS,
            CapabilityResultStatus.PARTIAL,
            CapabilityResultStatus.TIMED_OUT,
        }:
            manifest_ref = await PostgresObservationManifestStore().persist(
                conn,
                scan_id=self._plan.scan_id,
                action_id=action.action_id,
                capability_name=action.capability_name,
                output_schema=action.output_schema,
                observations=tuple(dict(item) for item in receipt.observations),
            )
        return CapabilityResultReference(
            action_id=action.action_id,
            action_digest=str(action.action_digest),
            capability_name=action.capability_name,
            adapter_name=receipt.adapter_name,
            adapter_version=receipt.adapter_version,
            output_schema=action.output_schema,
            status=status,
            partial=status in {
                CapabilityResultStatus.PARTIAL,
                CapabilityResultStatus.TIMED_OUT,
            },
            timed_out=status is CapabilityResultStatus.TIMED_OUT,
            reason_code=reason,
            receipt_ref=CapabilityReceiptReference(
                receipt_id=receipt.receipt_id,
                receipt_hash=receipt.receipt_hash,
            ),
            observation_manifest_ref=manifest_ref,
            budget_reserved=receipt.budget_reserved,
            budget_consumed=receipt.budget_consumed,
        )

    @staticmethod
    def _receipt_reason(
        receipt: CapabilityReceipt,
        default: CapabilityResultReason,
    ) -> CapabilityResultReason:
        known = {item.value: item for item in CapabilityResultReason}
        for error in receipt.errors:
            candidate = str(error or "").strip().lower().split(":", 1)[0]
            if candidate in known:
                return known[candidate]
        return default

    async def _load_result_with_conn(
        self, conn: Any, action: ScanAction,
    ) -> CapabilityResultReference | None:
        row = await conn.fetchrow(
            """SELECT status, action_digest, result_json
                 FROM scan_capability_actions
                WHERE scan_id=$1 AND action_id=$2""",
            uuid.UUID(self._plan.scan_id),
            action.action_id,
        )
        if row is None:
            raise ScanExecutionBackendError("persisted Scan action index is incomplete")
        if str(row.get("action_digest") or "") != action.action_digest:
            raise ScanExecutionBackendError("persisted Scan action authority changed")
        raw = row.get("result_json")
        if raw is None:
            if str(row.get("status") or "") in {
                "success", "partial", "skipped", "blocked", "failed",
                "cancelled", "timed_out",
            }:
                raise ScanExecutionBackendError("terminal Scan action has no generic result")
            return None
        try:
            result = CapabilityResultReference.from_dict(_json_object(
                raw, name="stored action result",
            ))
            placement_from_stored_result(action=action, stored=result)
        except (CapabilityResultError, ValueError) as exc:
            raise ScanExecutionBackendError("stored Scan action result is invalid") from exc
        return result

    async def load_result(self, action_id: str) -> CapabilityResultReference | None:
        async with self._pool.acquire() as conn:
            return await self.load_result_with_connection(conn, action_id)

    async def load_action_receipt(self, action_id: str) -> dict[str, Any]:
        """Load only the already-redacted public receipt for activity diagnostics."""
        action = self._require_action(action_id)
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """SELECT receipt_json
                     FROM scan_capability_actions
                    WHERE scan_id=$1 AND action_id=$2 AND action_digest=$3""",
                uuid.UUID(self._plan.scan_id),
                action.action_id,
                action.action_digest,
            )
        if row is None or row.get("receipt_json") is None:
            return {}
        return _json_object(row["receipt_json"], name="stored action receipt")

    async def load_result_with_connection(
        self, conn: Any, action_id: str,
    ) -> CapabilityResultReference | None:
        """Read a result without recursively acquiring the control-plane pool."""
        action = self._require_action(action_id)
        return await self._load_result_with_conn(conn, action)

    async def load_observations(
        self, action_id: str,
    ) -> tuple[Mapping[str, Any], ...]:
        """Load only content-addressed observations from a terminal action."""
        result = await self.load_result(action_id)
        if result is None or result.observation_manifest_ref is None:
            return ()
        try:
            async with self._pool.acquire() as conn:
                observations = await PostgresObservationManifestStore().load(
                    conn,
                    reference=result.observation_manifest_ref,
                    scan_id=self._plan.scan_id,
                    action_id=action_id,
                )
        except ObservationStoreError as exc:
            raise ScanExecutionBackendError(str(exc)) from exc
        if observations is None:
            raise ScanExecutionBackendError(
                "terminal Scan observation manifest is unavailable"
            )
        return tuple(observations)

    async def load_work_manifest(
        self,
        action_id: str,
        reference: ScanWorkManifestReference,
    ) -> ScanWorkManifest:
        """Load one exact work manifest frozen into the action authority."""
        action = self._require_action(action_id)
        if (
            not isinstance(reference, ScanWorkManifestReference)
            or reference not in work_manifest_references_in(action.capability_args)
        ):
            raise ScanExecutionBackendError(
                "work manifest is absent from immutable action authority"
            )
        try:
            async with self._pool.acquire() as conn:
                manifest = await PostgresScanManifestStore().load(
                    conn,
                    manifest_id=reference.manifest_id,
                    scan_id=self._plan.scan_id,
                    expected_kind=reference.kind,
                    expected_digest=reference.manifest_digest,
                    expected_target_binding_digest=self._plan.target_binding_digest,
                )
        except ScanManifestStoreError as exc:
            raise ScanExecutionBackendError(str(exc)) from exc
        if manifest is None or manifest.reference() != reference:
            raise ScanExecutionBackendError("authorized work manifest is unavailable")
        return manifest

    async def load_batch_attempts(
        self, action_id: str,
    ) -> tuple[Mapping[str, Any], ...]:
        """Load immutable completed sub-attempts for one local batch action."""
        action = self._require_action(action_id)
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT attempt_id, candidate_id, status, budget_consumed,
                          observations_json, errors_json, proof_state
                     FROM scan_action_attempt_checkpoints
                    WHERE scan_id=$1 AND action_id=$2 AND action_digest=$3
                    ORDER BY created_at, attempt_id""",
                uuid.UUID(self._plan.scan_id), action.action_id, action.action_digest,
            )
        return tuple({
            "attempt_id": str(row["attempt_id"]),
            "candidate_id": str(row["candidate_id"]),
            "status": str(row["status"]),
            "budget_consumed": _json_object(
                row["budget_consumed"], name="batch attempt budget",
            ),
            "observations": tuple(_json_array(
                row["observations_json"], name="batch attempt observations",
            )),
            "errors": tuple(str(item) for item in _json_array(
                row["errors_json"], name="batch attempt errors",
            )),
            "proof_state": str(row.get("proof_state") or "") or None,
        } for row in rows)

    async def checkpoint_batch_attempt(
        self, action_id: str, attempt: Mapping[str, Any],
    ) -> None:
        """Durably freeze one completed candidate attempt before continuing."""
        action = self._require_action(action_id)
        attempt_id = str(attempt.get("attempt_id") or "").strip().lower()
        candidate_id = str(attempt.get("candidate_id") or "").strip()
        status = str(attempt.get("status") or "").strip().lower()
        if (
            not re.fullmatch(r"[0-9a-f]{64}", attempt_id)
            or not candidate_id
            or status not in {
                "success", "partial", "skipped", "blocked", "failed",
                "cancelled", "timed_out",
            }
        ):
            raise ScanExecutionBackendError("batch attempt checkpoint is invalid")
        budget = {
            str(name): max(0, int(amount))
            for name, amount in dict(attempt.get("budget_consumed") or {}).items()
        }
        # Binary content captured by a probe carries NUL, which jsonb rejects
        # outright; one such byte failed the whole batch action and discarded
        # every attempt it had already checkpointed.
        observations = strip_null_bytes([
            dict(item) for item in attempt.get("observations") or ()
            if isinstance(item, Mapping)
        ])
        errors = strip_null_bytes(
            [str(item)[:500] for item in attempt.get("errors") or ()][:20]
        )
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO scan_action_attempt_checkpoints (
                       scan_id, action_id, action_digest, attempt_id, candidate_id,
                       status, budget_consumed, observations_json, errors_json,
                       proof_state
                   ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10)
                   ON CONFLICT (scan_id, action_id, attempt_id) DO UPDATE
                      SET updated_at=now()
                    WHERE scan_action_attempt_checkpoints.action_digest=EXCLUDED.action_digest
                      AND scan_action_attempt_checkpoints.candidate_id=EXCLUDED.candidate_id
                      AND scan_action_attempt_checkpoints.status=EXCLUDED.status
                  RETURNING attempt_id""",
                uuid.UUID(self._plan.scan_id), action.action_id, action.action_digest,
                attempt_id, candidate_id, status,
                json.dumps(budget, sort_keys=True),
                json.dumps(observations, sort_keys=True),
                json.dumps(errors),
                str(attempt.get("proof_state") or "") or None,
            )
        if row is None:
            raise ScanExecutionBackendError("batch attempt checkpoint conflicts with authority")

    async def cancellation_requested(self) -> bool:
        async with self._pool.acquire() as conn:
            return await self.cancellation_requested_with_connection(conn)

    async def cancellation_requested_with_connection(self, conn: Any) -> bool:
        """Read cancellation without recursively acquiring the pool."""
        status = await conn.fetchval(
            "SELECT status FROM scans WHERE id=$1",
            uuid.UUID(self._plan.scan_id),
        )
        if status is None:
            raise ScanExecutionBackendError("Scan owner disappeared during execution")
        return str(status).strip().lower() in {"cancelled", "cancelling"}
