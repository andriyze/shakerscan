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
from .capability_result import (
    CapabilityReceiptReference,
    CapabilityResultReason,
    CapabilityResultError,
    CapabilityResultReference,
    CapabilityResultStatus,
    placement_from_stored_result,
)
try:  # Preserve one class identity under api.scan.* host imports.
    from ..runtime.observation_store import PostgresObservationManifestStore
    from ..runtime.receipts import CapabilityReceipt
except (ImportError, ModuleNotFoundError):  # top-level scan.* worker imports
    from runtime.observation_store import PostgresObservationManifestStore
    from runtime.receipts import CapabilityReceipt


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

    async def load_result(self, action_id: str) -> CapabilityResultReference | None: ...

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
        self._actions = {action.action_id: action for action in plan.actions}

    def _require_action(self, action_id: str) -> ScanAction:
        action = self._actions.get(str(action_id or ""))
        if action is None:
            raise ScanExecutionBackendError("action is absent from the persisted Scan plan")
        return action

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def acquire_action(self, action: ScanAction) -> ActionLease:
        expected = self._require_action(action.action_id)
        if expected.action_digest != action.action_digest:
            raise ScanExecutionBackendError("action differs from the persisted Scan plan")
        if self.backend_name not in tuple(action.placement.get("eligible_backends") or ()):
            raise ScanExecutionBackendError("action cannot run on this backend")
        lease_id = str(uuid.uuid4())
        token = str(self._token_factory() or "").strip()
        if not _LEASE_TOKEN_RE.fullmatch(token):
            raise ScanExecutionBackendError("generated lease token is invalid")
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._lease_seconds)
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """UPDATE scan_capability_actions
                      SET status='leased', backend_name=$6, worker_id=$7,
                          lease_id=$8, lease_token_hash=$9,
                          lease_expires_at=$10, attempt=attempt+1,
                          started_at=COALESCE(started_at, now()), updated_at=now()
                    WHERE scan_id=$1 AND action_id=$2
                      AND action_digest=$3
                      AND execution_plan_digest=$4
                      AND target_binding_digest=$5
                      AND status='planned'
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
            )
            if row is None:
                state = await conn.fetchrow(
                    """SELECT status, result_json, action_digest
                         FROM scan_capability_actions
                        WHERE scan_id=$1 AND action_id=$2""",
                    uuid.UUID(self._plan.scan_id),
                    action.action_id,
                )
                if state and str(state.get("status") or "") in {
                    "success", "partial", "skipped", "blocked", "failed",
                    "cancelled", "timed_out",
                }:
                    raise ActionAlreadyTerminal(action.action_id)
                raise ScanExecutionBackendError(
                    "action is already leased or its immutable authority changed"
                )
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
            attempt=int(row["attempt"]),
        )

    async def heartbeat(self, lease: ActionLease) -> None:
        action = self._require_action(lease.action.action_id)
        validate_action_lease(lease, plan=self._plan, action=action)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._lease_seconds)
        async with self._pool.acquire() as conn:
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
        action = self._require_action(lease.action.action_id)
        validate_action_lease(lease, plan=self._plan, action=action)
        receipt_json: str | None = None
        async with self._pool.acquire() as conn, conn.transaction():
            if isinstance(result, CapabilityReceipt):
                receipt_json = json.dumps(
                    result.public_dict(), sort_keys=True, separators=(",", ":"),
                )
                result = await self._result_from_receipt(
                    conn, action=action, receipt=result,
                )
            if not isinstance(result, CapabilityResultReference):
                raise ScanExecutionBackendError("action settlement result type is invalid")
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
                          finished_at=now(), updated_at=now(),
                          lease_token_hash=NULL, lease_expires_at=NULL
                    WHERE scan_id=$1 AND action_id=$2 AND action_digest=$3
                      AND lease_id=$4 AND lease_token_hash=$5
                      AND worker_id=$6 AND status IN ('leased','running')
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
            reason = CapabilityResultReason.OUTPUT_TRUNCATED
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
        action = self._require_action(action_id)
        async with self._pool.acquire() as conn:
            return await self._load_result_with_conn(conn, action)

    async def cancellation_requested(self) -> bool:
        async with self._pool.acquire() as conn:
            status = await conn.fetchval(
                "SELECT status FROM scans WHERE id=$1",
                uuid.UUID(self._plan.scan_id),
            )
        if status is None:
            raise ScanExecutionBackendError("Scan owner disappeared during execution")
        return str(status).strip().lower() in {"cancelled", "cancelling"}
