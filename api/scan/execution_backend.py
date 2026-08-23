"""Backend-neutral leases for the canonical Scan action scheduler.

The control plane owns immutable plans and durable settlement.  Local workers and
outbound-only broker workers receive the same action authority; the backend is
allowed to vary only the placement and short-lived lease metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Awaitable, Callable, Mapping, Protocol
import uuid

from .action_plan import SCAN_ACTION_PLAN_SCHEMA, ScanAction, ScanActionPlan
from .capability_result import CapabilityResultReference


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
        result: CapabilityResultReference,
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
    ) -> CapabilityResultReference: ...

    async def terminal_without_execution(
        self,
        action: ScanAction,
        lease: ActionLease,
        *,
        status: str,
        reason_code: str,
        charge_full_reservation: bool,
    ) -> CapabilityResultReference: ...


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
