"""Execute exact request-collection replay through durable budgets and receipts.

The planner never calls this module with raw HTTP. The worker decrypts a selected
collection, builds a target-bound :class:`ReplayPlan`, and invokes this executor with a
server-owned transport that pins connections to the frozen target address set.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import inspect
import ipaddress
import re
from typing import Any, Awaitable, Callable, Mapping, Protocol, Sequence
import urllib.parse

try:
    from scanner_tools.request_replay import ReplayPlan, ReplayRequest
except ModuleNotFoundError:  # package import when scanner is installed as a package
    from scanner.scanner_tools.request_replay import ReplayPlan, ReplayRequest

from .budget_reservations import DurableBudgetReservation
from .models import TargetBinding
from .receipts import CapabilityReceipt


MAX_REPLAY_RESPONSE_BODY_BYTES = 2 * 1024 * 1024
_ERROR_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,119}$")


class ReplayExecutionError(ValueError):
    """The replay cannot be executed inside the frozen target/runtime authority."""


@dataclass(frozen=True)
class ReplayTransportResult:
    """Bounded worker-transport result; response values are never copied into receipts."""

    status_code: int | None
    connected_address: str | None
    final_url: str
    response_headers: Mapping[str, str] = field(default_factory=dict)
    response_body: bytes = b""
    elapsed_ms: int = 0
    error_code: str | None = None
    timed_out: bool = False

    def __post_init__(self) -> None:
        if self.status_code is not None and (
            isinstance(self.status_code, bool) or not 100 <= int(self.status_code) <= 599
        ):
            raise ReplayExecutionError("transport status_code is invalid")
        if isinstance(self.elapsed_ms, bool) or not 0 <= int(self.elapsed_ms) <= 86_400_000:
            raise ReplayExecutionError("transport elapsed_ms is invalid")
        body = bytes(self.response_body or b"")
        if len(body) > MAX_REPLAY_RESPONSE_BODY_BYTES:
            raise ReplayExecutionError("transport response body exceeds the capture limit")
        headers = dict(self.response_headers or {})
        if len(headers) > 200:
            raise ReplayExecutionError("transport returned too many response headers")
        error = str(self.error_code or "").strip().lower() or None
        if error is not None and not _ERROR_RE.fullmatch(error):
            raise ReplayExecutionError("transport error_code is invalid")
        if self.timed_out and error is None:
            error = "timeout"
        object.__setattr__(self, "status_code", int(self.status_code) if self.status_code else None)
        object.__setattr__(self, "connected_address", (
            str(ipaddress.ip_address(self.connected_address)) if self.connected_address else None
        ))
        object.__setattr__(self, "response_headers", headers)
        object.__setattr__(self, "response_body", body)
        object.__setattr__(self, "elapsed_ms", int(self.elapsed_ms))
        object.__setattr__(self, "error_code", error)


class ReplayTransport(Protocol):
    async def send(
        self,
        request: ReplayRequest,
        *,
        target: TargetBinding,
        timeout_seconds: float,
        follow_redirects: bool,
    ) -> ReplayTransportResult:
        """Send one exact request using server-owned target pinning."""


ReservationSink = Callable[
    [DurableBudgetReservation, Mapping[str, int]], Awaitable[None] | None
]
SettlementSink = Callable[
    [DurableBudgetReservation, CapabilityReceipt, Mapping[str, int]],
    Awaitable[None] | None,
]
Clock = Callable[[], datetime]


@dataclass(frozen=True)
class ReplayExecutionOutcome:
    status: str
    reservation: DurableBudgetReservation
    receipt: CapabilityReceipt
    ledger_consumed: Mapping[str, int]

    def public_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reservation_id": self.reservation.reservation_id,
            "reservation_status": self.reservation.status,
            "receipt": self.receipt.public_dict(),
            "ledger_consumed": dict(self.ledger_consumed),
        }


async def _invoke(callback: Callable[..., Any] | None, *args: Any) -> None:
    if callback is None:
        return
    result = callback(*args)
    if inspect.isawaitable(result):
        await result


def _utc(clock: Clock) -> datetime:
    value = clock()
    if value.tzinfo is None:
        raise ReplayExecutionError("execution clock must return timezone-aware timestamps")
    return value.astimezone(timezone.utc)


def _origin(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(str(value or ""))
        port = parsed.port
    except ValueError as exc:
        raise ReplayExecutionError("transport final URL has an invalid authority") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ReplayExecutionError("transport final URL is not HTTP(S)")
    host = parsed.hostname.lower().rstrip(".")
    display = f"[{host}]" if ":" in host else host
    default = 443 if parsed.scheme.lower() == "https" else 80
    authority = display if port in {None, default} else f"{display}:{port}"
    return f"{parsed.scheme.lower()}://{authority}"


def _redacted_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(str(value or ""))
    query = urllib.parse.urlencode([
        (str(name)[:200], "<redacted>")
        for name, _item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    ])
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", query, "")
    )[:2_000]


def _validate_runtime_binding(plan: ReplayPlan, target: TargetBinding) -> None:
    target_origins = set(target.allowed_origins)
    if not target_origins or not set(plan.allowed_origins) <= target_origins:
        raise ReplayExecutionError("replay plan origins are outside the frozen target binding")
    if target.target_kind in {"web", "api", "device"} and not target.allowed_addresses:
        raise ReplayExecutionError("exact replay requires frozen target addresses")


def _validate_transport_result(
    result: ReplayTransportResult,
    *,
    plan: ReplayPlan,
    target: TargetBinding,
) -> None:
    if result.connected_address not in set(target.allowed_addresses):
        raise ReplayExecutionError("transport connected outside the frozen target address set")
    if _origin(result.final_url) not in set(plan.allowed_origins):
        raise ReplayExecutionError("transport final URL escaped the replay origin binding")


def _observation(request: ReplayRequest, result: ReplayTransportResult) -> dict[str, Any]:
    public_request = request.public_dict()
    return {
        "kind": "request_replay",
        "request_id": request.request_id,
        "method": request.method,
        "redacted_url": public_request["redacted_url"],
        "final_url": _redacted_url(result.final_url),
        "connected_address": result.connected_address,
        "status_code": result.status_code,
        "response_header_names": sorted(str(name)[:200] for name in result.response_headers),
        "response_body_sha256": hashlib.sha256(result.response_body).hexdigest(),
        "response_body_size": len(result.response_body),
        "elapsed_ms": result.elapsed_ms,
        "error_code": result.error_code,
        "timed_out": bool(result.timed_out),
    }


def _actual_budget(plan: ReplayPlan, attempted: int) -> dict[str, int]:
    attempted = max(0, min(int(attempted), len(plan.requests)))
    actual = {"http_requests": attempted}
    state_changing = sum(
        request.method not in {"GET", "HEAD", "OPTIONS"}
        for request in plan.requests[:attempted]
    )
    if "state_changing_requests" in plan.estimated_budget:
        actual["state_changing_requests"] = int(state_changing)
    return actual


def _receipt(
    *,
    plan: ReplayPlan,
    target: TargetBinding,
    owner_kind: str,
    owner_id: str,
    worker_id: str,
    reservation: DurableBudgetReservation,
    reservation_state: str,
    actual: Mapping[str, int],
    status: str,
    partial: bool,
    timed_out: bool,
    started_at: datetime,
    finished_at: datetime,
    observations: Sequence[Mapping[str, Any]],
    errors: Sequence[str],
    receipt_id: str | None,
) -> CapabilityReceipt:
    return CapabilityReceipt(
        capability_name="collections.replay",
        adapter_name="pinned_http_replay",
        adapter_version="1",
        target_id=target.target_id,
        scan_id=owner_id if owner_kind == "scan" else None,
        hunt_id=owner_id if owner_kind == "hunt" else None,
        worker_id=worker_id,
        scope_receipt_id=target.scope_receipt_id,
        approval_receipt_id=plan.authorization.approval_receipt_id,
        status=status,
        partial=partial,
        timed_out=timed_out,
        input_digest=plan.input_digest,
        parser_version="request-replay-observations/v1",
        receipt_id=receipt_id or reservation.reservation_id,
        started_at=started_at.isoformat(),
        finished_at=finished_at.isoformat(),
        redacted_execution=plan.public_dict(),
        budget_reservation_id=reservation.reservation_id,
        budget_reservation_state=reservation_state,
        budget_reserved=reservation.requested,
        budget_consumed=actual,
        observations=tuple(observations),
        errors=tuple(errors),
    )


async def execute_replay_plan(
    plan: ReplayPlan,
    *,
    target: TargetBinding,
    owner_kind: str,
    owner_id: str,
    worker_id: str,
    limits: Mapping[str, int],
    consumed: Mapping[str, int],
    transport: ReplayTransport,
    timeout_seconds: float = 30.0,
    reservation_id: str | None = None,
    receipt_id: str | None = None,
    lease_seconds: int = 120,
    clock: Clock = lambda: datetime.now(timezone.utc),
    on_reservation: ReservationSink | None = None,
    on_settlement: SettlementSink | None = None,
) -> ReplayExecutionOutcome:
    """Execute one exact ReplayPlan with reserve-before-send accounting.

    Persistence callbacks are intentionally explicit. The caller stores requested,
    reserved, and running states as they occur; ``on_settlement`` atomically stores the
    terminal reservation, receipt, and reconciled ledger snapshot.
    """
    if owner_kind not in {"scan", "hunt"}:
        raise ReplayExecutionError("owner_kind must be scan or hunt")
    owner = str(owner_id or "").strip()
    worker = str(worker_id or "").strip()
    if not owner or not worker:
        raise ReplayExecutionError("owner_id and worker_id are required")
    if isinstance(timeout_seconds, bool) or not 0.1 <= float(timeout_seconds) <= 300:
        raise ReplayExecutionError("timeout_seconds must be between 0.1 and 300")
    _validate_runtime_binding(plan, target)

    now = _utc(clock)
    requested = DurableBudgetReservation.request(
        owner_kind=owner_kind,
        owner_id=owner,
        capability_name="collections.replay",
        amounts=plan.estimated_budget,
        now=now,
        reservation_id=reservation_id,
    )
    await _invoke(on_reservation, requested, dict(consumed))
    reserved, held_ledger = requested.reserve_against(
        limits=limits,
        consumed=consumed,
        now=_utc(clock),
        lease_seconds=lease_seconds,
    )
    await _invoke(on_reservation, reserved, held_ledger)
    running = reserved.start(
        worker_id=worker,
        now=_utc(clock),
        lease_seconds=lease_seconds,
    )
    await _invoke(on_reservation, running, held_ledger)

    started_at = running.started_at or _utc(clock)
    observations: list[Mapping[str, Any]] = []
    errors: list[str] = []
    attempted = 0
    any_timeout = False
    try:
        for request in plan.requests:
            attempted += 1  # Charge conservatively before the target may receive bytes.
            result = await transport.send(
                request,
                target=target,
                timeout_seconds=float(timeout_seconds),
                follow_redirects=False,
            )
            if not isinstance(result, ReplayTransportResult):
                raise ReplayExecutionError("transport returned an invalid result type")
            _validate_transport_result(result, plan=plan, target=target)
            observations.append(_observation(request, result))
            if result.error_code:
                errors.append(f"{request.request_id}:{result.error_code}")
            any_timeout = any_timeout or result.timed_out
    except asyncio.CancelledError:
        actual = _actual_budget(plan, attempted)
        finished_at = _utc(clock)
        receipt = _receipt(
            plan=plan,
            target=target,
            owner_kind=owner_kind,
            owner_id=owner,
            worker_id=worker,
            reservation=running,
            reservation_state="failed",
            actual=actual,
            status="partial",
            partial=True,
            timed_out=False,
            started_at=started_at,
            finished_at=finished_at,
            observations=observations,
            errors=(*errors, "execution_cancelled"),
            receipt_id=receipt_id,
        )
        failed = running.fail(
            reason="execution_cancelled",
            now=finished_at,
            actual=actual,
            execution_receipt_hash=receipt.receipt_hash,
            execution_may_have_started=True,
        )
        settled = failed.reconcile_consumed(held_ledger)
        if on_settlement is not None:
            await asyncio.shield(_invoke(on_settlement, failed, receipt, settled))
        raise
    except Exception as exc:
        actual = _actual_budget(plan, attempted)
        finished_at = _utc(clock)
        error_code = f"executor_{type(exc).__name__.lower()}"[:120]
        partial = attempted > 0
        receipt = _receipt(
            plan=plan,
            target=target,
            owner_kind=owner_kind,
            owner_id=owner,
            worker_id=worker,
            reservation=running,
            reservation_state="failed",
            actual=actual,
            status="partial" if partial else "failed",
            partial=partial,
            timed_out=False,
            started_at=started_at,
            finished_at=finished_at,
            observations=observations,
            errors=(*errors, error_code),
            receipt_id=receipt_id,
        )
        failed = running.fail(
            reason=error_code,
            now=finished_at,
            actual=actual,
            execution_receipt_hash=receipt.receipt_hash,
            execution_may_have_started=attempted > 0,
        )
        settled = failed.reconcile_consumed(held_ledger)
        await _invoke(on_settlement, failed, receipt, settled)
        return ReplayExecutionOutcome(receipt.status, failed, receipt, settled)

    actual = _actual_budget(plan, attempted)
    partial = bool(errors)
    finished_at = _utc(clock)
    receipt = _receipt(
        plan=plan,
        target=target,
        owner_kind=owner_kind,
        owner_id=owner,
        worker_id=worker,
        reservation=running,
        reservation_state="committed",
        actual=actual,
        status="partial" if partial else "succeeded",
        partial=partial,
        timed_out=any_timeout,
        started_at=started_at,
        finished_at=finished_at,
        observations=observations,
        errors=errors,
        receipt_id=receipt_id,
    )
    committed = running.commit(
        actual=actual,
        execution_receipt_hash=receipt.receipt_hash,
        now=finished_at,
    )
    settled = committed.reconcile_consumed(held_ledger)
    await _invoke(on_settlement, committed, receipt, settled)
    return ReplayExecutionOutcome(receipt.status, committed, receipt, settled)
