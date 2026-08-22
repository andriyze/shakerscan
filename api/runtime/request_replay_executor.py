"""Execute exact request-collection replay through durable budgets and receipts.

The planner never calls this module with raw HTTP. The worker decrypts a selected
collection, builds a target-bound :class:`ReplayPlan`, and invokes this executor with a
server-owned transport that pins connections to the frozen target address set.

The executor adds a second, worker-owned deadline around every transport call. Transport
implementations are still expected to enforce their own socket deadlines, but a buggy
adapter cannot hold the durable reservation indefinitely. Evidence contains only redacted
URLs, response header names, and body hashes; exact request/response values stay private.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import inspect
import ipaddress
import math
import re
from typing import Any, Awaitable, Callable, Mapping, Protocol, Sequence
import urllib.parse

try:
    from scanner_tools.request_replay import ReplayPlan, ReplayRequest
    from scanner_tools.url_redaction import redact_url
except ModuleNotFoundError:  # package import when scanner is installed as a package
    from scanner.scanner_tools.request_replay import ReplayPlan, ReplayRequest
    from scanner.scanner_tools.url_redaction import redact_url

from .budget_reservations import DurableBudgetReservation
from .models import TargetBinding
from .receipts import CapabilityReceipt


MAX_REPLAY_RESPONSE_BODY_BYTES = 2 * 1024 * 1024
MAX_REPLAY_RESPONSE_HEADERS = 200
MIN_REPLAY_LEASE_SECONDS = 30
REPLAY_LEASE_SAFETY_SECONDS = 5
_ERROR_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,119}$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,200}$")


class ReplayExecutionError(ValueError):
    """The replay cannot be executed inside the frozen target/runtime authority."""


def _canonical_authority(value: str) -> tuple[str, str, int | None]:
    """Return scheme/authority/port while rejecting userinfo and malformed hosts."""
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        port = parsed.port
    except ValueError as exc:
        raise ReplayExecutionError("transport URL has an invalid authority") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ReplayExecutionError("transport URL is not HTTP(S)")
    if parsed.username is not None or parsed.password is not None:
        raise ReplayExecutionError("transport URL must not contain user information")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ReplayExecutionError("transport URL hostname is invalid") from exc
    display = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    authority = display if port in {None, default} else f"{display}:{port}"
    return scheme, authority, port


def _origin(value: str) -> str:
    scheme, authority, _port = _canonical_authority(value)
    return f"{scheme}://{authority}"


def _redacted_url(value: str) -> str:
    # Validate the authority first so redaction never turns malformed transport output into
    # apparently valid evidence. The shared redactor then removes query values, userinfo, and
    # likely credentials/signatures embedded in path segments.
    _canonical_authority(value)
    return redact_url(value)


def _effective_lease_seconds(*, lease_seconds: int, timeout_seconds: float) -> int:
    if isinstance(lease_seconds, bool):
        raise ReplayExecutionError("lease_seconds must be a positive integer")
    try:
        requested = int(lease_seconds)
    except (TypeError, ValueError) as exc:
        raise ReplayExecutionError("lease_seconds must be a positive integer") from exc
    if requested <= 0:
        raise ReplayExecutionError("lease_seconds must be a positive integer")
    one_wire_attempt = math.ceil(float(timeout_seconds) + 0.5) + REPLAY_LEASE_SAFETY_SECONDS
    return max(requested, MIN_REPLAY_LEASE_SECONDS, one_wire_attempt)


def _response_headers(value: Mapping[str, str]) -> dict[str, str]:
    headers = dict(value or {})
    if len(headers) > MAX_REPLAY_RESPONSE_HEADERS:
        raise ReplayExecutionError("transport returned too many response headers")
    normalized: dict[str, str] = {}
    for raw_name, raw_value in headers.items():
        name = str(raw_name or "").strip()
        item = str(raw_value or "")
        if not _HEADER_NAME_RE.fullmatch(name):
            raise ReplayExecutionError("transport returned an invalid response header name")
        if "\r" in item or "\n" in item:
            raise ReplayExecutionError("transport returned a response header with line breaks")
        normalized[name] = item[:8_192]
    return normalized


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
        error = str(self.error_code or "").strip().lower() or None
        if error is not None and not _ERROR_RE.fullmatch(error):
            raise ReplayExecutionError("transport error_code is invalid")
        if self.timed_out and error is None:
            error = "timeout"
        address = None
        if self.connected_address:
            try:
                address = str(ipaddress.ip_address(self.connected_address))
            except ValueError as exc:
                raise ReplayExecutionError("transport connected_address is invalid") from exc
        object.__setattr__(self, "status_code", int(self.status_code) if self.status_code else None)
        object.__setattr__(self, "connected_address", address)
        object.__setattr__(self, "response_headers", _response_headers(self.response_headers))
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
    """Verify target pinning without misclassifying a pre-connect failure as scope escape."""
    if result.connected_address is None:
        if not result.error_code or result.status_code is not None:
            raise ReplayExecutionError(
                "transport omitted connected_address for a completed HTTP exchange"
            )
        if result.response_headers or result.response_body:
            raise ReplayExecutionError(
                "pre-connect transport failure cannot contain an HTTP response"
            )
    elif result.connected_address not in set(target.allowed_addresses):
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


def replay_reservation_budget(
    plan: ReplayPlan, additional_budget: Mapping[str, int] | None = None,
) -> dict[str, int]:
    """Return the complete trusted reservation for one replay action.

    The plan owns wire-request dimensions.  A production owner may add orthogonal
    dimensions such as ``agent_actions`` and ``tool_wall_seconds``; overlapping a
    plan-owned dimension is rejected so the control plane cannot weaken exact replay
    accounting by replacing the request count.
    """
    requested = dict(plan.estimated_budget)
    for raw_dimension, raw_amount in dict(additional_budget or {}).items():
        dimension = str(raw_dimension or "").strip()
        if dimension in requested:
            raise ReplayExecutionError(
                f"additional replay budget overlaps plan dimension: {dimension}"
            )
        if isinstance(raw_amount, bool):
            raise ReplayExecutionError(
                f"additional replay budget for {dimension} must be an integer"
            )
        try:
            amount = int(raw_amount)
        except (TypeError, ValueError) as exc:
            raise ReplayExecutionError(
                f"additional replay budget for {dimension} must be an integer"
            ) from exc
        if amount <= 0:
            raise ReplayExecutionError(
                f"additional replay budget for {dimension} must be positive"
            )
        requested[dimension] = amount
    return requested


def _settled_budget(
    plan: ReplayPlan,
    attempted: int,
    *,
    requested: Mapping[str, int],
    started_at: datetime,
    finished_at: datetime,
) -> dict[str, int]:
    actual = _actual_budget(plan, attempted)
    plan_dimensions = set(plan.estimated_budget)
    elapsed_seconds = max(
        0,
        math.ceil((finished_at - started_at).total_seconds()),
    )
    for dimension, amount in requested.items():
        if dimension in plan_dimensions:
            continue
        actual[dimension] = (
            min(int(amount), elapsed_seconds)
            if dimension == "tool_wall_seconds"
            else int(amount)
        )
    return actual


def _normalize_receipt_context(value: Mapping[str, Any] | None) -> dict[str, Any]:
    context = dict(value or {})
    if not context:
        return {}
    profile_ref = str(context.get("principal_profile_ref") or "").strip()
    principal_slot = str(context.get("principal_slot") or "").strip().lower()
    try:
        profile_version = int(context.get("principal_profile_version") or 0)
    except (TypeError, ValueError) as exc:
        raise ReplayExecutionError("principal receipt profile version is invalid") from exc
    if not profile_ref or len(profile_ref) > 200 or profile_version < 1:
        raise ReplayExecutionError("principal receipt profile binding is invalid")
    if principal_slot not in {"primary", "secondary", "service"}:
        raise ReplayExecutionError("principal receipt slot is invalid")
    return {
        "principal_profile_ref": profile_ref,
        "principal_profile_version": profile_version,
        "principal_slot": principal_slot,
    }


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
    receipt_context: Mapping[str, Any] | None,
) -> CapabilityReceipt:
    redacted_execution = plan.public_dict()
    redacted_execution.update(_normalize_receipt_context(receipt_context))
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
        redacted_execution=redacted_execution,
        budget_reservation_id=reservation.reservation_id,
        budget_reservation_state=reservation_state,
        budget_reserved=reservation.requested,
        budget_consumed=actual,
        observations=tuple(observations),
        errors=tuple(errors),
    )


async def _send_with_worker_deadline(
    transport: ReplayTransport,
    request: ReplayRequest,
    *,
    target: TargetBinding,
    timeout_seconds: float,
) -> ReplayTransportResult:
    """Apply a worker-owned wall deadline in addition to transport socket timeouts."""
    try:
        return await asyncio.wait_for(
            transport.send(
                request,
                target=target,
                timeout_seconds=timeout_seconds,
                follow_redirects=False,
            ),
            timeout=timeout_seconds + 0.5,
        )
    except asyncio.TimeoutError:
        return ReplayTransportResult(
            status_code=None,
            connected_address=None,
            final_url=request.url,
            response_headers={},
            response_body=b"",
            elapsed_ms=max(1, math.ceil(timeout_seconds * 1_000)),
            error_code="worker_timeout",
            timed_out=True,
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
    require_durable_persistence: bool = False,
    additional_budget: Mapping[str, int] | None = None,
    initial_reservation: DurableBudgetReservation | None = None,
    receipt_context: Mapping[str, Any] | None = None,
) -> ReplayExecutionOutcome:
    """Execute one exact ReplayPlan with reserve-before-send accounting.

    Production call sites should set ``require_durable_persistence=True`` and provide callbacks
    that persist each immutable reservation version and the terminal receipt/ledger update in the
    owning datastore transaction. The false default is retained only for isolated adapter tests
    until the production replay job handler is switched to the durable repository.
    """
    if owner_kind not in {"scan", "hunt"}:
        raise ReplayExecutionError("owner_kind must be scan or hunt")
    owner = str(owner_id or "").strip()
    worker = str(worker_id or "").strip()
    if not owner or not worker:
        raise ReplayExecutionError("owner_id and worker_id are required")
    if isinstance(timeout_seconds, bool) or not 0.1 <= float(timeout_seconds) <= 300:
        raise ReplayExecutionError("timeout_seconds must be between 0.1 and 300")
    if require_durable_persistence and (
        on_reservation is None or on_settlement is None
    ):
        raise ReplayExecutionError(
            "durable replay requires reservation and settlement persistence callbacks"
        )
    receipt_context = _normalize_receipt_context(receipt_context)
    _validate_runtime_binding(plan, target)
    effective_lease = _effective_lease_seconds(
        lease_seconds=lease_seconds,
        timeout_seconds=float(timeout_seconds),
    )

    requested_budget = replay_reservation_budget(plan, additional_budget)
    if initial_reservation is None:
        now = _utc(clock)
        requested = DurableBudgetReservation.request(
            owner_kind=owner_kind,
            owner_id=owner,
            capability_name="collections.replay",
            amounts=requested_budget,
            now=now,
            reservation_id=reservation_id,
        )
        await _invoke(on_reservation, requested, dict(consumed))
    else:
        requested = initial_reservation
        if (
            requested.status not in {"requested", "reserved"}
            or requested.owner_kind != owner_kind
            or requested.owner_id != owner
            or requested.capability_name != "collections.replay"
            or dict(requested.requested) != requested_budget
            or (reservation_id is not None and requested.reservation_id != reservation_id)
        ):
            raise ReplayExecutionError(
                "pre-created replay reservation does not match the execution action"
            )
    if requested.status == "reserved":
        # The owner row and reservation were atomically held before the worker was
        # dispatched. ``consumed`` is therefore the ledger snapshot after that hold.
        reserved = requested
        held_ledger = dict(consumed)
    else:
        reserved, held_ledger = requested.reserve_against(
            limits=limits,
            consumed=consumed,
            now=_utc(clock),
            lease_seconds=effective_lease,
        )
        await _invoke(on_reservation, reserved, held_ledger)
    running = reserved.start(
        worker_id=worker,
        now=_utc(clock),
        lease_seconds=effective_lease,
    )
    await _invoke(on_reservation, running, held_ledger)

    started_at = running.started_at or _utc(clock)
    observations: list[Mapping[str, Any]] = []
    errors: list[str] = []
    attempted = 0
    any_timeout = False
    try:
        for index, request in enumerate(plan.requests):
            attempted += 1  # Charge conservatively before the target may receive bytes.
            result = await _send_with_worker_deadline(
                transport,
                request,
                target=target,
                timeout_seconds=float(timeout_seconds),
            )
            if not isinstance(result, ReplayTransportResult):
                raise ReplayExecutionError("transport returned an invalid result type")
            _validate_transport_result(result, plan=plan, target=target)
            observations.append(_observation(request, result))
            if result.error_code:
                errors.append(f"{request.request_id}:{result.error_code}")
            any_timeout = any_timeout or result.timed_out
            if index + 1 < len(plan.requests):
                running = running.heartbeat(
                    worker_id=worker,
                    now=_utc(clock),
                    lease_seconds=effective_lease,
                )
                await _invoke(on_reservation, running, held_ledger)
    except asyncio.CancelledError:
        finished_at = _utc(clock)
        actual = _settled_budget(
            plan, attempted, requested=requested.requested,
            started_at=started_at, finished_at=finished_at,
        )
        receipt = _receipt(
            plan=plan, target=target, owner_kind=owner_kind, owner_id=owner,
            worker_id=worker, reservation=running, reservation_state="failed",
            actual=actual, status="partial", partial=True, timed_out=False,
            started_at=started_at, finished_at=finished_at,
            observations=observations, errors=(*errors, "execution_cancelled"),
            receipt_id=receipt_id, receipt_context=receipt_context,
        )
        failed = running.fail(
            reason="execution_cancelled", now=finished_at, actual=actual,
            execution_receipt_hash=receipt.receipt_hash, execution_may_have_started=True,
        )
        settled = failed.reconcile_consumed(held_ledger)
        if on_settlement is not None:
            await asyncio.shield(_invoke(on_settlement, failed, receipt, settled))
        raise
    except Exception as exc:
        finished_at = _utc(clock)
        actual = _settled_budget(
            plan, attempted, requested=requested.requested,
            started_at=started_at, finished_at=finished_at,
        )
        error_code = f"executor_{type(exc).__name__.lower()}"[:120]
        partial = attempted > 0
        receipt = _receipt(
            plan=plan, target=target, owner_kind=owner_kind, owner_id=owner,
            worker_id=worker, reservation=running, reservation_state="failed",
            actual=actual, status="partial" if partial else "failed", partial=partial,
            timed_out=False, started_at=started_at, finished_at=finished_at,
            observations=observations, errors=(*errors, error_code), receipt_id=receipt_id,
            receipt_context=receipt_context,
        )
        failed = running.fail(
            reason=error_code, now=finished_at, actual=actual,
            execution_receipt_hash=receipt.receipt_hash,
            execution_may_have_started=attempted > 0,
        )
        settled = failed.reconcile_consumed(held_ledger)
        await _invoke(on_settlement, failed, receipt, settled)
        return ReplayExecutionOutcome(receipt.status, failed, receipt, settled)

    finished_at = _utc(clock)
    actual = _settled_budget(
        plan, attempted, requested=requested.requested,
        started_at=started_at, finished_at=finished_at,
    )
    partial = bool(errors)
    receipt = _receipt(
        plan=plan, target=target, owner_kind=owner_kind, owner_id=owner,
        worker_id=worker, reservation=running, reservation_state="committed",
        actual=actual, status="partial" if partial else "succeeded", partial=partial,
        timed_out=any_timeout, started_at=started_at, finished_at=finished_at,
        observations=observations, errors=errors, receipt_id=receipt_id,
        receipt_context=receipt_context,
    )
    committed = running.commit(
        actual=actual,
        execution_receipt_hash=receipt.receipt_hash,
        now=finished_at,
        worker_id=worker,
    )
    settled = committed.reconcile_consumed(held_ledger)
    await _invoke(on_settlement, committed, receipt, settled)
    return ReplayExecutionOutcome(receipt.status, committed, receipt, settled)
