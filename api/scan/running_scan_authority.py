"""Re-check target authorization while a Scan that is not an action graph runs.

Connected-device scans (posture and service probes, with their device web children) and AI
scans run as one piece of work rather than as canonical actions, so the action executor never
re-checked their authorization once they started. ``RunningScanAuthority`` gives them the same
decision (``ScanAuthorityGuard``) with the same deadlines (``authority_deadline``) as an action:

* before the work starts the full check runs, fail-closed and time-bounded; a denial refuses
  the run (``ScanAuthorityStopped``) before any traffic;
* while it runs the guard is polled; a revoke, an expiry or a deactivated target records the
  interruption, which the run's existing stop checks observe (``action_interrupted``), so the
  scanner stops as it does on a user cancel. Work that does not stop on its own within
  ``HARD_STOP_GRACE_SECONDS`` is cancelled. A database that cannot be reached, or does not
  answer, for the tolerance stops the run as ``authorization_unverified``, never as a revoke;
* a run that returns after the stop keeps what it found, reads partial and names the stop
  (``annotate``); one that ends with an error or is cancelled raises ``ScanAuthorityStopped``
  with the reason, so the Scan fails naming its authorization rather than a user cancel.

Only receipts the run was admitted with are re-checked: the target's standing authorization
(``asset_authorization_receipt_id``) or an approval receipt bound at submission
(``approval_receipt_id``). A run admitted without any receipt has no revocable authorization
and is not watched, as a passive local Scan without a receipt continues after a revoke.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
import urllib.parse
import uuid

try:  # Preserve one class identity for host package imports.
    from ..runtime.models import TargetBinding
except (ImportError, ModuleNotFoundError):  # top-level worker imports
    from runtime.models import TargetBinding

from .action_authority_guard import ScanAuthorityGuard
from .action_interruption import ActionInterruption, interruption_scope
from .authority_deadline import UNVERIFIED, check_before_start, stop_task, watch_authorization


# How long a stopped run may take to wind down through its own stop checks before it is
# cancelled outright.
HARD_STOP_GRACE_SECONDS = 5.0

# What each run does to its target, as the capability whose approval rule applies to it.
_RUN_CAPABILITIES: Mapping[str, tuple[str, Mapping[str, Any]]] = {
    "device_posture": ("device.scan", {}),
    "device_probe": ("device.service.verify", {}),
    # AI scans send their prompts as POST requests to the model endpoint.
    **{kind: ("http.request", {"method": "POST"})
       for kind in ("ai_api", "ai_rag", "ai_trace", "ai_mcp", "ai_widget")},
}


@dataclass(frozen=True)
class RunAuthorityAction:
    """The whole run, checked as one action."""

    capability_name: str
    capability_input: Mapping[str, Any] = field(default_factory=dict)
    action_id: str = "scan.run"


class ScanAuthorityStopped(ValueError):
    """The run's authorization was refused before it started, or withdrawn while it ran."""

    def __init__(self, reason: str, *, before_start: bool) -> None:
        self.reason = reason
        self.before_start = before_start
        when = "before it started" if before_start else "while it ran"
        super().__init__(f"Scan stopped {when}: target authorization check returned {reason}")


class RunningScanAuthority:
    """``async with`` around a run: checked before it starts and polled while it runs."""

    def __init__(self, guard: ScanAuthorityGuard | None, action: RunAuthorityAction | None, *,
                 grace_seconds: float = HARD_STOP_GRACE_SECONDS) -> None:
        self.guard = guard if action is not None else None
        self.action = action
        self.grace_seconds = grace_seconds
        self.reason: str | None = None
        self._signal = ActionInterruption()
        self._scope: Any = None
        self._timeout: Any = None
        self._stopped = asyncio.Event()
        self._monitor: asyncio.Task[Any] | None = None

    async def __aenter__(self) -> "RunningScanAuthority":
        if self.guard is None:
            return self
        denial, confirmed_at = await check_before_start(self.guard, self.action)
        if denial is not None:
            raise ScanAuthorityStopped(denial, before_start=True)
        self._scope = interruption_scope(self._signal)
        self._scope.__enter__()
        self._timeout = asyncio.timeout(None)
        await self._timeout.__aenter__()
        self._monitor = asyncio.create_task(watch_authorization(
            self.guard, self.action, confirmed_at=confirmed_at, stopped=self._stopped,
            signal=self._signal, on_interrupt=self._interrupted))
        return self

    def _interrupted(self, reason: str) -> None:
        self.reason = reason
        # The run's stop checks see the signal; work that ignores them is cancelled after the
        # grace. ``asyncio.timeout`` owns the cancellation, so nothing else is cancelled.
        self._timeout.reschedule(asyncio.get_running_loop().time() + self.grace_seconds)

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if self.guard is None:
            return False
        self._stopped.set()
        await stop_task(self._monitor)
        try:
            await self._timeout.__aexit__(exc_type, exc, tb)
        except TimeoutError:
            raise ScanAuthorityStopped(self.reason or UNVERIFIED, before_start=False) from None
        finally:
            self._scope.__exit__(None, None, None)
        if self.reason is not None and exc is not None and isinstance(exc, Exception):
            # A scanner that ends its stop with an error (the device scanners raise "cancelled
            # before <stage>") was stopped by its authorization, not by a user cancel.
            raise ScanAuthorityStopped(self.reason, before_start=False) from exc
        return False

    async def annotate(self, result: dict[str, Any], *, scan_id: str) -> dict[str, Any]:
        """Mark a run that stopped on its authorization: partial, with the reason."""
        if self.guard is None or self.reason is None or not isinstance(result, dict):
            return result
        return await self.guard.annotate(result, scan_id=scan_id, interrupted=self.reason,
                                         interrupted_action=self.action.action_id)


async def running_scan_authority(
    pool: Any,
    *,
    options: Mapping[str, Any],
    device_target_id: str | None = None,
    ai_target_id: str | None = None,
    record_event: Callable[[str], Any] | None = None,
    **guard_kwargs: Any,
) -> RunningScanAuthority:
    """The authority for one device or AI run, or an unwatched one when nothing is revocable."""
    run_kind = str(options.get("run_kind") or "")
    capability = _RUN_CAPABILITIES.get(run_kind)
    asset_id = device_target_id if run_kind.startswith("device_") else ai_target_id
    approval_id = _uuid(options.get("asset_authorization_receipt_id")) or _uuid(options.get("approval_receipt_id"))
    if capability is None or _uuid(asset_id) is None or approval_id is None:
        return RunningScanAuthority(None, None)
    async with pool.acquire() as conn:
        scope_id = str(options.get("scope_receipt_id") or "").strip() or str(await conn.fetchval(
            "SELECT scope_receipt_id FROM approval_receipts WHERE id=$1", approval_id) or "") or None
        host = await _asset_host(conn, run_kind, uuid.UUID(str(asset_id)))
    binding = TargetBinding(
        target_id=str(asset_id), target_kind="device" if run_kind.startswith("device_") else "api",
        canonical_host=host or "unresolved.invalid", scope_receipt_id=scope_id,
    )
    guard = ScanAuthorityGuard(pool=pool, target_binding=binding, scope_receipt_id=scope_id,
                               approval_receipt_id=str(approval_id), record_event=record_event,
                               **guard_kwargs)
    return RunningScanAuthority(guard, RunAuthorityAction(capability[0], dict(capability[1])))


async def _asset_host(conn: Any, run_kind: str, asset_id: uuid.UUID) -> str | None:
    """The host the run was admitted against, derived as the authorization gate derives it."""
    if run_kind.startswith("device_"):
        try:
            from ..target_authorization import TargetAuthorizationError, evaluate_target_scope
        except (ImportError, ModuleNotFoundError):
            from target_authorization import TargetAuthorizationError, evaluate_target_scope
        try:
            return (await evaluate_target_scope(conn, asset_id)).get("host") or None
        except TargetAuthorizationError:
            return None  # the device is gone: the check refuses the run as out of scope
    endpoint = await conn.fetchval("SELECT endpoint_url FROM ai_targets WHERE id=$1", asset_id)
    return urllib.parse.urlsplit(str(endpoint or "")).hostname


def _uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value)) if value else None
    except (TypeError, ValueError, AttributeError):
        return None
