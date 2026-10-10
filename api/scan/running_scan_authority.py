"""Re-check target authorization while a Scan that is not an action graph runs.

Connected-device scans (posture and service probes, with their device web children) and AI
scans run as one piece of work rather than as canonical actions, so the action executor never
re-checked their authorization once they started. ``RunningScanAuthority`` re-checks them with
the guard's machinery (``ScanAuthorityGuard``: a cheap poll, a full check when something
changed) and the same deadlines (``authority_deadline``) as an action:

* before the work starts the check runs, fail-closed and time-bounded; a denial refuses the run
  (``ScanAuthorityStopped``) before any traffic;
* while it runs the guard is polled; a stop is recorded on the interruption signal, which the
  run's existing stop checks observe (``action_interrupted``), so the scanner stops as it does
  on a user cancel. Work that does not stop on its own within ``HARD_STOP_GRACE_SECONDS`` is
  cancelled. A database that cannot be reached, or does not answer, for the tolerance stops the
  run as ``authorization_unverified``, never as a revoke;
* a run that returns after the stop keeps what it found, reads partial and names the stop
  (``annotate``); one that ends with an error or is cancelled raises ``ScanAuthorityStopped``
  carrying a report that names the stop, so the Scan fails naming its authorization rather
  than a user cancel or a validation error.

What is re-checked is what admission checked for these runs, not the canonical action rules:
they were admitted without requiring an expiry on a per-scan approval or binding its scope to
the target's standing receipt, so the re-check requires neither (``admitted_authority_reason``).
Each receipt the run was admitted with is watched against its own scope: the target's standing
authorization (``asset_authorization_receipt_id``, device posture scans) and the approval
receipt bound at submission (``approval_receipt_id``), both when both are present. Reasons:
``authorization_revoked`` only for a revoked receipt, ``authorization_expired`` only for an
expiry that was set and passed, ``scope_invalid`` for a deactivated target, a blocked scope, a
target host the scope no longer covers, a standing receipt the target no longer stands behind,
or a receipt that no longer exists.

Which runs are watched: only runs admitted with at least one receipt. A device probe or a
``confirm_authorized`` posture scan submitted without a standing authorization or an approval
receipt, and an AI scan submitted without an approval receipt, have no revocable authorization
and are not re-checked while they run, as a passive local Scan without a receipt is not.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Any, Callable, Mapping
import urllib.parse
import uuid

from .action_authority_guard import ScanAuthorityGuard
from .action_interruption import ActionInterruption, interruption_scope
from .authority_deadline import UNVERIFIED, check_before_start, stop_task, watch_authorization
from .authorization import ActionAuthorityDecision
from .capability_result import CapabilityResultReason


# How long a stopped run may take to wind down through its own stop checks before it is
# cancelled outright.
HARD_STOP_GRACE_SECONDS = 5.0

_RUN_KINDS = frozenset({"device_posture", "device_probe",
                        "ai_api", "ai_rag", "ai_trace", "ai_mcp", "ai_widget"})
_SCOPE = CapabilityResultReason.SCOPE_INVALID.value


@dataclass(frozen=True)
class RunAuthorityAction:
    """The whole run, checked as one action."""

    run_kind: str
    action_id: str = "scan.run"


@dataclass(frozen=True)
class _RunTarget:
    target_id: str


class ScanAuthorityStopped(ValueError):
    """The run's authorization was refused before it started, or withdrawn while it ran.

    ``report`` is the Scan result to record for a run that did not return: no findings, and its
    coverage and metadata name the authorization stop.
    """

    def __init__(self, reason: str, *, before_start: bool) -> None:
        self.reason = reason
        self.before_start = before_start
        when = "before it started" if before_start else "while it ran"
        super().__init__(f"Scan stopped {when}: target authorization check returned {reason}")
        self.report: dict[str, Any] = {"error": str(self), "findings": [],
                                       "result": {"score": None, "grade": None}}


def _row(value: Any) -> dict[str, Any]:
    return dict(value) if value is not None else {}


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    return value


def _canonical_host(value: Any) -> str:
    host = str(value or "").strip().strip("[]").lower().rstrip(".")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _host_in_admitted_scope(host: str, scope: Mapping[str, Any]) -> bool:
    """The admission rule (``_host_matches_receipt_scope``): normalized host, hosts or roots."""
    candidate = _canonical_host(host)
    if not candidate:
        return False
    normalized = _json(scope.get("normalized_scope")) or {}
    if isinstance(normalized, dict) and candidate == _canonical_host(normalized.get("host")):
        return True
    hosts = _json(scope.get("allowed_hosts")) or []
    if any(candidate == _canonical_host(item) for item in (hosts if isinstance(hosts, list) else [])):
        return True
    roots = _json(scope.get("allowed_root_domains")) or []
    for root in roots if isinstance(roots, list) else []:
        root_host = _canonical_host(root)
        if root_host and (candidate == root_host or candidate.endswith("." + root_host)):
            return True
    return False


async def _asset_state(conn: Any, run_kind: str, asset_id: uuid.UUID) -> tuple[bool | None, str]:
    """``(is_active, host)`` of the device or AI target, its host parsed as admission parses it."""
    if run_kind.startswith("device_"):
        row = _row(await conn.fetchrow(
            "SELECT is_active, primary_locator AS locator FROM device_targets WHERE id=$1", asset_id))
    else:
        row = _row(await conn.fetchrow(
            "SELECT is_active, endpoint_url AS locator FROM ai_targets WHERE id=$1", asset_id))
    locator = str(row.get("locator") or "")
    parsed = urllib.parse.urlparse(locator if "://" in locator else f"https://{locator}")
    return row.get("is_active"), parsed.hostname or ""


async def _standing_still_current(conn: Any, asset_id: uuid.UUID, approval_id: uuid.UUID) -> bool:
    try:
        from ..target_authorization import standing_authorization_is_current
        from ..devices.network_authorization import network_authorization_snapshot
    except (ImportError, ModuleNotFoundError):
        from target_authorization import standing_authorization_is_current
        from devices.network_authorization import network_authorization_snapshot
    if await standing_authorization_is_current(conn, asset_id, approval_id):
        return True
    # Admission accepted the receipt the asset's current authorization resolves to, which may
    # be inherited from another asset.
    snapshot = await network_authorization_snapshot(conn, asset_id)
    return bool(snapshot) and snapshot.get("approval_receipt_id") == str(approval_id)


async def admitted_authority_reason(
    conn: Any,
    *,
    action: RunAuthorityAction,
    target_binding: Any,
    scope_receipt_id: str | None,
    approval_receipt_id: str | None,
    standing: bool,
) -> tuple[str | None, ActionAuthorityDecision | None]:
    """``(None, None)`` while the receipt still holds as admission accepted it, else a reason.

    The ``ScanAuthorityGuard.decide`` for these runs. It reads the receipt's own scope (not one
    from the Scan options) and the asset's current host, so a revoke, an expiry that was set, a
    deactivated asset or a host the scope no longer covers stops the run.
    """
    asset_id = uuid.UUID(str(target_binding.target_id))
    active, host = await _asset_state(conn, action.run_kind, asset_id)
    if active is not True:
        return _SCOPE, ActionAuthorityDecision.REJECTED_SCOPE
    approval_id = uuid.UUID(str(approval_receipt_id))
    approval = _row(await conn.fetchrow(
        "SELECT status, revoked_at, expires_at, scope_receipt_id FROM approval_receipts WHERE id=$1",
        approval_id))
    if not approval:
        return _SCOPE, ActionAuthorityDecision.REJECTED_MISSING
    if str(approval.get("status") or "").lower() == "revoked" or approval.get("revoked_at") is not None:
        return CapabilityResultReason.AUTHORIZATION_REVOKED.value, ActionAuthorityDecision.REJECTED_REVOKED
    expires_at = approval.get("expires_at")
    if isinstance(expires_at, datetime):
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            return CapabilityResultReason.AUTHORIZATION_EXPIRED.value, ActionAuthorityDecision.REJECTED_EXPIRED
    scope = _row(await conn.fetchrow(
        "SELECT verdict, normalized_scope, allowed_hosts, allowed_root_domains FROM scope_receipts WHERE id=$1",
        str(approval.get("scope_receipt_id") or "")))
    if not scope:
        return _SCOPE, ActionAuthorityDecision.REJECTED_MISSING
    if str(scope.get("verdict") or "") == "blocked" or not _host_in_admitted_scope(host, scope):
        return _SCOPE, ActionAuthorityDecision.REJECTED_SCOPE
    if standing and not await _standing_still_current(conn, asset_id, approval_id):
        return _SCOPE, ActionAuthorityDecision.REJECTED_SCOPE
    return None, None


class _Receipts:
    """Every receipt a run was admitted with, checked together; the first stop wins."""

    def __init__(self, guards: list[ScanAuthorityGuard]) -> None:
        self.guards = guards
        first = guards[0]
        self.poll_seconds = first.poll_seconds
        self.unverified_after_seconds = first.unverified_after_seconds
        self.check_retry_delays = first.check_retry_delays

    @property
    def withdrawn(self) -> bool:
        return any(guard.withdrawn for guard in self.guards)

    async def check(self, action: Any) -> str | None:
        for guard in self.guards:
            reason = await guard.check(action)
            if reason is not None:
                return reason
        return None

    async def poll(self, action: Any) -> str | None:
        for guard in self.guards:
            reason = await guard.poll(action)
            if reason is not None:
                return reason
        return None

    async def annotate(self, report: dict[str, Any], *, interrupted: str, interrupted_action: str) -> dict[str, Any]:
        guard = next((item for item in self.guards if item.withdrawn), self.guards[0])
        return await guard.annotate(report, scan_id="", interrupted=interrupted,
                                    interrupted_action=interrupted_action, record_not_run=False)


class RunningScanAuthority:
    """``async with`` around a run: checked before it starts and polled while it runs."""

    def __init__(self, guard: _Receipts | None, action: RunAuthorityAction | None, *,
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

    async def _stopped_error(self, reason: str, *, before_start: bool) -> ScanAuthorityStopped:
        self.reason = reason
        error = ScanAuthorityStopped(reason, before_start=before_start)
        error.report = await self.annotate(error.report, scan_id="")
        return error

    async def __aenter__(self) -> "RunningScanAuthority":
        if self.guard is None:
            return self
        denial, confirmed_at = await check_before_start(self.guard, self.action)
        if denial is not None:
            raise await self._stopped_error(denial, before_start=True)
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
            raise await self._stopped_error(self.reason or UNVERIFIED, before_start=False) from None
        finally:
            self._scope.__exit__(None, None, None)
        if self.reason is not None and exc is not None and isinstance(exc, Exception):
            # A scanner that ends its stop with an error (the device scanners raise "cancelled
            # before <stage>") was stopped by its authorization, not by a user cancel.
            raise await self._stopped_error(self.reason, before_start=False) from exc
        return False

    async def annotate(self, result: dict[str, Any], *, scan_id: str) -> dict[str, Any]:
        """Mark a run that stopped on its authorization: partial, with the reason."""
        if self.guard is None or self.reason is None or not isinstance(result, dict):
            return result
        return await self.guard.annotate(result, interrupted=self.reason,
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
    """The authority for one device or AI run, or an unwatched one when nothing is revocable.

    Reads nothing: every database read happens in the bounded check before the run starts.
    """
    run_kind = str(options.get("run_kind") or "")
    asset_id = _uuid(device_target_id if run_kind.startswith("device_") else ai_target_id)
    receipts: list[tuple[uuid.UUID, bool]] = []
    standing = _uuid(options.get("asset_authorization_receipt_id")) if run_kind.startswith("device_") else None
    if standing is not None:
        receipts.append((standing, True))
    approval = _uuid(options.get("approval_receipt_id"))
    if approval is not None and approval != standing:
        receipts.append((approval, False))
    if run_kind not in _RUN_KINDS or asset_id is None or not receipts:
        return RunningScanAuthority(None, None)

    def decide(is_standing: bool):
        async def reason(conn: Any, **kwargs: Any):
            return await admitted_authority_reason(conn, standing=is_standing, **kwargs)
        return reason

    guards = [
        ScanAuthorityGuard(pool=pool, target_binding=_RunTarget(str(asset_id)), scope_receipt_id=None,
                           approval_receipt_id=str(receipt), record_event=record_event,
                           decide=decide(is_standing), **guard_kwargs)
        for receipt, is_standing in receipts
    ]
    return RunningScanAuthority(_Receipts(guards), RunAuthorityAction(run_kind))


def _uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value)) if value else None
    except (TypeError, ValueError, AttributeError):
        return None
