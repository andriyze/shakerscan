"""Canonical receipt-producing action driver shared by local and broker workers."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping, Protocol

try:  # Preserve one class identity for host package imports.
    from ..runtime.receipts import CapabilityReceipt
except (ImportError, ModuleNotFoundError):  # top-level worker imports
    from runtime.receipts import CapabilityReceipt

from .action_plan import ScanAction
from .capability_result import CapabilityResultReference, CapabilityResultReason
from .execution_backend import ActionAuthorityWithdrawn, ActionHeartbeat, ActionLease
from .action_interruption import ActionInterruption, interruption_scope
from .authority_deadline import (  # noqa: F401  (the tolerance constants are re-exported)
    AUTHORITY_CHECK_RETRY_DELAYS,
    AUTHORITY_UNVERIFIED_AFTER_SECONDS,
    check_before_start,
    stop_task,
    watch_authorization,
)


class WorkerActionExecutionError(RuntimeError):
    """A worker dispatcher did not return a canonical action receipt."""


ActionDispatcher = Callable[
    [ScanAction, ActionLease, ActionHeartbeat],
    Awaitable[CapabilityReceipt | Mapping[str, Any]],
]


class ActionAuthority(Protocol):
    """Target authorization re-checked around each action (``action_authority_guard``).

    ``check`` runs before dispatch and ``poll`` every ``poll_seconds`` while the action runs;
    each returns ``None`` while authorized, else a ``CapabilityResultReason`` value, and raises
    when it cannot tell.
    """

    poll_seconds: float

    async def check(self, action: ScanAction) -> str | None: ...

    async def poll(self, action: ScanAction) -> str | None: ...


def with_authority_interruption(receipt: CapabilityReceipt, reason: str, observed_at: str | None) -> CapabilityReceipt:
    """The receipt of an action whose target authorization was withdrawn while it ran.

    What it observed before the stop is kept; the receipt is partial and names ``reason`` first.
    A stop the receipt already reported (a fleet node's own) is kept as
    ``reported_target_authority_interruption``; ``target_authority_interruption`` is always
    this decision, so a receipt cannot pre-empt it by naming a stop of its own.
    """
    stopped = {"reason_code": reason, "observed_at": observed_at}
    execution = dict(receipt.redacted_execution)
    reported = execution.pop("target_authority_interruption", None)
    if reported is not None and reported != stopped:
        execution["reported_target_authority_interruption"] = reported
    return replace(receipt, status="partial", partial=True,
        errors=(reason, *tuple(error for error in receipt.errors if error not in {"cancelled", reason})),
        observations=(*receipt.observations, {"kind": "target_authority_interruption", **stopped}),
        redacted_execution={**execution, "target_authority_interruption": stopped})


class ReceiptScanActionExecutor:
    """Turn canonical capability dispatch into lease-bound receipts.

    The dispatcher is the sole placement-specific seam.  Both local and broker
    workers use this class above the same capability adapters and registry.
    """

    def __init__(
        self,
        *,
        scan_id: str,
        target_id: str,
        worker_id: str,
        dispatcher: ActionDispatcher,
        scope_receipt_id: str | None = None,
        approval_receipt_id: str | None = None,
        credential_check: Callable[[ScanAction], Awaitable[str | None]] | None = None,
        user_cancelled: Callable[[], bool] = lambda: False,
        authority: ActionAuthority | None = None,
    ) -> None:
        self._scan_id = str(scan_id)
        self._target_id = str(target_id)
        self._worker_id = str(worker_id)
        self._dispatcher = dispatcher
        self._scope_receipt_id = scope_receipt_id
        self._approval_receipt_id = approval_receipt_id
        self._credential_check = credential_check
        self._user_cancelled = user_cancelled
        self._authority = authority

    async def execute(
        self,
        action: ScanAction,
        lease: ActionLease,
        heartbeat: ActionHeartbeat,
    ) -> CapabilityReceipt:
        stop_heartbeats = asyncio.Event()

        signal = ActionInterruption()
        authority_interruption: str | None = None

        async def guarded_heartbeat() -> bool:
            """Heartbeat the lease; ``False`` once the control plane withdrew the authorization.

            A withdrawal stops the action as the authority monitor would (the tool sees
            ``action_interrupted``) and its receipt is settled as an authorization stop. It is
            never raised into the adapter, which would turn it into an adapter failure.
            """
            nonlocal authority_interruption
            try:
                await heartbeat()
                return True
            except ActionAuthorityWithdrawn as exc:
                if signal.reason is None:
                    authority_interruption = exc.reason
                    signal.record(exc.reason)
                return False

        async def adapter_heartbeat() -> None:
            await guarded_heartbeat()

        async def keep_lease_alive() -> None:
            interval = max(1.0, min(30.0, float(lease.lease_seconds) / 3.0))
            while not stop_heartbeats.is_set():
                try:
                    await asyncio.wait_for(stop_heartbeats.wait(), timeout=interval)
                except asyncio.TimeoutError:
                    if not await guarded_heartbeat():
                        return

        heartbeat_task = asyncio.create_task(keep_lease_alive())
        monitor = None
        authority_monitor = None
        check = self._credential_check if action.action_id != "finalize.report" else None
        authority = self._authority if action.action_id != "finalize.report" else None

        async def check_authority():
            assert check is not None
            try:
                reason = await check(action)
                reason = CapabilityResultReason(reason).value if reason is not None else None
            except Exception:
                reason = CapabilityResultReason.AUTHENTICATION_UNCERTAIN.value
            signal.record(reason)
            return reason

        async def observe_authority():
            assert check is not None
            while not stop_heartbeats.is_set() and signal.reason is None:
                try:
                    await asyncio.wait_for(stop_heartbeats.wait(), timeout=0.5)
                except asyncio.TimeoutError:
                    await check_authority()

        def authorization_interrupted(reason: str) -> None:
            nonlocal authority_interruption
            authority_interruption = reason

        try:
            denial = None
            confirmed_at = 0.0
            if authority is not None:
                # Bounded in time as a whole (``authority_deadline``): a check that stalls is
                # cancelled at the deadline and the action is blocked, unverified.
                denial, confirmed_at = await check_before_start(authority, action)
            if denial is None and check is not None:
                denial = await check_authority()
            if denial is not None:
                reason = CapabilityResultReason(denial).value
                result = await self.terminal_without_execution(action, lease,
                    status="blocked", reason_code=reason, charge_full_reservation=False)
            else:
                with interruption_scope(signal):
                    if check is not None:
                        monitor = asyncio.create_task(observe_authority())
                    if authority is not None:
                        # The deadline runs from the last confirmation, and a poll that does
                        # not answer cannot hold the interruption back.
                        authority_monitor = asyncio.create_task(watch_authorization(
                            authority, action, confirmed_at=confirmed_at, stopped=stop_heartbeats,
                            signal=signal, on_interrupt=authorization_interrupted))
                    result = await self._dispatcher(action, lease, adapter_heartbeat)
                    if check is not None:
                        await check_authority()
        finally:
            stop_heartbeats.set()
            for task in (monitor, authority_monitor):
                await stop_task(task)
            await heartbeat_task
        if isinstance(result, CapabilityReceipt):
            receipt = result
        elif isinstance(result, Mapping):
            try:
                receipt = CapabilityReceipt.from_dict(result)
            except (TypeError, ValueError) as exc:
                raise WorkerActionExecutionError(
                    "worker dispatcher returned an invalid capability receipt"
                ) from exc
        else:
            raise WorkerActionExecutionError(
                "worker dispatcher must return a capability receipt"
            )
        if (
            receipt.scan_id != self._scan_id
            or receipt.target_id != self._target_id
            or receipt.worker_id != self._worker_id
            or receipt.input_digest != action.action_digest
            or receipt.capability_name != action.capability_name
            or receipt.adapter_name != str(action.placement.get("adapter_name") or "")
            or receipt.adapter_version != str(action.placement.get("adapter_version") or "")
            or dict(receipt.budget_reserved) != dict(action.requested_budget)
        ):
            raise WorkerActionExecutionError(
                "worker receipt differs from immutable action authority"
            )
        if authority_interruption is not None and signal.reason == authority_interruption and denial is None:
            # Authorization was withdrawn while the action ran: what it observed before the
            # stop is kept, and the receipt says it is partial and why.
            receipt = with_authority_interruption(receipt, authority_interruption, signal.observed_at)
        elif signal.reason is not None and denial is None and not self._user_cancelled():
            interruption = {"reason_code": signal.reason, "last_authority_check_at": signal.last_confirmed_at,
                "observed_at": signal.observed_at, "continuous_identity_proven": False}
            receipt = replace(receipt, status="partial", partial=True,
                errors=(signal.reason, *tuple(error for error in receipt.errors if error != "cancelled")),
                observations=(*receipt.observations, {"kind": "identity_authority_interruption", **interruption}),
                redacted_execution={**dict(receipt.redacted_execution), "identity_interruption": interruption})
        return receipt

    async def restore_terminal_state(
        self,
        action: ScanAction,
        result: CapabilityResultReference,
    ) -> bool:
        """Restore worker-private prerequisites without repeating target traffic."""
        restore = getattr(self._dispatcher, "restore_terminal_state", None)
        if restore is None:
            return True
        return bool(await restore(action, result))

    async def terminal_without_execution(
        self,
        action: ScanAction,
        lease: ActionLease,
        *,
        status: str,
        reason_code: str,
        charge_full_reservation: bool,
    ) -> CapabilityReceipt:
        now = datetime.now(timezone.utc).isoformat()
        consumed = (
            dict(action.requested_budget)
            if charge_full_reservation
            else {name: 0 for name in action.requested_budget}
        )
        return CapabilityReceipt(
            capability_name=action.capability_name,
            adapter_name=str(action.placement.get("adapter_name") or ""),
            adapter_version=str(action.placement.get("adapter_version") or ""),
            target_id=self._target_id,
            scan_id=self._scan_id,
            worker_id=self._worker_id,
            scope_receipt_id=self._scope_receipt_id,
            approval_receipt_id=self._approval_receipt_id,
            status=status,
            input_digest=str(action.action_digest),
            parser_version="scan-orchestrator/v1",
            started_at=now,
            finished_at=now,
            budget_reserved=action.requested_budget,
            budget_consumed=consumed,
            redacted_execution={
                "action_id": action.action_id,
                "execution_started": False,
                "lease_id": lease.lease_id,
            },
            observations=(),
            errors=(reason_code,),
        )
