"""Canonical receipt-producing action driver shared by local and broker workers."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping

try:  # Preserve one class identity for host package imports.
    from ..runtime.receipts import CapabilityReceipt
except (ImportError, ModuleNotFoundError):  # top-level worker imports
    from runtime.receipts import CapabilityReceipt

from .action_plan import ScanAction
from .execution_backend import ActionHeartbeat, ActionLease


class WorkerActionExecutionError(RuntimeError):
    """A worker dispatcher did not return a canonical action receipt."""


ActionDispatcher = Callable[
    [ScanAction, ActionLease, ActionHeartbeat],
    Awaitable[CapabilityReceipt | Mapping[str, Any]],
]


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
    ) -> None:
        self._scan_id = str(scan_id)
        self._target_id = str(target_id)
        self._worker_id = str(worker_id)
        self._dispatcher = dispatcher
        self._scope_receipt_id = scope_receipt_id
        self._approval_receipt_id = approval_receipt_id

    async def execute(
        self,
        action: ScanAction,
        lease: ActionLease,
        heartbeat: ActionHeartbeat,
    ) -> CapabilityReceipt:
        stop_heartbeats = asyncio.Event()

        async def keep_lease_alive() -> None:
            interval = max(1.0, min(30.0, float(lease.lease_seconds) / 3.0))
            while not stop_heartbeats.is_set():
                try:
                    await asyncio.wait_for(stop_heartbeats.wait(), timeout=interval)
                except asyncio.TimeoutError:
                    await heartbeat()

        heartbeat_task = asyncio.create_task(keep_lease_alive())
        try:
            result = await self._dispatcher(action, lease, heartbeat)
        finally:
            stop_heartbeats.set()
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
        return receipt

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
