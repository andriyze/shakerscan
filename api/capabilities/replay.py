"""Shared-executor adapter for exact request-collection replay."""

from __future__ import annotations

from typing import Any, Mapping

from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
from runtime.capability_registry import CapabilitySpec
from runtime.request_replay_executor import execute_replay_plan


class ReplayExecutionAdapter:
    """Run the durable exact-replay engine behind the canonical capability seam."""

    manages_cancellation = True

    def __init__(
        self,
        *,
        specification: CapabilitySpec,
        execution_kwargs: Mapping[str, Any],
    ) -> None:
        self.capability_name = specification.name
        self.adapter_name = specification.adapter
        self.adapter_version = specification.adapter_version
        self._execution_kwargs = dict(execution_kwargs)
        self.outcome: Any | None = None

    async def execute(
        self,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult:
        # The exact replay engine persists a heartbeat after each request and
        # owns the reservation transition callbacks supplied by the worker.
        # ``heartbeat`` is therefore represented by those durable callbacks.
        del heartbeat
        outcome = await execute_replay_plan(
            **self._execution_kwargs,
            cancelled=cancelled,
        )
        self.outcome = outcome
        receipt = outcome.receipt
        status = {
            "succeeded": "success",
            "partial": "partial",
            "cancelled": "cancelled",
            "blocked": "blocked",
        }.get(str(outcome.status), "failed")
        actual = dict(outcome.reservation.actual)
        return CapabilityAdapterResult(
            status=status,
            observations=tuple(
                dict(item) for item in receipt.observations
                if isinstance(item, Mapping)
            ),
            errors=tuple(str(item) for item in receipt.errors),
            actual_budget=actual,
            partial=bool(receipt.partial),
            timed_out=bool(receipt.timed_out),
            execution_started=(
                int(actual.get("http_requests") or 0) > 0
                or int(actual.get("state_changing_requests") or 0) > 0
            ),
            parser_version=str(receipt.parser_version),
            redacted_execution=dict(receipt.redacted_execution),
        )
