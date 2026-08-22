"""Shared-executor adapter for fixed-template external scanner processes."""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Mapping

from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
from runtime.capability_registry import CapabilitySpec


ScannerProcessRunner = Callable[..., Awaitable[Mapping[str, Any]]]


class ScannerExecutionAdapter:
    """Normalize a fixed-template scanner process into one capability result."""

    def __init__(
        self,
        *,
        specification: CapabilitySpec,
        process_payload: Mapping[str, Any],
        process_runner: ScannerProcessRunner,
        requested_budget: Mapping[str, int],
        redacted_execution: Mapping[str, Any],
    ) -> None:
        self.capability_name = specification.name
        self.adapter_name = specification.adapter
        self.adapter_version = specification.adapter_version
        self._specification = specification
        self._process_payload = dict(process_payload)
        self._process_runner = process_runner
        self._requested_budget = {
            str(key): int(value)
            for key, value in dict(requested_budget).items()
        }
        self._redacted_execution = dict(redacted_execution)
        self.process_result: dict[str, Any] = {}

    async def execute(
        self,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult:
        # The shared executor checks cancellation immediately before this call.
        # The process runner uses the opaque job identity for in-flight Redis
        # cancellation and invokes the durable heartbeat supplied here.
        process_result = dict(
            await self._process_runner(
                self._process_payload,
                heartbeat=heartbeat,
            )
        )
        self.process_result = process_result
        typed_output = (
            dict(process_result.get("typed_output") or {})
            if isinstance(process_result.get("typed_output"), Mapping)
            else {}
        )
        observations = tuple(
            dict(item)
            for item in typed_output.get("records") or ()
            if isinstance(item, Mapping)
        )[:5000]
        parser_errors = [
            str(item) for item in typed_output.get("errors") or ()
        ][:20]
        process_status = str(process_result.get("status") or "failed")
        timed_out = bool(process_result.get("timed_out"))
        partial = bool(process_result.get("partial") or timed_out)
        if process_status == "success":
            status = "partial" if partial else "success"
        elif process_status == "cancelled":
            status = "cancelled"
        elif partial:
            status = "partial"
        else:
            status = "failed"

        primary_error = str(process_result.get("error") or "").strip()
        errors = ([primary_error] if primary_error else []) + parser_errors
        settlement = (
            dict(process_result.get("settlement") or {})
            if isinstance(process_result.get("settlement"), Mapping)
            else {}
        )
        not_executed = str(settlement.get("source") or "") == "not_executed"
        execution_started = not not_executed
        if process_result.get("execution_uncertain"):
            actual = dict(self._requested_budget)
            execution_started = True
        else:
            actual: dict[str, int] = {}
            if "tool_wall_seconds" in self._requested_budget:
                actual["tool_wall_seconds"] = min(
                    int(self._requested_budget["tool_wall_seconds"]),
                    max(0, int(process_result.get("elapsed_seconds") or 0)),
                )
            if "http_requests" in self._requested_budget:
                if str(settlement.get("mode") or "") == "exact":
                    actual["http_requests"] = min(
                        int(self._requested_budget["http_requests"]),
                        max(0, int(settlement.get("actual") or 0)),
                    )
                elif execution_started:
                    # Tools without exact wire telemetry retain the full hold.
                    actual["http_requests"] = int(
                        self._requested_budget["http_requests"]
                    )

        return CapabilityAdapterResult(
            status=status,
            observations=observations,
            errors=tuple(errors[:20]),
            actual_budget=actual,
            partial=partial,
            timed_out=timed_out,
            execution_started=execution_started,
            parser_version=str(
                typed_output.get("parser")
                or self._specification.output_schema
            ),
            redacted_execution=dict(self._redacted_execution),
        )
