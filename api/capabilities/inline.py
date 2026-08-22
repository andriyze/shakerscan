"""Canonical adapters for bounded inline HTTP and TLS Hunt actions."""

from __future__ import annotations

import math
import time
from typing import Any, Awaitable, Callable, Mapping

from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
from runtime.capability_registry import CapabilitySpec


InlineOperation = Callable[[], Awaitable[Mapping[str, Any]]]


class _InlineAdapter:
    def __init__(
        self,
        *,
        specification: CapabilitySpec,
        operation: InlineOperation,
        requested_budget: Mapping[str, int],
        redacted_execution: Mapping[str, Any],
    ) -> None:
        self.capability_name = specification.name
        self.adapter_name = specification.adapter
        self.adapter_version = specification.adapter_version
        self._specification = specification
        self._operation = operation
        self._requested_budget = {
            str(key): int(value)
            for key, value in dict(requested_budget).items()
        }
        self._redacted_execution = dict(redacted_execution)
        self.result: dict[str, Any] = {}

    def _wall_budget(self, started: float, *, execution_started: bool) -> dict[str, int]:
        if not execution_started or "tool_wall_seconds" not in self._requested_budget:
            return {}
        return {
            "tool_wall_seconds": min(
                int(self._requested_budget["tool_wall_seconds"]),
                max(1, math.ceil(time.perf_counter() - started)),
            )
        }


class HttpRequestExecutionAdapter(_InlineAdapter):
    """Normalize one same-origin, frozen-address HTTP probe."""

    async def execute(
        self,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult:
        del heartbeat, cancelled
        started = time.perf_counter()
        result = dict(await self._operation())
        self.result = result
        execution_started = isinstance(result.get("request"), Mapping)
        followed = max(0, int(result.get("hops_followed") or 0))
        actual = self._wall_budget(started, execution_started=execution_started)
        if "http_requests" in self._requested_budget:
            actual["http_requests"] = min(
                int(self._requested_budget["http_requests"]),
                1 + followed if execution_started else 0,
            )
        error = str(result.get("error") or "").strip()
        blocked = bool(
            result.get("needs_approval")
            or error.startswith("scope:")
            or "unavailable" in error
        )
        status = "success" if result.get("ok") else "blocked" if blocked else "failed"
        observations = ()
        if execution_started:
            observations = ({
                "kind": "http_observation",
                "request": dict(result.get("request") or {}),
                "response": dict(result.get("response") or {}),
                "redirect_chain": list(result.get("redirect_chain") or ()),
            },)
        return CapabilityAdapterResult(
            status=status,
            observations=observations,
            errors=(error,) if error else (),
            actual_budget=actual,
            execution_started=execution_started,
            parser_version=self._specification.output_schema,
            redacted_execution=dict(self._redacted_execution),
        )


class TlsInspectionExecutionAdapter(_InlineAdapter):
    """Normalize one frozen-address TLS handshake."""

    async def execute(
        self,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult:
        del heartbeat, cancelled
        result = dict(await self._operation())
        self.result = result
        measured = (
            dict(result.get("budget_consumed") or {})
            if isinstance(result.get("budget_consumed"), Mapping)
            else {}
        )
        execution_started = int(measured.get("tcp_ports_attempted") or 0) > 0
        status_value = str(result.get("status") or "")
        status = (
            "success"
            if result.get("ok") or status_value == "success"
            else "blocked"
            if status_value == "blocked"
            else "failed"
        )
        observation = result.get("observation")
        return CapabilityAdapterResult(
            status=status,
            observations=(dict(observation),) if isinstance(observation, Mapping) else (),
            errors=(str(result["error"]),) if result.get("error") else (),
            actual_budget={
                str(key): int(value)
                for key, value in measured.items()
            },
            execution_started=execution_started,
            parser_version=self._specification.output_schema,
            redacted_execution=dict(self._redacted_execution),
        )


class DeviceExecutionAdapter(_InlineAdapter):
    """Normalize one canonical device control, HTTP, queue, or SSH action."""

    def __init__(
        self,
        *,
        specification: CapabilitySpec,
        operation: InlineOperation,
        requested_budget: Mapping[str, int],
        redacted_execution: Mapping[str, Any],
        state: Mapping[str, Any],
        blocked_exceptions: tuple[type[BaseException], ...],
    ) -> None:
        super().__init__(
            specification=specification,
            operation=operation,
            requested_budget=requested_budget,
            redacted_execution=redacted_execution,
        )
        self._state = state
        self._blocked_exceptions = blocked_exceptions
        self._http_before = int(state.get("device_http_requests_used") or 0)
        self._queues_before = int(state.get("scans_queued") or 0)
        self.blocked_exception: BaseException | None = None

    async def execute(
        self,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult:
        del heartbeat, cancelled
        started = time.perf_counter()
        try:
            result = dict(await self._operation())
        except self._blocked_exceptions as exc:
            self.blocked_exception = exc
            result = {}
        self.result = result
        http_attempts = max(
            0,
            int(self._state.get("device_http_requests_used") or 0)
            - self._http_before,
        )
        queues = max(
            0,
            int(self._state.get("scans_queued") or 0)
            - self._queues_before,
        )
        execution_started = bool(http_attempts or queues or result.get("ok"))
        actual = self._wall_budget(
            started,
            execution_started=execution_started,
        )
        measured = (
            dict(result.get("budget_consumed") or {})
            if isinstance(result.get("budget_consumed"), Mapping)
            else {}
        )
        for dimension, amount in measured.items():
            if dimension in self._requested_budget:
                actual[str(dimension)] = int(amount)
        if http_attempts:
            for dimension in ("http_requests", "device_fragility_points"):
                if dimension in self._requested_budget:
                    actual[dimension] = min(
                        int(self._requested_budget[dimension]), http_attempts,
                    )
        if queues:
            for dimension in (
                "tcp_ports_attempted",
                "udp_ports_attempted",
                "device_fragility_points",
            ):
                if dimension in self._requested_budget:
                    actual[dimension] = int(self._requested_budget[dimension])

        status = (
            "blocked"
            if self.blocked_exception is not None
            else "success"
            if result.get("ok")
            else "blocked"
            if result.get("blocked")
            else "failed"
        )
        observation: dict[str, Any] = {
            "kind": "device_capability",
            "capability": self.capability_name,
            "status": status,
        }
        if result.get("evidence_ref"):
            observation["evidence_ref"] = str(result["evidence_ref"])
        queued = result.get("queued")
        if isinstance(queued, Mapping):
            observation["queued"] = {
                key: str(value) if value is not None else None
                for key, value in dict(queued).items()
                if key in {"scan_id", "job_id", "run_kind", "status"}
            }
        if result.get("requires_user_confirmation"):
            observation["requires_user_confirmation"] = True
        error = (
            f"blocked:{type(self.blocked_exception).__name__}"
            if self.blocked_exception is not None
            else str(result.get("error") or "").strip()
        )
        return CapabilityAdapterResult(
            status=status,
            observations=(observation,),
            errors=(error,) if error else (),
            actual_budget=actual,
            execution_started=execution_started,
            parser_version=self._specification.output_schema,
            redacted_execution=dict(self._redacted_execution),
        )
