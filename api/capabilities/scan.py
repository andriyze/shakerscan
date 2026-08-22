"""Shared-executor adapter for one canonical deterministic Scan process."""

from __future__ import annotations

import asyncio
import math
import time
from typing import Any, Awaitable, Callable, Mapping

from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
from runtime.capability_registry import CapabilitySpec


DeterministicScanRunner = Callable[[], Awaitable[Mapping[str, Any]]]


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


class DeterministicScanExecutionAdapter:
    """Execute and meter the fixed-stage scanner behind one durable action.

    The scanner report remains with the worker for ordinary Scan persistence.
    The capability receipt contains only a bounded summary and measured counters.
    """

    manages_cancellation = True

    def __init__(
        self,
        *,
        specification: CapabilitySpec,
        scan_runner: DeterministicScanRunner,
        requested_budget: Mapping[str, int],
        redacted_execution: Mapping[str, Any],
        heartbeat_interval_seconds: float = 20.0,
    ) -> None:
        self.capability_name = specification.name
        self.adapter_name = specification.adapter
        self.adapter_version = specification.adapter_version
        self._specification = specification
        self._scan_runner = scan_runner
        self._requested_budget = {
            str(name): int(amount)
            for name, amount in dict(requested_budget).items()
        }
        self._redacted_execution = dict(redacted_execution)
        self._heartbeat_interval_seconds = max(
            0.01, float(heartbeat_interval_seconds),
        )
        self.scan_result: dict[str, Any] = {}

    async def execute(
        self,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult:
        if cancelled():
            return CapabilityAdapterResult(
                status="cancelled",
                errors=("cancelled_before_execution",),
                actual_budget={name: 0 for name in self._requested_budget},
                execution_started=False,
                parser_version=self._specification.output_schema,
                redacted_execution=self._redacted_execution,
            )

        await heartbeat()
        started = time.monotonic()
        task = asyncio.create_task(self._scan_runner())
        try:
            while not task.done():
                done, _pending = await asyncio.wait(
                    {task}, timeout=self._heartbeat_interval_seconds,
                )
                if task in done:
                    break
                if cancelled():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    return CapabilityAdapterResult(
                        status="cancelled",
                        errors=("cancelled_during_execution",),
                        actual_budget=dict(self._requested_budget),
                        execution_started=True,
                        parser_version=self._specification.output_schema,
                        redacted_execution=self._redacted_execution,
                    )
                await heartbeat()
            result = dict(await task)
        except BaseException:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise

        elapsed = max(0.0, time.monotonic() - started)
        self.scan_result = result
        metadata = _mapping(result.get("scan_metadata"))
        coverage = _mapping(result.get("coverage"))
        request_budget = _mapping(result.get("request_budget"))
        discovery = _mapping(result.get("discovery"))
        browser_crawl = _mapping(discovery.get("browser_crawl"))
        error = str(result.get("error") or "").strip()
        timed_out = bool(metadata.get("timed_out"))
        partial = bool(
            metadata.get("partial")
            or timed_out
            or str(coverage.get("status") or "").lower() == "partial"
        )
        cancelled_result = "cancel" in error.lower()
        execution_started = not bool(
            metadata.get("preflight_failed")
            or metadata.get("admission_control_failed")
        )
        if cancelled_result:
            status = "cancelled"
        elif error and partial:
            status = "partial"
        elif error:
            status = "failed"
        elif partial:
            status = "partial"
        else:
            status = "success"

        if not execution_started:
            actual = {name: 0 for name in self._requested_budget}
        else:
            actual: dict[str, int] = {}
            if "tool_wall_seconds" in self._requested_budget:
                actual["tool_wall_seconds"] = min(
                    self._requested_budget["tool_wall_seconds"],
                    max(1, int(math.ceil(elapsed))),
                )
            if "hosts_attempted" in self._requested_budget:
                actual["hosts_attempted"] = min(
                    self._requested_budget["hosts_attempted"], 1,
                )
            exact_http = bool(
                request_budget.get("schema_version") == "request_meter_v1"
                and request_budget.get("mode") == "enforce"
                and request_budget.get("fully_metered") is True
            )
            if exact_http and "http_requests" in self._requested_budget:
                actual["http_requests"] = min(
                    self._requested_budget["http_requests"],
                    max(0, int(request_budget.get("attempted_requests") or 0)),
                )
            if exact_http and "state_changing_requests" in self._requested_budget:
                actual["state_changing_requests"] = min(
                    self._requested_budget["state_changing_requests"],
                    max(
                        0,
                        int(
                            request_budget.get(
                                "state_changing_attempted_requests"
                            ) or 0
                        ),
                    ),
                )
            if "browser_actions" in self._requested_budget:
                pages = browser_crawl.get("pages_visited")
                if pages is not None:
                    actual["browser_actions"] = min(
                        self._requested_budget["browser_actions"],
                        max(0, int(pages)),
                    )

        findings = result.get("findings")
        finding_count = len(findings) if isinstance(findings, list) else 0
        observations = ({
            "kind": "deterministic_scan_summary",
            "status": status,
            "coverage_status": str(coverage.get("status") or "unknown")[:40],
            "finding_count": finding_count,
            "request_meter_exact": bool(
                request_budget.get("schema_version") == "request_meter_v1"
                and request_budget.get("mode") == "enforce"
                and request_budget.get("fully_metered") is True
            ),
        },)
        return CapabilityAdapterResult(
            status=status,
            observations=observations,
            errors=(error[:1000],) if error else (),
            actual_budget=actual,
            partial=partial,
            timed_out=timed_out,
            execution_started=execution_started,
            parser_version=str(
                metadata.get("schema_version")
                or self._specification.output_schema
            ),
            redacted_execution=self._redacted_execution,
        )
