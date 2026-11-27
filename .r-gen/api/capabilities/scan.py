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


def measure_deterministic_scan_result(
    result: Mapping[str, Any],
    *,
    requested_budget: Mapping[str, int],
    elapsed_seconds: float,
) -> CapabilityAdapterResult:
    """Classify one scanner report and reconcile only trustworthy counters.

    Callers that cannot prove elapsed time (for example, a remote control plane)
    pass the full held wall-time amount. Missing or non-enforcing request-meter
    evidence intentionally leaves HTTP dimensions absent so the reservation
    state machine conservatively charges the complete hold.
    """
    bounded_request = {
        str(name): max(0, int(amount))
        for name, amount in dict(requested_budget).items()
    }
    report = dict(result)
    metadata = _mapping(report.get("scan_metadata"))
    coverage = _mapping(report.get("coverage"))
    request_budget = _mapping(report.get("request_budget"))
    discovery = _mapping(report.get("discovery"))
    browser_crawl = _mapping(discovery.get("browser_crawl"))
    tls = _mapping(report.get("tls"))
    tls_runtime = _mapping(tls.get("canonical_runtime"))
    error = str(report.get("error") or "").strip()
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
        actual = {name: 0 for name in bounded_request}
    else:
        actual: dict[str, int] = {}
        if "tool_wall_seconds" in bounded_request:
            actual["tool_wall_seconds"] = min(
                bounded_request["tool_wall_seconds"],
                max(1, int(math.ceil(max(0.0, elapsed_seconds)))),
            )
        if "hosts_attempted" in bounded_request:
            actual["hosts_attempted"] = min(
                bounded_request["hosts_attempted"], 1,
            )
        if (
            "tcp_ports_attempted" in bounded_request
            and tls_runtime.get("schema_version")
            == "canonical-tls-runtime/v1"
        ):
            actual["tcp_ports_attempted"] = min(
                bounded_request["tcp_ports_attempted"],
                max(0, int(tls_runtime.get("tcp_ports_attempted") or 0)),
            )
        exact_http = bool(
            request_budget.get("schema_version") == "request_meter_v1"
            and request_budget.get("mode") == "enforce"
            and request_budget.get("fully_metered") is True
        )
        if exact_http and "http_requests" in bounded_request:
            actual["http_requests"] = min(
                bounded_request["http_requests"],
                max(0, int(request_budget.get("attempted_requests") or 0)),
            )
        if exact_http and "state_changing_requests" in bounded_request:
            actual["state_changing_requests"] = min(
                bounded_request["state_changing_requests"],
                max(
                    0,
                    int(
                        request_budget.get(
                            "state_changing_attempted_requests"
                        ) or 0
                    ),
                ),
            )
        if "browser_actions" in bounded_request:
            pages = browser_crawl.get("pages_visited")
            if pages is not None:
                actual["browser_actions"] = min(
                    bounded_request["browser_actions"],
                    max(0, int(pages)),
                )

    findings = report.get("findings")
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
            metadata.get("schema_version") or "scan-report/v2"
        ),
        redacted_execution={},
    )


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
        measured = measure_deterministic_scan_result(
            result,
            requested_budget=self._requested_budget,
            elapsed_seconds=elapsed,
        )
        return CapabilityAdapterResult(
            status=measured.status,
            observations=measured.observations,
            errors=measured.errors,
            actual_budget=measured.actual_budget,
            partial=measured.partial,
            timed_out=measured.timed_out,
            execution_started=measured.execution_started,
            parser_version=measured.parser_version,
            redacted_execution=self._redacted_execution,
        )
