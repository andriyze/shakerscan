"""Shared-executor adapter for fixed-template external scanner processes."""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Mapping

from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
from runtime.capability_registry import CapabilitySpec
from scan.external_process import (
    ExternalProcessContractError,
    validate_enforcement_receipt,
)


ScannerProcessRunner = Callable[..., Awaitable[Mapping[str, Any]]]


class ScannerExecutionAdapter:
    """Normalize a fixed-template scanner process into one capability result."""

    manages_cancellation = True

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
        scanner_options = (
            dict(self._process_payload.get("scanner_options") or {})
            if isinstance(self._process_payload.get("scanner_options"), Mapping)
            else {}
        )
        self._state_changing = (
            bool(scanner_options.get("body_field_names"))
            and str(scanner_options.get("method") or "GET").upper()
            not in {"GET", "HEAD", "OPTIONS"}
        )
        if self._state_changing and int(
            self._requested_budget.get("state_changing_requests") or 0
        ) < int(self._requested_budget.get("http_requests") or 0):
            raise ValueError(
                "body scanner requires a conservative state-changing reservation"
            )
        self.process_result: dict[str, Any] = {}

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
        # The shared executor checks cancellation immediately before this call.
        # The process runner uses the opaque job identity for in-flight Redis
        # cancellation and invokes the durable heartbeat supplied here.
        process_payload = dict(self._process_payload)
        # This callback never crosses a queue or receipt boundary. The worker's
        # subprocess loop polls it so Scan cancellation remains distinct and
        # stops the external child rather than waiting for its hard timeout.
        process_payload["_cancelled"] = cancelled
        # The reservation is injected at the last in-memory boundary. The
        # worker's authoritative builder must derive argv from this exact hold.
        process_payload["_reserved_budget"] = dict(self._requested_budget)
        process_result = dict(await self._process_runner(
            process_payload,
            heartbeat=heartbeat,
        ))
        self.process_result = process_result
        settlement = (
            dict(process_result.get("settlement") or {})
            if isinstance(process_result.get("settlement"), Mapping)
            else {}
        )
        not_executed = str(settlement.get("source") or "") == "not_executed"
        enforcement: dict[str, Any] = {}
        enforcement_error = ""
        if not not_executed:
            try:
                enforcement = validate_enforcement_receipt(
                    process_result.get("process_enforcement")
                    if isinstance(process_result.get("process_enforcement"), Mapping)
                    else {},
                    reserved=self._requested_budget,
                )
                expected_tool = str(
                    self._specification.process_tool_name
                    or self._specification.adapter
                )
                if str(enforcement.get("tool_name") or "") != expected_tool:
                    raise ExternalProcessContractError(
                        "process enforcement tool identity mismatch"
                    )
                if str(enforcement.get("parser_version") or "") != str(
                    self._specification.output_schema
                ):
                    raise ExternalProcessContractError(
                        "process enforcement parser identity mismatch"
                    )
                hard_http = int(
                    dict(enforcement.get("hard_budget") or {}).get("http_requests")
                    or 0
                )
                observed_wire = (
                    int(settlement.get("actual") or 0)
                    if str(settlement.get("mode") or "") == "exact"
                    else int(settlement.get("observed_minimum") or 0)
                )
                if hard_http > 0 and observed_wire > hard_http:
                    raise ExternalProcessContractError(
                        "wire limiter reported traffic above the hard ceiling"
                    )
            except (ExternalProcessContractError, TypeError, ValueError) as exc:
                enforcement_error = f"external_process_contract:{str(exc)[:200]}"
                process_result["status"] = "failed"
                process_result["error"] = enforcement_error
                process_result["execution_uncertain"] = True
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
            if "state_changing_requests" in self._requested_budget:
                actual["state_changing_requests"] = (
                    int(self._requested_budget["state_changing_requests"])
                    if self._state_changing and execution_started else 0
                )

        redacted_execution = dict(self._redacted_execution)
        if enforcement:
            redacted_execution["process_enforcement"] = enforcement
            hard_budget = dict(enforcement.get("hard_budget") or {})
            raw_network = (
                dict(process_result.get("network_telemetry") or {})
                if isinstance(process_result.get("network_telemetry"), Mapping)
                else {}
            )
            redacted_execution["wire_telemetry"] = {
                "schema_version": "external-wire-telemetry/v1",
                "accounting_mode": (
                    "exact"
                    if str(settlement.get("mode") or "") == "exact"
                    else str(enforcement.get("accounting_mode") or "conservative")
                ),
                "actual_http_requests": (
                    max(0, int(settlement.get("actual") or 0))
                    if str(settlement.get("mode") or "") == "exact"
                    else None
                ),
                "observed_http_requests_minimum": max(
                    0, int(settlement.get("observed_minimum") or 0),
                ),
                "http_request_upper_bound": int(
                    hard_budget.get("http_requests") or 0
                ),
                "tcp_attempt_upper_bound": int(
                    hard_budget.get("tcp_ports_attempted") or 0
                ),
                "connections_attempted": max(
                    0, int(raw_network.get("connections_attempted") or 0),
                ),
                "connections_opened": max(
                    0, int(raw_network.get("connections_opened") or 0),
                ),
                "targets": max(0, int(raw_network.get("targets") or 0)),
                "wall_seconds": max(
                    0, int(process_result.get("elapsed_seconds") or 0),
                ),
                "limiter_status": (
                    "failed"
                    if enforcement_error
                    or str(process_result.get("error") or "")
                    == "connection_limit_exceeded"
                    else "within_ceiling"
                ),
            }
        browser_profile = process_result.get("browser_profile")
        if isinstance(browser_profile, Mapping) and browser_profile:
            redacted_execution["browser_profile"] = {
                "schema_version": str(browser_profile.get("schema_version") or ""),
                "kind": str(browser_profile.get("kind") or ""),
                "seeded_items": max(
                    0, int(browser_profile.get("seeded_items") or 0),
                ),
                "target_requests": max(
                    0, int(browser_profile.get("target_requests") or 0),
                ),
                "secret_values_visible": False,
            }
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
            redacted_execution=redacted_execution,
        )
