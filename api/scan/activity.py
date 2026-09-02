"""Content-free, user-facing activity events for canonical Scan actions."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from .action_plan import ScanAction, ScanActionPlan
from .capability_result import CapabilityResultReference


_ACRONYMS = {
    "api": "API",
    "dns": "DNS",
    "http": "HTTP",
    "sqli": "SQLi",
    "tls": "TLS",
    "xss": "XSS",
}


def _action_label(action_id: str) -> str:
    tokens = str(action_id or "Action").replace("_", ".").split(".")
    return " ".join(
        _ACRONYMS.get(token.lower(), token.capitalize())
        for token in tokens
        if token
    ) or "Action"


def scan_action_activity_event(
    *,
    plan: ScanActionPlan,
    action: ScanAction,
    event: str,
    result: CapabilityResultReference | None = None,
    progress_start: int = 5,
    progress_end: int = 95,
) -> dict[str, Any]:
    """Project an action transition into a bounded, secret-free UI event."""
    if event not in {"running", "restored", "settled"}:
        raise ValueError("unsupported Scan action activity event")
    if event == "running" and result is not None:
        raise ValueError("running Scan action activity cannot include a result")
    if event != "running" and result is None:
        raise ValueError("terminal Scan action activity requires a result")
    if not 0 <= progress_start <= progress_end <= 99:
        raise ValueError("Scan action activity progress range is invalid")
    action_ids = tuple(item.action_id for item in plan.actions)
    try:
        index = action_ids.index(action.action_id)
    except ValueError as exc:
        raise ValueError("Scan action activity is detached from its plan") from exc
    position = index if event == "running" else index + 1
    span = progress_end - progress_start
    progress = round(progress_start + span * position / max(1, len(action_ids)))
    label = _action_label(action.action_id)
    if event == "running":
        line = f"[scan] Started {label} · {progress}%"
    else:
        status = result.status.value
        verb = "Restored" if event == "restored" else "Finished"
        line = f"[scan] {verb} {label} · {status} · {progress}%"
    return {
        "phase": action.action_id,
        "progress": progress,
        "line": line[:1000],
    }


def _diagnostic_error_class(value: Any) -> str:
    errors = value if isinstance(value, (list, tuple)) else ()
    for raw in errors:
        token = str(raw or "").strip().lower().split(":", 1)[0]
        token = re.sub(r"[^a-z0-9_-]+", "_", token)[:80]
        if token in {
            "timed_out", "timeout", "connection_limit_exceeded",
            "external_process_contract", "scanner_not_available",
            "cancelled_before_execution",
        } or re.fullmatch(r"exit_-?[0-9]+", token):
            return token
        if token:
            return "unclassified_adapter_error"
    return "none"


def scan_action_diagnostic_line(
    *,
    action: ScanAction,
    result: CapabilityResultReference,
    receipt: Mapping[str, Any] | None,
) -> str | None:
    """Render allowlisted process telemetry without target or payload content."""
    public_receipt = dict(receipt or {})
    execution = (
        dict(public_receipt.get("redacted_execution") or {})
        if isinstance(public_receipt.get("redacted_execution"), Mapping) else {}
    )
    enforcement = (
        dict(execution.get("process_enforcement") or {})
        if isinstance(execution.get("process_enforcement"), Mapping) else {}
    )
    wire = (
        dict(execution.get("wire_telemetry") or {})
        if isinstance(execution.get("wire_telemetry"), Mapping) else {}
    )
    execution_started = execution.get("execution_started")
    execution_state = (
        "started" if execution_started is True
        else "not_started" if execution_started is False
        else "unknown"
    )
    reason = result.reason_code.value if result.reason_code is not None else "none"
    error_class = _diagnostic_error_class(public_receipt.get("errors"))
    if (
        result.status.value == "skipped"
        and execution_started is False
        and reason in {"insufficient_plan_budget", "not_applicable"}
    ):
        # Allocation/policy skips never launched an adapter. A retained internal
        # diagnostic may explain the scheduler decision, but it is not an adapter
        # error and must not be rendered as one in the operator log.
        error_class = "none"
    label = _action_label(action.action_id)
    if not enforcement and not wire:
        if result.status.value == "success":
            return None
        accounted_http = int(result.budget_consumed.get("http_requests", 0))
        reserved_http = int(result.budget_reserved.get("http_requests", 0))
        accounted_wall = int(result.budget_consumed.get("tool_wall_seconds", 0))
        reserved_wall = int(result.budget_reserved.get("tool_wall_seconds", 0))
        return (
            f"[scan] Diagnostic {label} · outcome={result.status.value}"
            f" · reason={reason} · error={error_class}"
            f" · execution={execution_state}"
            f" · http={accounted_http}/{reserved_http} accounted/reserved"
            f" · wall={accounted_wall}s/{reserved_wall}s accounted/reserved"
        )[:1000]

    hard = (
        dict(enforcement.get("hard_budget") or {})
        if isinstance(enforcement.get("hard_budget"), Mapping) else {}
    )
    reserved_http = int(result.budget_reserved.get("http_requests", 0))
    hard_http = max(0, int(hard.get("http_requests") or reserved_http))
    exact_http = wire.get("actual_http_requests")
    observed_http = max(
        0,
        int(
            exact_http
            if isinstance(exact_http, int) and not isinstance(exact_http, bool)
            else wire.get("observed_http_requests_minimum") or 0
        ),
    )
    reserved_wall = int(result.budget_reserved.get("tool_wall_seconds", 0))
    hard_wall = max(0, int(hard.get("tool_wall_seconds") or reserved_wall))
    observed_wall = max(0, int(wire.get("wall_seconds") or 0))
    attempted_connections = max(0, int(wire.get("connections_attempted") or 0))
    opened_connections = max(0, int(wire.get("connections_opened") or 0))
    limiter = str(wire.get("limiter_status") or "unknown").strip().lower()
    if limiter not in {"within_ceiling", "failed"}:
        limiter = "unknown"
    return (
        f"[scan] Diagnostic {label} · outcome={result.status.value}"
        f" · reason={reason} · error={error_class}"
        f" · execution={execution_state}"
        f" · http={observed_http}/{hard_http}/{reserved_http} observed/hard/reserved"
        f" · wall={observed_wall}s/{hard_wall}s"
        f" · connections={opened_connections}/{attempted_connections} opened/attempted"
        f" · limiter={limiter}"
    )[:1000]


def parallel_scan_activity_lines(
    *,
    shards: Sequence[Mapping[str, Any]],
    child_logs: Mapping[str, Sequence[Any]],
    limit: int,
) -> list[str]:
    """Combine child activity into one bounded parent-scan feed."""
    bounded_limit = max(1, min(1000, int(limit)))
    lines: list[str] = []
    for position, shard in enumerate(shards, start=1):
        shard_id = str(shard.get("id") or "")
        try:
            index = int(shard.get("shard_index")) + 1
        except (TypeError, ValueError):
            index = position
        prefix = f"[Shard {index}]"
        raw_lines = list(child_logs.get(shard_id) or ())
        if raw_lines:
            for raw_line in raw_lines:
                text = (
                    raw_line.decode("utf-8", "replace")
                    if isinstance(raw_line, bytes)
                    else str(raw_line)
                ).strip()
                if text:
                    lines.append(f"{prefix} {text}"[:1200])
            continue
        status = re.sub(
            r"[^a-z0-9_-]+", "_",
            str(shard.get("status") or "unknown").strip().lower(),
        )[:32] or "unknown"
        phase = re.sub(
            r"[^a-z0-9_.:-]+", "_",
            str(shard.get("current_phase") or status).strip().lower(),
        )[:120] or status
        lines.append(f"{prefix} {status} · {_action_label(phase)}")
    return lines[-bounded_limit:]
