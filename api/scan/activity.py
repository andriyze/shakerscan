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
