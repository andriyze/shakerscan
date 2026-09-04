"""Content-free worker-pool summaries shared by operational API surfaces."""

from __future__ import annotations

from typing import Any, Callable, Mapping


def _specialized_pool(readiness: Mapping[str, Any]) -> dict[str, Any]:
    reports = readiness.get("workers") if isinstance(readiness.get("workers"), list) else []
    count = int(readiness.get("worker_count") or len(reports))
    current = int(readiness.get("capable_worker_count") or 0)
    stale = sum(
        1 for report in reports
        if isinstance(report, Mapping) and report.get("build_current") is False
    )
    pending = max(0, count - current - stale)
    return {
        "count": count,
        "current": current,
        "stale": stale,
        "pending": pending,
        "status": str(readiness.get("status") or "not_ready"),
        "reason": readiness.get("reason"),
    }


def _readiness(source: Callable[[], Mapping[str, Any]]) -> Mapping[str, Any]:
    try:
        return source()
    except Exception:
        return {"status": "not_ready", "reason": "worker_readiness_unavailable"}


def worker_pool_summaries(
    web_dast: Mapping[str, Any],
    *,
    agent_tool: Callable[[], Mapping[str, Any]],
    device: Callable[[], Mapping[str, Any]],
    model_intake: Callable[[], Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Return the four execution pools without changing legacy Web DAST summary semantics."""
    web_count = int(web_dast.get("count") or 0)
    web_current = int(web_dast.get("current_count") or 0)
    web_stale = int(web_dast.get("stale_count") or 0)
    web_pending = int(web_dast.get("pending_count") or max(0, web_count - web_current - web_stale))
    return {
        "web_dast": {
            "count": web_count,
            "current": web_current,
            "stale": web_stale,
            "pending": web_pending,
            "status": "ready" if web_current > 0 and web_stale == 0 and web_pending == 0 else "not_ready",
            "reason": None if web_current > 0 and web_stale == 0 and web_pending == 0 else "web_dast_pool_not_uniform",
        },
        "agent_tool": _specialized_pool(_readiness(agent_tool)),
        "device": _specialized_pool(_readiness(device)),
        "model_intake": _specialized_pool(_readiness(model_intake)),
    }
