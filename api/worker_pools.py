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


def web_dast_heartbeat_summary(
    reports: list[Mapping[str, Any]],
    *,
    now_epoch: float,
    max_age_seconds: float,
    clock_skew_seconds: float = 0.0,
) -> dict[str, Any]:
    """Web DAST pool summary derived from worker heartbeats, for deployments that do not mount
    the Docker socket (the self-hosted Enterprise gateway is one). The socket-backed path counts
    live containers; without the socket the same population is the workers still writing fresh
    build reports to Redis. Shape matches ``compute_fleet_summary`` so callers can use it
    interchangeably.

    ``reports`` are the parsed ``shakerscan:worker_build`` entries: each a mapping with
    ``reported_epoch`` (POSIX seconds the worker last reported), ``build_current`` (True on the
    expected build, False on a stale build, None not yet classified), and optional ``name`` and
    ``build_fingerprint``. Only reports inside the freshness window count as present, so a worker
    that stopped heartbeating drops out just as a removed container would.
    """
    fresh = [
        report
        for report in reports
        if isinstance(report.get("reported_epoch"), (int, float))
        and -clock_skew_seconds <= now_epoch - float(report["reported_epoch"]) <= max_age_seconds
    ]
    current = [r for r in fresh if r.get("build_current") is True]
    stale = [r for r in fresh if r.get("build_current") is False]
    pending = [r for r in fresh if r.get("build_current") is None]
    fingerprints = sorted(
        {str(r.get("build_fingerprint")) for r in current + stale if r.get("build_fingerprint")}
    )
    return {
        "count": len(fresh),
        "current_count": len(current),
        "stale_count": len(stale),
        "pending_count": len(pending),
        "fleet_uniform": len(fresh) > 0 and not stale and not pending,
        "distinct_fingerprints": fingerprints,
        "stale_workers": [str(r.get("name")) for r in stale if r.get("name")],
        "fresh_names": [str(r.get("name")) for r in fresh if r.get("name")],
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
