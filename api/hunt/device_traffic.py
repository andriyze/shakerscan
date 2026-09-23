"""Device safety shared by ordinary worker capabilities and native adapters.

The existing reservation ledger owns in-flight holds. The existing device policy
owns pacing and health; no worker placement may bypass either one.
"""
from __future__ import annotations

import json
from typing import Any, Mapping

from .device_policy import DeviceHuntPolicyState


def worker_device_traffic(run: Mapping[str, Any], spec: Any) -> bool:
    return bool(
        run["device_target_id"]
        and spec.placement_requirements.get("network_reachability")
        and not str(spec.hunt_executor).startswith("device")
        and spec.hunt_executor != "worker_replay"
    )


def traffic_envelope(amounts: Mapping[str, int]) -> int:
    """Bound requests/connections, including multi-request browser/scanner actions."""
    return max(1, int(amounts.get("http_requests", 0)),
               int(amounts.get("browser_actions", 0)),
               int(amounts.get("tcp_ports_attempted", 0))
               + int(amounts.get("udp_ports_attempted", 0)))


def reserve_device_traffic(run: Mapping[str, Any], spec: Any, amounts: dict[str, int]) -> None:
    if worker_device_traffic(run, spec):
        amounts["device_fragility_points"] = max(
            int(amounts.get("device_fragility_points") or 0), traffic_envelope(amounts),
        )


async def require_device_admission(conn: Any, run: Mapping[str, Any], *,
                                   fragility: int, requests: int, scans: int = 0) -> None:
    """Called under the run transaction, before writing a reservation."""
    try:
        import device_agent
    except ModuleNotFoundError:
        from .. import device_agent
    device_id = run["device_target_id"]
    await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                       f"device-http:{device_id}")
    busy = await conn.fetchval(
        """SELECT EXISTS(SELECT 1 FROM budget_reservations r
           JOIN hunt_runs h ON r.owner_kind='hunt' AND r.owner_id=h.id::text
           WHERE h.device_target_id=$1 AND r.status IN ('reserved','running')
             AND COALESCE((r.requested_json->>'device_fragility_points')::int,0)>0)""",
        device_id,
    )
    if busy:
        raise ValueError("A device traffic action is already in flight")
    legacy = int(await conn.fetchval(
        """SELECT COALESCE(SUM(fragility_cost),0) FROM device_agent_actions
           WHERE device_target_id=$1 AND outcome <> 'blocked'
             AND created_at >= date_trunc('day', NOW())""", device_id) or 0)
    # The ledger timestamps the action, so long-lived Hunts do not carry yesterday's
    # usage into today's allowance or escape the allowance by predating midnight.
    daily = int(await conn.fetchval(
        """SELECT COALESCE(SUM(COALESCE(((CASE
               WHEN r.status IN ('reserved','running') THEN r.requested_json
               ELSE r.actual_json END)->>'device_fragility_points')::int,0)),0)
           FROM budget_reservations r JOIN hunt_runs h
             ON r.owner_kind='hunt' AND r.owner_id=h.id::text
           WHERE h.device_target_id=$1 AND r.updated_at >= date_trunc('day', NOW())""",
        device_id) or 0)
    if legacy + daily + fragility > device_agent.MAX_FRAGILITY_PER_DEVICE_DAY:
        raise ValueError("Daily fragility budget for this device is exhausted")
    context = run["context_pack"]
    if isinstance(context, str):
        context = json.loads(context)
    DeviceHuntPolicyState.from_mapping(context.get("device_policy_state") or {}).require_admission(
        request_attempts=requests, scan_attempts=scans, fragility_cost=fragility,
    )


def require_worker_device_policy(run: Mapping[str, Any]) -> None:
    """Recheck the latest circuit breaker and pacing immediately before dispatch."""
    if not run["device_target_id"]:
        return
    context = run["context_pack"]
    if isinstance(context, str):
        context = json.loads(context)
    DeviceHuntPolicyState.from_mapping(context.get("device_policy_state") or {}).require_admission(
        request_attempts=1, fragility_cost=1,
    )


async def settle_device_traffic(conn: Any, run: Mapping[str, Any], requested: Mapping[str, int],
                                actual: dict[str, int], *, status: str,
                                health_observed: bool | None = None) -> None:
    """Settle device usage in the worker's existing terminal transaction."""
    reserved = int(requested.get("device_fragility_points") or 0)
    if not run["device_target_id"] or not reserved:
        return
    # Adapters already retain the full hold when execution usage is uncertain.
    # A measured failure must only charge its observed requests/connections.
    observed = any(int(actual.get(k) or 0) for k in (
        "http_requests", "tcp_ports_attempted", "udp_ports_attempted", "browser_actions",
        "tool_wall_seconds", "device_fragility_points",
    ))
    cost = min(reserved, max(int(actual.get("device_fragility_points") or 0),
                             traffic_envelope(actual))) if observed else 0
    actual["device_fragility_points"] = cost
    await record_device_traffic(conn, run, cost, status=status, health_observed=health_observed)


async def record_device_traffic(conn: Any, run: Mapping[str, Any], cost: int, *, status: str,
                               health_observed: bool | None = None) -> None:
    """Update usage independently of a capability's health observation.

    An explicit False means no health checkpoint: keep both prior failures and
    freezes, rather than inventing either a health failure or a recovery. NSE
    coverage outcomes (including optional omissions) are not device health tests.
    Callers without an override retain the existing health semantics.
    """
    if not run["device_target_id"] or not cost:
        return
    context = run["context_pack"]
    context = json.loads(context) if isinstance(context, str) else dict(context)
    state = DeviceHuntPolicyState.from_mapping(context.get("device_policy_state") or {})
    state = state.reconcile_adapter_state({}, {
        "device_http_requests_used": cost,
        "health_observed": bool(cost) if health_observed is None else health_observed,
        "health_failed": status in {"failed", "partial"},
    }, actual_fragility=cost, health_failed=status in {"failed", "partial"})
    context["device_policy_state"] = state.public_dict()
    await conn.execute("UPDATE hunt_runs SET context_pack=$2::jsonb WHERE id=$1",
                       run["id"], json.dumps(context))
