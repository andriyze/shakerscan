"""Durable Hunt run reads and terminal lifecycle transitions."""

from __future__ import annotations

from datetime import datetime
import importlib
import json
from typing import Any, Mapping
import uuid

from fastapi import HTTPException

agent_tools = importlib.import_module(
    "agent_tools" if __package__ == "hunt" else "api.agent_tools"
)


HUNT_RUN_STATUSES = frozenset({
    "created",
    "active",
    "awaiting_planner",
    "completed",
    "cancelled",
    "failed",
    "budget_exhausted",
})


def _uuid_or_400(value: str, label: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid {label}") from exc


def _decode_json(value: Any, default: Any) -> Any:
    decoded = value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            decoded = value
    return decoded if isinstance(decoded, type(default)) else default


def _row_dict(row: Any) -> dict[str, Any]:
    item = dict(row or {})
    for key, value in tuple(item.items()):
        if isinstance(value, uuid.UUID):
            item[key] = str(value)
        elif isinstance(value, datetime):
            item[key] = value.isoformat()
    return item


def public_hunt_run(
    row: Any,
    *,
    include_context: bool = True,
    include_capabilities: bool = True,
) -> dict[str, Any]:
    """Return the content-safe Hunt projection shared by every client."""

    item = _row_dict(row)
    policy = _decode_json(item.get("policy_json"), {})
    allowed = policy.get("allowed_capabilities")
    capabilities: list[dict[str, Any]] = []
    if isinstance(allowed, list):
        for raw_name in allowed:
            try:
                capabilities.append(
                    agent_tools.CAPABILITY_REGISTRY.require(
                        str(raw_name)
                    ).planner_contract()
                )
            except KeyError:
                continue
    result = {
        "hunt_id": str(item.get("id")) if item.get("id") else None,
        "target_kind": item.get("target_kind"),
        "target_id": str(
            item.get("target_id") or item.get("device_target_id") or ""
        ) or None,
        "objective": item.get("objective"),
        "status": item.get("status"),
        "budget_profile": item.get("budget_profile"),
        "policy": policy,
        "budget": _decode_json(item.get("budget_json"), {}),
        "budget_used": _decode_json(item.get("budget_used_json"), {}),
        "stop_reason": item.get("stop_reason"),
        "final_debrief": _decode_json(item.get("final_debrief"), {}),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "next_action": (
            f"POST /hunts/{item.get('id')}/query"
            if item.get("status") in {"active", "awaiting_planner"}
            else None
        ),
    }
    if include_capabilities:
        result["capabilities"] = capabilities
    if include_context:
        result["context_pack"] = _decode_json(item.get("context_pack"), {})
    return result


async def hunt_run_or_404(
    connection: Any,
    hunt_id: str,
    *,
    for_update: bool = False,
) -> Any:
    query = "SELECT * FROM hunt_runs WHERE id=$1"
    if for_update:
        query += " FOR UPDATE"
    row = await connection.fetchrow(query, _uuid_or_400(hunt_id, "hunt id"))
    if not row:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return row


class HuntRunService:
    """Own read/list/finish/cancel/resume persistence for canonical Hunts."""

    def __init__(self, pool_provider):
        self._pool_provider = pool_provider

    def _pool(self):
        pool = self._pool_provider()
        if pool is None:
            raise HTTPException(status_code=503, detail="Database is not ready")
        return pool

    async def get(self, hunt_id: str) -> dict[str, Any]:
        async with self._pool().acquire() as connection:
            row = await hunt_run_or_404(connection, hunt_id)
        return public_hunt_run(row)

    async def list(
        self,
        *,
        target_id: str | None,
        status: str | None,
        limit: int,
    ) -> dict[str, Any]:
        clauses: list[str] = []
        params: list[Any] = []
        if target_id:
            params.append(_uuid_or_400(target_id, "target id"))
            clauses.append(
                f"(target_id=${len(params)} OR device_target_id=${len(params)})"
            )
        if status:
            if status not in HUNT_RUN_STATUSES:
                raise HTTPException(status_code=400, detail="invalid Hunt status")
            params.append(status)
            clauses.append(f"status=${len(params)}")
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(limit)
        async with self._pool().acquire() as connection:
            rows = await connection.fetch(
                f"SELECT * FROM hunt_runs{where} "
                f"ORDER BY created_at DESC LIMIT ${len(params)}",
                *params,
            )
        return {
            "hunts": [
                public_hunt_run(
                    row, include_context=False, include_capabilities=False
                )
                for row in rows
            ],
            "count": len(rows),
        }

    async def finish(
        self, hunt_id: str, *, summary: str, next_actions: list[str]
    ) -> dict[str, Any]:
        async with self._pool().acquire() as connection:
            row = await connection.fetchrow(
                """UPDATE hunt_runs SET status='completed', stop_reason='completed',
                          final_debrief=$2, completed_at=NOW(), updated_at=NOW()
                   WHERE id=$1 AND status IN ('active','awaiting_planner')
                   RETURNING *""",
                _uuid_or_400(hunt_id, "hunt id"),
                json.dumps({"summary": summary, "next_actions": next_actions}),
            )
            if not row:
                row = await hunt_run_or_404(connection, hunt_id)
                if row["status"] != "completed":
                    raise HTTPException(
                        status_code=409, detail=f"Hunt is {row['status']}"
                    )
        return public_hunt_run(row)

    async def cancel(self, hunt_id: str) -> dict[str, Any]:
        async with self._pool().acquire() as connection:
            row = await connection.fetchrow(
                """UPDATE hunt_runs SET status='cancelled', stop_reason='cancelled',
                          completed_at=NOW(), updated_at=NOW()
                   WHERE id=$1 AND status IN ('created','active','awaiting_planner')
                   RETURNING *""",
                _uuid_or_400(hunt_id, "hunt id"),
            )
            if not row:
                row = await hunt_run_or_404(connection, hunt_id)
        return public_hunt_run(row)

    async def resume(self, hunt_id: str) -> dict[str, Any]:
        async with self._pool().acquire() as connection:
            row = await connection.fetchrow(
                """UPDATE hunt_runs SET status='active', stop_reason=NULL,
                          updated_at=NOW()
                   WHERE id=$1 AND status='awaiting_planner' RETURNING *""",
                _uuid_or_400(hunt_id, "hunt id"),
            )
            if not row:
                row = await hunt_run_or_404(connection, hunt_id)
                if row["status"] != "active":
                    raise HTTPException(
                        status_code=409,
                        detail=f"Hunt is {row['status']} and cannot resume",
                    )
        return public_hunt_run(row)


__all__ = [
    "HUNT_RUN_STATUSES",
    "HuntRunService",
    "hunt_run_or_404",
    "public_hunt_run",
]
