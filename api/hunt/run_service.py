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

try:
    from hunt.cancellation import signal_cancelled_jobs
except ModuleNotFoundError:  # package import in host-side tests
    from .cancellation import signal_cancelled_jobs


HUNT_RUN_STATUSES = frozenset({
    "created",
    "active",
    "awaiting_planner",
    "completed",
    "cancelled",
    "failed",
    "budget_exhausted",
})

_ACTION_REFERENCE_FIELDS = {
    "scan_id": "scan_ids",
    "scan_ids": "scan_ids",
    "queued_scan_id": "scan_ids",
    "finding_id": "finding_ids",
    "finding_ids": "finding_ids",
    "candidate_id": "candidate_ids",
    "candidate_ids": "candidate_ids",
    "evidence_id": "evidence_ids",
    "evidence_ids": "evidence_ids",
    "evidence_ref": "evidence_ids",
    "evidence_instance_id": "evidence_ids",
    "evidence_instance_ids": "evidence_ids",
}


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


def _uuid_reference(value: Any) -> str | None:
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError):
        return None


def _action_reference_ids(value: Any) -> dict[str, list[str]]:
    """Extract only typed UUID references from a redacted action result."""

    references: dict[str, list[str]] = {
        "scan_ids": [],
        "finding_ids": [],
        "candidate_ids": [],
        "evidence_ids": [],
    }

    def visit(node: Any, *, depth: int = 0) -> None:
        if depth > 6:
            return
        if isinstance(node, Mapping):
            for raw_key, raw_value in node.items():
                key = str(raw_key)
                reference_kind = _ACTION_REFERENCE_FIELDS.get(key)
                if reference_kind:
                    values = raw_value if isinstance(raw_value, (list, tuple)) else [raw_value]
                    for candidate in values:
                        reference = _uuid_reference(candidate)
                        if reference and reference not in references[reference_kind]:
                            references[reference_kind].append(reference)
                if isinstance(raw_value, (Mapping, list, tuple)):
                    visit(raw_value, depth=depth + 1)
        elif isinstance(node, (list, tuple)):
            for child in node:
                visit(child, depth=depth + 1)

    visit(value)
    return references


def public_hunt_action(row: Any) -> dict[str, Any]:
    """Return a content-safe projection of one canonical capability action."""

    item = _row_dict(row)
    input_summary = _decode_json(item.get("input_summary"), {})
    result_summary = _decode_json(item.get("result_summary"), {})
    budget_consumed = result_summary.get("budget_consumed")
    if not isinstance(budget_consumed, Mapping):
        budget_consumed = {}
    observations = result_summary.get("observations")
    if isinstance(observations, list):
        observation_count = len(observations)
    else:
        # Worker-owned network/scanner actions intentionally persist only a
        # content-safe count, not their complete observation bodies. Older
        # rows used ``record_count`` while current rows use the canonical
        # ``observation_count`` name. Preserve both so the UI does not turn a
        # successful probe or crawl into a misleading "0 observations" card.
        raw_observation_count = result_summary.get(
            "observation_count", result_summary.get("record_count", 0)
        )
        observation_count = (
            int(raw_observation_count)
            if isinstance(raw_observation_count, int)
            and not isinstance(raw_observation_count, bool)
            and raw_observation_count >= 0
            else 0
        )
    return {
        "action_id": str(item.get("id")) if item.get("id") else None,
        "capability_name": item.get("capability_name"),
        "status": item.get("status"),
        "input_digest": input_summary.get("input_digest"),
        "idempotency_key_sha256": input_summary.get("idempotency_key_sha256"),
        "receipt_id": str(item.get("receipt_id")) if item.get("receipt_id") else None,
        "started_at": item.get("started_at"),
        "completed_at": item.get("completed_at"),
        "result": {
            "ok": result_summary.get("ok") is True,
            "partial": result_summary.get("partial") is True,
            "timed_out": result_summary.get("timed_out") is True,
            "observation_count": observation_count,
            "budget_consumed": {
                str(key): amount
                for key, amount in budget_consumed.items()
                if isinstance(amount, (int, float)) and not isinstance(amount, bool)
            },
            "reference_ids": _action_reference_ids(result_summary),
        },
    }


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

    def __init__(self, pool_provider, redis_provider=None):
        self._pool_provider = pool_provider
        # Optional so existing construction and tests are unchanged; without it a cancellation
        # still stops the Hunt and its scans, it simply cannot reach worker-placed capability jobs.
        self._redis_provider = redis_provider

    def _pool(self):
        pool = self._pool_provider()
        if pool is None:
            raise HTTPException(status_code=503, detail="Database is not ready")
        return pool

    async def get(self, hunt_id: str) -> dict[str, Any]:
        async with self._pool().acquire() as connection:
            row = await hunt_run_or_404(connection, hunt_id)
            actions = await connection.fetch(
                """SELECT id, capability_name, status, input_summary,
                          result_summary, receipt_id, started_at, completed_at
                   FROM hunt_actions WHERE hunt_run_id=$1
                   ORDER BY started_at ASC, id ASC""",
                _uuid_or_400(hunt_id, "hunt id"),
            )
        result = public_hunt_run(row)
        result["actions"] = [public_hunt_action(action) for action in actions]
        return result

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
        """Cancel a Hunt and the downstream work it queued.

        Flipping ``hunt_runs.status`` alone stopped the Hunt from admitting new actions but left
        every scan it had already queued running against the target. Actions still in flight learn
        of the cancellation through ``HuntCancellationWatch``; scans are already queued jobs and
        have to be cancelled where they live.

        The status rules mirror ``cancel_scan``: device traffic goes to ``cancelling`` and stays
        there until its worker acknowledges a terminal state after reaping the process group, so a
        cancel never invents a terminal row while a device is still being probed. Reservations are
        deliberately left to settle through their own path -- releasing a hold whose action is still
        running would let the next action spend budget that is already committed.
        """
        run_uuid = _uuid_or_400(hunt_id, "hunt id")
        cancelled_ids: list[str] = []
        durable_job_ids: list[str] = []
        async with self._pool().acquire() as connection:
            row = await connection.fetchrow(
                """UPDATE hunt_runs SET status='cancelled', stop_reason='cancelled',
                          completed_at=NOW(), updated_at=NOW()
                   WHERE id=$1 AND status IN ('created','active','awaiting_planner')
                   RETURNING *""",
                run_uuid,
            )
            if not row:
                row = await hunt_run_or_404(connection, run_uuid)
                if row["status"] != "cancelled":
                    return public_hunt_run(row)
            else:
                cancelled = await connection.fetch(
                    """UPDATE scans
                   SET status = CASE
                           WHEN run_kind IN ('device_posture','device_probe') AND status='running'
                           THEN 'cancelling' ELSE 'cancelled' END,
                       error_message = 'Cancelled by owning Hunt',
                       completed_at = CASE
                           WHEN run_kind IN ('device_posture','device_probe') AND status='running'
                           THEN NULL ELSE NOW() END,
                       progress = CASE
                           WHEN run_kind IN ('device_posture','device_probe') AND status='running'
                           THEN progress ELSE 100 END,
                       current_phase = CASE
                           WHEN run_kind IN ('device_posture','device_probe') AND status='running'
                           THEN 'cancelling' ELSE 'cancelled' END
                   WHERE options->'hunt_dispatch'->>'hunt_id' = $1::text
                     AND status IN ('pending','queued','running')
                   RETURNING id""",
                    str(run_uuid),
                )
                cancelled_ids = [str(item["id"]) for item in cancelled]
                if cancelled_ids:
                    # Shards of a cancelled parent must not be left to finish on their own.
                    await connection.execute(
                        """UPDATE scans
                       SET status='cancelled', error_message='Cancelled by parent scan',
                           completed_at=NOW(), progress=100, current_phase='cancelled'
                       WHERE parent_scan_id = ANY($1::uuid[])
                         AND status IN ('pending','queued','running')""",
                        [uuid.UUID(item) for item in cancelled_ids],
                    )
            durable_jobs = await connection.fetch(
                """UPDATE hunt_cancellable_jobs
                   SET cancel_requested_at=COALESCE(cancel_requested_at, NOW()),
                       updated_at=NOW()
                   WHERE hunt_id=$1 AND signal_state != 'terminal'
                   RETURNING job_id""",
                run_uuid,
            )
            durable_job_ids = sorted(str(item["job_id"]) for item in durable_jobs)
        # A worker-placed capability polls `agent_tool_cancel:{job_id}` for a job id minted at
        # queue time, so cancelling the Hunt and its scans still left that traffic running. Signal
        # every job this Hunt queued. Idempotent: an already-set flag is harmless and a finished
        # job never reads it.
        signalled: list[str] = []
        if self._redis_provider is not None:
            try:
                signalled = signal_cancelled_jobs(
                    self._redis_provider(), run_uuid, job_ids=durable_job_ids,
                )
            except (AttributeError, NameError, TypeError):
                # A programming error must never look like an unreachable Redis. The
                # blanket handler that used to sit here swallowed a missing import, so
                # this call raised NameError on every cancellation, wrote no cancel keys,
                # and still returned an empty list as though there had been nothing to
                # signal.
                raise
            except Exception:  # noqa: BLE001 - Redis is unreachable; the Hunt is cancelled either way
                signalled = []
        durable_signalled = sorted(set(signalled).intersection(durable_job_ids))
        if durable_signalled:
            async with self._pool().acquire() as connection:
                await connection.execute(
                    """UPDATE hunt_cancellable_jobs
                       SET signal_state='signalled', signalled_at=NOW(), updated_at=NOW()
                       WHERE hunt_id=$1 AND job_id = ANY($2::uuid[])""",
                    run_uuid,
                    [uuid.UUID(item) for item in durable_signalled],
                )
        pending_job_ids = sorted(set(durable_job_ids).difference(signalled))
        payload = public_hunt_run(row)
        payload["cancelled_scan_ids"] = cancelled_ids
        payload["cancelled_job_ids"] = signalled
        payload["pending_cancel_job_ids"] = pending_job_ids
        payload["cancellation_degraded"] = bool(pending_job_ids)
        return payload

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
    "public_hunt_action",
    "public_hunt_run",
]
