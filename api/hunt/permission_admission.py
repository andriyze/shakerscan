"""Where Hunt admission meets permission requests.

A refusal on the allowable list parks the action under its idempotency key as
``awaiting_permission`` and answers 409 ``permission_required``; only that action waits, the Hunt
and its clock carry on. A refusal inside the start bounds is granted in the same transaction that
raises the request, and admission runs again. A refusal no grant can lift is recorded on the Hunt
as a ``blocked`` action with its code (D25/D35), and replays as such.

On a retry with the same key and input, a parked action whose request was granted is re-admitted
under the same action id through the full admission pipeline (scope, credentials, approval,
budget reservation); a grant changes what admission allows and never skips it. A denied, expired
or withdrawn request settles the action ``blocked`` with ``permission_<status>``.
"""
from __future__ import annotations

from collections.abc import Mapping
import json
from typing import Any
import uuid

from fastapi import HTTPException

from .permission_grants import LEDGER_TO_BUDGET, hunt_finished, try_preauthorized_grant
from .permission_reasons import PERMISSION_REQUIRED, HuntRefusal, refusal_summary
from .permission_store import expire_due, load_request, public_request, raise_request, record_event
from .permission_subjects import complete_destination_subject, credential_use_refusal
from .verification_budget import record_budget_shortage, reservation_exhausted

PARKABLE_RUN_STATUSES = frozenset({"active", "awaiting_planner", "budget_exhausted"})
MAX_ADMISSION_ATTEMPTS = 4


class PermissionPending(HTTPException):
    """409 ``permission_required``: the action is parked until a person decides."""


def permission_required(request: Mapping[str, Any], action_id: Any, refusal_detail: Mapping[str, Any]) -> PermissionPending:
    public = public_request(request)
    return PermissionPending(status_code=409, detail={
        **{key: value for key, value in refusal_detail.items() if key in {
            "error", "reason_code", "message", "shortages", "remaining", "slot",
            "retryable_with_smaller_action",
        }},
        "code": PERMISSION_REQUIRED,
        "action_id": str(action_id),
        "permission_request": {
            key: public[key] for key in ("id", "kind", "status", "title", "expires_at", "approve_command")
        },
        "recovery": (
            f"Waiting for the user to allow: {public['title']}. Tell the user to run "
            f"`shakerscan approve {public['id']}` in their own terminal. Continue other work "
            "meanwhile. On granted, call the same capability again with the same idempotency key "
            "and input. On denied or expired, do not retry this action."
        ),
        "execution_started": False,
    })


def budget_refusal(
    run: Mapping[str, Any], *, limits: Mapping[str, int], used: Mapping[str, Any],
    shortages: Mapping[str, int], charges: Mapping[str, int], message: str | None = None,
) -> HuntRefusal:
    """A coded budget refusal; grantable as ``budget.raise`` when the dimension is amendable."""
    from .budget_amendments import amendable_dimensions

    exhausted = reservation_exhausted(limits, used, shortages)
    dimension = next(iter(shortages), "unknown")
    code = "budget_exhausted" if exhausted else "budget_insufficient_for_action"
    budget_key = LEDGER_TO_BUDGET.get(dimension)
    limit = int(limits.get(dimension) or 0)
    needed = int(used.get(dimension) or 0) + int(charges.get(dimension) or shortages.get(dimension) or 1)
    extra = {
        "retryable_with_smaller_action": not exhausted,
        "shortages": {key: int(value) for key, value in shortages.items()},
        "remaining": {key: max(0, int(limits.get(key) or 0) - int(used.get(key) or 0)) for key in shortages},
    }
    legacy = f"{code}:{dimension}"
    if budget_key is None or budget_key not in amendable_dimensions(run):
        refusal = HuntRefusal(
            "budget_dimension_needs_permission",
            f"{dimension} is 0 for this Hunt because its permission is off; a budget raise cannot "
            "grant it.", extra=extra, error=legacy,
        )
    else:
        refusal = HuntRefusal(
            code,
            message or f"The Hunt's {budget_key} limit ({limit}) does not cover this action, which needs a "
            f"total of {needed}. A person can raise it for this Hunt (a permission request is raised).",
            extra=extra, error=legacy,
            subject={"dimension": budget_key, "ledger_dimension": dimension, "limit": limit},
        )
    refusal.display = {"needed_total": needed, "proposed_total": max(needed, limit * 2)}  # type: ignore[attr-defined]
    refusal.budget_state = {"limits": dict(limits), "used": dict(used), "shortages": dict(shortages)}  # type: ignore[attr-defined]
    return refusal


def verification_budget_refusal(run: Mapping[str, Any], used: Mapping[str, Any], budget: Mapping[str, Any]) -> HuntRefusal:
    """``max_verifications`` reached: grantable, and the Hunt keeps running meanwhile."""
    limit = int(budget.get("max_verifications") or 0)
    refusal = budget_refusal(
        run, limits={"verifications": limit}, used={"verifications": int(used.get("verifications") or 0)},
        shortages={"verifications": 1}, charges={"verifications": 1},
        message=(
            f"Hunt verification budget exhausted ({limit} of max_verifications used). A person "
            "can raise it for this Hunt (a permission request is raised); other actions continue."
        ),
    )
    refusal.budget_state = None  # type: ignore[attr-defined]
    return refusal


async def parked_outcome(
    conn: Any, run: dict[str, Any], action_id: Any, summary: Mapping[str, Any],
) -> tuple[str, dict[str, Any] | None]:
    """``pending``, ``granted`` or ``closed`` for a parked action's request (Hunt row locked)."""
    request_id = summary.get("permission_request_id")
    await expire_due(conn, run["id"])
    request = await load_request(conn, run["id"], request_id) if request_id else None
    if request is None:
        return "closed", None
    if request["status"] == "pending":
        if hunt_finished(run):
            return "closed", request
        if await try_preauthorized_grant(conn, run, request) is not None:
            request = await load_request(conn, run["id"], request_id)
        else:
            return "pending", request
    if request["status"] == "granted":
        return "granted", request
    return "closed", request


async def close_parked_action(conn: Any, run: Mapping[str, Any], action_id: Any, request: Mapping[str, Any] | None) -> None:
    status = str((request or {}).get("status") or "withdrawn")
    status = status if status in {"denied", "expired", "withdrawn"} else "withdrawn"
    code = f"permission_{status}"
    await conn.execute(
        """UPDATE hunt_actions SET status='blocked', completed_at=NOW(),
                  result_summary=result_summary || $3::jsonb
           WHERE id=$1 AND hunt_run_id=$2 AND status='awaiting_permission'""",
        action_id, run["id"], json.dumps({
            "error": code, "reason_code": code,
            "message": f"The permission this action waited for was {status}; it did not run.",
        }),
    )


async def _store_refused_action(
    conn: Any, *, run: Mapping[str, Any], action_id: Any, name: str, input_summary: Mapping[str, Any],
    status: str, summary: Mapping[str, Any],
) -> None:
    await conn.execute(
        """INSERT INTO hunt_actions (id, hunt_run_id, capability_name, status, input_summary,
                                      result_summary, completed_at)
           VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb, CASE WHEN $4='blocked' THEN NOW() ELSE NULL END)
           ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status,
               result_summary=EXCLUDED.result_summary, completed_at=EXCLUDED.completed_at
           WHERE hunt_actions.status='awaiting_permission'""",
        action_id, run["id"], name, status, json.dumps(dict(input_summary)), json.dumps(dict(summary)),
    )


async def settle_refusal(
    pool: Any, *, hunt_id: Any, action_id: Any, name: str, input_summary: Mapping[str, Any],
    input_digest: str, refusal: HuntRefusal,
) -> dict[str, Any]:
    """Record or park a refused action. Returns the request a pre-authorized grant just granted
    (admit again, then record its use).

    Otherwise raises the answer: 409 ``permission_required`` for a parked action, or the coded
    refusal itself.
    """
    hunt_uuid = uuid.UUID(str(hunt_id))
    async with pool.acquire() as conn:
        snapshot = await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1", hunt_uuid)
        if snapshot is not None:
            # DNS for another host happens before any lock is taken.
            refusal = await complete_destination_subject(dict(snapshot), refusal)
        pending: PermissionPending | None = None
        async with conn.transaction():
            row = await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", hunt_uuid)
            if row is None:
                raise refusal
            run = dict(row)
            budget_state = getattr(refusal, "budget_state", None)
            if budget_state:
                await record_budget_shortage(conn, hunt_id=run["id"], **budget_state)
                run = dict(await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1", hunt_uuid))
            refusal = await credential_use_refusal(conn, run, refusal)
            kind = refusal.kind if refusal.subject else None
            if kind and str(run["status"]) in PARKABLE_RUN_STATUSES and not hunt_finished(run):
                request, _created = await raise_request(
                    conn, run=run, kind=kind, reason_code=refusal.reason_code, subject=refusal.subject,
                    display=getattr(refusal, "display", None), action_id=action_id,
                    capability_name=name, input_digest=input_digest,
                )
                if request is not None:
                    if await try_preauthorized_grant(conn, run, request) is not None:
                        return dict(await load_request(conn, run["id"], request["id"]) or request)
                    summary = {**refusal_summary(refusal), "permission_request_id": str(request["id"])}
                    await _store_refused_action(
                        conn, run=run, action_id=action_id, name=name, input_summary=input_summary,
                        status="awaiting_permission", summary=summary,
                    )
                    detail = refusal.detail if isinstance(refusal.detail, Mapping) else {}
                    pending = permission_required(request, action_id, detail)
            if pending is None and refusal.recorded:
                await _store_refused_action(
                    conn, run=run, action_id=action_id, name=name, input_summary=input_summary,
                    status="blocked", summary=refusal_summary(refusal),
                )
    if pending is not None:
        raise pending
    raise refusal


async def record_grant_use(conn: Any, *, hunt_id: Any, action_id: Any, request: Mapping[str, Any]) -> None:
    await record_event(
        conn, hunt_id=hunt_id, request_id=request["id"], grant_id=request.get("grant_id"),
        action_id=action_id, event="used", actor="agent", source="admission",
    )


__all__ = [
    "MAX_ADMISSION_ATTEMPTS", "PermissionPending", "budget_refusal", "close_parked_action",
    "parked_outcome", "permission_required", "record_grant_use", "settle_refusal",
    "verification_budget_refusal",
]
