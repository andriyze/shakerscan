"""The report a cancelled Scan keeps.

Cancellation stops execution: no action starts after it, and the running one is stopped. It
does not discard what the actions that had already settled confirmed. The worker finalizes
those receipts with the same pure finalizer (no target traffic), marks the report cancelled,
and keeps its findings; the Scan stays ``cancelled``.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Awaitable, Callable
import uuid

from .continuation_rounds import prepare_local_scan_continuation


CANCELLED_REPORT_KEPT = "cancelled_report_kept"


def mark_cancelled_scan_report(report: dict[str, Any]) -> dict[str, Any]:
    """Mark a report built after cancellation: cancelled coverage, findings kept."""
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    reasons = [str(item) for item in coverage.get("reasons") or () if str(item).strip()]
    report["coverage"] = {
        **coverage,
        "status": "cancelled",
        "reasons": [*reasons, *([] if "cancelled" in reasons else ["cancelled"])],
    }
    metadata = report.get("scan_metadata") if isinstance(report.get("scan_metadata"), dict) else {}
    reliability = [str(item) for item in metadata.get("grade_reliability_reasons") or () if str(item).strip()]
    report["scan_metadata"] = {
        **metadata,
        "status": "cancelled",
        "partial": True,
        "cancelled": True,
        CANCELLED_REPORT_KEPT: True,
        "grade_reliable": False,
        "grade_reliability_reasons": [*reliability, *([] if "cancelled" in reliability else ["cancelled"])],
    }
    # The report was built without running the finalization action, which the cancellation
    # settled or never planned: the execution record says so instead of claiming success.
    execution = report.get("canonical_action_execution")
    if isinstance(execution, dict):
        finalization = execution.get("finalization_action")
        if isinstance(finalization, dict):
            execution["finalization_action"] = {**finalization, "status": "cancelled"}
            matrix = execution.get("status_matrix")
            action_id = finalization.get("action_id")
            if isinstance(matrix, dict) and action_id in matrix:
                execution["status_matrix"] = {**matrix, action_id: "cancelled"}
        execution["finalized_after_cancellation"] = True
    return report


def is_kept_cancelled_report(result: Any) -> bool:
    metadata = result.get("scan_metadata") if isinstance(result, dict) else None
    return isinstance(metadata, dict) and metadata.get(CANCELLED_REPORT_KEPT) is True and not result.get("error")


def cancellation_error_result(result: Any, target: Any) -> Any:
    """A kept cancelled report turned back into the cancellation error, for callers that
    record a cancelled run as an error (an ASM exploit batch); any other result unchanged."""
    if not is_kept_cancelled_report(result):
        return result
    return {"target": target, "error": "Cancelled by user",
            "result": {"score": None, "grade": None}, "findings": []}


async def build_cancelled_scan_report(
    dispatcher: Any, *, scan_id: str, finalization: Any = None,
) -> dict[str, Any]:
    """The report of a cancelled Scan from its settled receipts (no target traffic).

    ``finalization`` is ``(plan, revision)`` of a finalize-only revision compiled for a work
    round that was cancelled before its finalizer was planned; it is not persisted, because a
    cancelled Scan's plan is frozen. A report that cannot be built (an action of the plan is not
    terminal) falls back to the earlier outcome: the cancellation error, with no findings kept.
    """
    try:
        if finalization is None:
            report = await dispatcher.build_scan_report()
        else:
            plan, revision = finalization
            report = await dispatcher.build_scan_report(plan=plan, plan_revision=revision)
    except Exception as exc:
        print(
            f"[scan] cancelled scan {str(scan_id)[:8]} report could not be built "
            f"({type(exc).__name__}); no findings are kept",
            file=sys.stderr, flush=True,
        )
        raise ValueError("Cancelled by user") from exc
    return mark_cancelled_scan_report(report)


async def cancelled_scan_report(
    dispatcher: Any, *, scan_id: str, load_allocation: Callable[[], Awaitable[Any]], runtime: Any,
) -> dict[str, Any]:
    """The kept report of a Scan cancelled in any round.

    A round that planned the finalizer reports over its own plan. A work round has none: the
    finalize-only revision the normal path would have run is compiled (never persisted) and the
    report is built over it. Anything missing falls back to the cancellation error.
    """
    finalization = None
    if not any(action.action_id == "finalize.report" for action in dispatcher.plan.actions):
        try:
            allocation = await load_allocation()
            results = {
                action.action_id: await dispatcher.backend.load_result(action.action_id)
                for action in dispatcher.plan.actions
            }
            revision = dispatcher.plan_revision
            prepared = await prepare_local_scan_continuation(
                runtime, parent_plan=dispatcher.plan, allocation=allocation,
                parent_results=results,
                revision_number=(int(revision.revision) if revision is not None else 0) + 1,
                include_finalizer=True, finalize_only=True,
            ) if allocation is not None and None not in results.values() else None
            if prepared is not None:
                finalization = (prepared.plan, prepared.revision)
        except Exception as exc:
            print(f"[scan] cancelled scan {str(scan_id)[:8]} finalization revision could not be "
                  f"compiled ({type(exc).__name__})", file=sys.stderr, flush=True)
        if finalization is None:
            raise ValueError("Cancelled by user")
    return await build_cancelled_scan_report(dispatcher, scan_id=scan_id, finalization=finalization)


async def persist_kept_cancelled_scan(
    pool: Any, *, scan_id: str, result: dict[str, Any], completed_at: Any, duration: int,
    coverage: dict[str, Any], budget_used: dict[str, Any],
) -> bool:
    """Store a cancelled Scan's kept report; the row stays cancelled. False if it is not."""
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    async with pool.acquire() as conn:
        kept = await conn.fetchval(
            """UPDATE scans SET status='cancelled', result=$2, findings_count=$3,
                      completed_at=COALESCE(completed_at, $4), duration_seconds=$5,
                      progress=100, current_phase='cancelled',
                      error_message=COALESCE(error_message, 'Cancelled by user'),
                      score=NULL, grade=NULL,
                      coverage_status=$6, coverage_json=$7, budget_used_json=$8,
                      assurance_score=COALESCE(assurance_score, 0)
                WHERE id=$1 AND status IN ('cancelled','cancelling')
            RETURNING id""",
            uuid.UUID(str(scan_id)), json.dumps(result), len(findings), completed_at,
            duration, str(coverage.get("status") or "cancelled"), json.dumps(coverage),
            json.dumps(budget_used),
        )
    return kept is not None


__all__ = [
    "CANCELLED_REPORT_KEPT",
    "build_cancelled_scan_report",
    "cancellation_error_result",
    "cancelled_scan_report",
    "is_kept_cancelled_report",
    "mark_cancelled_scan_report",
    "persist_kept_cancelled_scan",
]
